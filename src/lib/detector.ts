/**
 * The detector: runs the LogDFA over a parsed log and turns raw machine steps
 * into human-readable, severity-classified findings.
 *
 * Two layers cooperate:
 *
 *  1. Pure DFA layer — an undefined (state, event) pair is an invalid
 *     transition. Severity depends on *where* it happened and *what* the
 *     event was (privileged event before authentication → CRITICAL, etc.).
 *
 *  2. Security-policy layer — suspicious-but-legal behaviour the DFA alone
 *     cannot judge: brute-force thresholds (state q1f3), privilege escalation
 *     (entering q5), unrecognized symbols outside Σ, and the final-state
 *     acceptance check δ*(q0, w) ∈ F.
 *
 * Every finding carries a programmatic explanation: event, previous state,
 * expected events, reason, severity.
 */

import { LogDFA, BRUTE_FORCE_THRESHOLD, STATES } from "./automaton";
import { isKnownEvent, isPrivileged } from "./alphabet";
import { parseLog } from "./parser";
import type {
  AnalysisResult,
  AnalysisSummary,
  AnomalyType,
  ParsedEvent,
  ResultRow,
  Severity,
  Verdict,
} from "./types";

const END_OF_LOG = "END_OF_LOG";

/** States that exist before the actor has authenticated successfully. */
const PRE_AUTH_STATES = new Set(["q0", "q1", "q1f1", "q1f2", "q1f3"]);

function fmtExpected(expected: string[]): string {
  return expected.length ? expected.join(", ") : "(none)";
}

function stateTag(state: string): string {
  return `${state} (${STATES[state]?.label ?? state})`;
}

/** Severity + anomaly class of an invalid transition (state, event). */
export function classifyInvalidTransition(
  state: string,
  event: string,
): { severity: Severity; anomalyType: AnomalyType } {
  if (PRE_AUTH_STATES.has(state) && isPrivileged(event)) {
    return { severity: "CRITICAL", anomalyType: "INVALID_TRANSITION" };
  }
  if (event === "DATABASE_ACCESS" && state === "q2") {
    return { severity: "HIGH", anomalyType: "SUSPICIOUS_DATABASE_ACCESS" };
  }
  if (state === "q3") {
    return {
      severity: isPrivileged(event) ? "HIGH" : "MEDIUM",
      anomalyType: "INVALID_WORKFLOW",
    };
  }
  if (state === "q2" && isPrivileged(event)) {
    return { severity: "HIGH", anomalyType: "INVALID_TRANSITION" };
  }
  return { severity: "MEDIUM", anomalyType: "INVALID_TRANSITION" };
}

/** Programmatic explanation for an invalid transition. */
function invalidTransitionReason(
  state: string,
  event: string,
  expected: string[],
): string {
  const expectedText = fmtExpected(expected);
  if (PRE_AUTH_STATES.has(state) && isPrivileged(event)) {
    if (state === "q1f3") {
      return `No transition for ${event} in ${stateTag(state)}. A privileged action occurred after repeated authentication failures — strong indicator of an account-takeover attempt. Expected one of: ${expectedText}.`;
    }
    return `No transition for ${event} in ${stateTag(state)}. ${event} is a privileged action, but the session has not been authenticated — possible unauthorized privilege use. Expected one of: ${expectedText}.`;
  }
  if (state === "q3") {
    return `No transition for ${event} in ${stateTag(state)}. The session had already ended, so this event belongs to a session that no longer exists (invalid workflow). Only LOGIN may follow a logout. Expected: ${expectedText}.`;
  }
  if (event === "DATABASE_ACCESS" && state === "q2") {
    return `No transition for ${event} in ${stateTag(state)}. Direct database access is only permitted from an elevated administrative context, but no PRIVILEGE_CHANGE was recorded. Expected one of: ${expectedText}.`;
  }
  if (state === "q2" && isPrivileged(event)) {
    return `No transition for ${event} in ${stateTag(state)}. Administrative/privileged action performed without the required PRIVILEGE_CHANGE → ADMIN_ACCESS workflow. Expected one of: ${expectedText}.`;
  }
  if (event === "AUTH_FAILURE" && state === "q2") {
    return `No transition for ${event} in ${stateTag(state)}. An authentication failure occurred while the session was already authenticated — possible session misuse or credential stuffing. Expected one of: ${expectedText}.`;
  }
  return `No transition for ${event} in ${stateTag(state)}. This event is not valid in the current context. Expected one of: ${expectedText}.`;
}

const END_STATE_REASONS: Record<string, string> = {
  q0: "The log ends in q0 (START) without any successful login — no session was ever established.",
  q1: "The log ends in q1 (LOGIN_ATTEMPT) before an authentication outcome was recorded.",
  q1f1: "The log ends in q1f1 (AUTH_FAIL_1) before an authentication outcome was recorded.",
  q1f2: "The log ends in q1f2 (AUTH_FAIL_2) before an authentication outcome was recorded.",
  q1f3: "The log ends in q1f3 (AUTH_FAIL_3+) with repeated failures unresolved and no authentication outcome.",
  q4: "The log ends in q4 (PRIVILEGE_CHANGE) — the session terminates while privileges were recently elevated and no logout was recorded.",
  q5: "The log ends in q5 (ADMIN_ACCESS) — the session terminates while administrative privileges are still active and no logout was recorded.",
};

function severityRank(s: Severity): number {
  return { NONE: 0, MEDIUM: 1, HIGH: 2, CRITICAL: 3 }[s];
}

function verdictFor(max: Severity): Verdict {
  if (max === "CRITICAL") return "CRITICAL";
  if (severityRank(max) >= severityRank("MEDIUM")) return "ANOMALY";
  return "NORMAL";
}

/**
 * Analyse a raw log string (already read from a file / textarea).
 * `filename` is display-only metadata.
 */
export function analyzeLogText(
  text: string,
  filename: string,
  source: AnalysisResult["source"],
): AnalysisResult {
  const started = performance.now();
  const parse = parseLog(text);
  const dfa = new LogDFA();

  const results: ResultRow[] = [];
  let consecutiveFailures = 0;

  for (const ev of parse.events) {
    const step = dfa.step(ev.event);

    let row: ResultRow;

    if (!isKnownEvent(ev.event)) {
      row = {
        position: ev.position,
        event: ev.event,
        previousState: step.from,
        currentState: step.to,
        status: "ANOMALY",
        severity: "MEDIUM",
        anomalyType: "UNRECOGNIZED_EVENT",
        expectedEvents: step.expected,
        reason: `The symbol "${ev.event}" is not in the automaton alphabet Σ, so the DFA cannot process it. The machine stays in ${stateTag(step.from)}.`,
        timestamp: ev.timestamp,
        user: ev.user,
        ip: ev.ip,
      };
    } else if (step.allowed) {
      // Track consecutive authentication failures for the policy layer.
      if (ev.event === "AUTH_FAILURE") {
        consecutiveFailures += 1;
      } else {
        consecutiveFailures = 0;
      }

      const bruteForce =
        ev.event === "AUTH_FAILURE" &&
        consecutiveFailures >= BRUTE_FORCE_THRESHOLD;
      const escalation =
        ev.event === "ADMIN_ACCESS" && step.to === "q5" && step.from === "q4";

      row = {
        position: ev.position,
        event: ev.event,
        previousState: step.from,
        currentState: step.to,
        status: bruteForce || escalation ? "ANOMALY" : "NORMAL",
        severity: "NONE",
        anomalyType: undefined,
        expectedEvents: [],
        reason:
          step.from === step.to
            ? `Self-transition in ${stateTag(step.to)} — normal ${ev.event} activity.`
            : `${ev.event}: ${stateTag(step.from)} → ${stateTag(step.to)}.`,
        timestamp: ev.timestamp,
        user: ev.user,
        ip: ev.ip,
      };

      if (bruteForce) {
        row.status = "ANOMALY";
        row.severity = "HIGH";
        row.anomalyType = "BRUTE_FORCE";
        row.reason = `${consecutiveFailures} consecutive authentication failures (threshold ${BRUTE_FORCE_THRESHOLD}) — possible brute-force login attempt${ev.ip ? ` from ${ev.ip}` : ""}. The automaton has climbed the failure ladder to ${stateTag(step.to)}.`;
      }
      if (escalation) {
        row.status = "ANOMALY";
        row.severity = "CRITICAL";
        row.anomalyType = "PRIVILEGE_ESCALATION";
        row.reason = `The transition ${stateTag(step.from)} → ${stateTag(step.to)} on ${ev.event} is valid, but PRIVILEGE_CHANGE followed by ADMIN_ACCESS is flagged CRITICAL by security policy: a privilege change was immediately used for administrative access (escalation pattern).`;
      }
    } else {
      consecutiveFailures = 0;
      const { severity, anomalyType } = classifyInvalidTransition(
        step.from,
        ev.event,
      );
      row = {
        position: ev.position,
        event: ev.event,
        previousState: step.from,
        currentState: step.to,
        status: "ANOMALY",
        severity,
        anomalyType,
        expectedEvents: step.expected,
        reason: invalidTransitionReason(step.from, ev.event, step.expected),
        timestamp: ev.timestamp,
        user: ev.user,
        ip: ev.ip,
      };
    }

    results.push(row);
  }

  // Final-state acceptance: δ*(q0, w) ∈ F ?
  const finalState = dfa.currentState;
  const accepted = dfa.isAccepting(finalState);
  if (parse.events.length === 0) {
    results.push({
      position: 1,
      event: END_OF_LOG,
      previousState: finalState,
      currentState: finalState,
      status: parse.warnings.length ? "ANOMALY" : "NORMAL",
      severity: parse.warnings.length ? "MEDIUM" : "NONE",
      anomalyType: parse.warnings.length ? "INCOMPLETE_SESSION" : undefined,
      expectedEvents: dfa.expectedEvents(finalState),
      reason: parse.warnings.length
        ? "No processable events were found in this input (empty or unparseable log)."
        : "The log contains no events.",
    });
  } else if (!accepted) {
    results.push({
      position: parse.events.length + 1,
      event: END_OF_LOG,
      previousState: finalState,
      currentState: finalState,
      status: "ANOMALY",
      severity: "MEDIUM",
      anomalyType: "INCOMPLETE_SESSION",
      expectedEvents: dfa.expectedEvents(finalState),
      reason: `${END_STATE_REASONS[finalState] ?? "The log ends in a non-accepting state."} A complete session must end in an accepting state (F = {q2, q3}).`,
    });
  }

  const anomalyRows = results.filter((r) => r.status === "ANOMALY");
  const maxSeverity = anomalyRows.reduce<Severity>(
    (max, r) => (severityRank(r.severity) > severityRank(max) ? r.severity : max),
    "NONE",
  );

  const summary: AnalysisSummary = {
    verdict: verdictFor(maxSeverity),
    totalEvents: parse.events.length,
    normalEvents: parse.events.length - anomalyRows.length,
    anomalies: anomalyRows.length,
    criticalAnomalies: anomalyRows.filter((r) => r.severity === "CRITICAL")
      .length,
    highAnomalies: anomalyRows.filter((r) => r.severity === "HIGH").length,
    mediumAnomalies: anomalyRows.filter((r) => r.severity === "MEDIUM").length,
    maxSeverity,
    detectionMs: Math.round((performance.now() - started) * 100) / 100,
    finalState,
    accepted,
  };

  return {
    filename,
    source,
    parse,
    eventSequence: parse.events.map((e: ParsedEvent) => e.event),
    results,
    summary,
  };
}
