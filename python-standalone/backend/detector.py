"""The detector: runs LogDFA over a parsed log and produces explained,
severity-classified findings.

Two layers cooperate:

  1. Pure DFA layer — an undefined (state, event) pair is an invalid
     transition; severity depends on where it happened and what the event was.
  2. Security-policy layer — suspicious-but-legal behaviour the DFA alone
     cannot judge: the brute-force ladder (q1f3), privilege escalation
     (entering q5), unknown symbols outside Σ, and the final-state
     acceptance check δ*(q0, w) ∈ F.

Every finding carries a programmatic explanation.
"""

from __future__ import annotations

import time
from typing import List, Optional

from .automaton import LogDFA, BRUTE_FORCE_THRESHOLD, STATES
from .log_parser import parse_log
from .rules import is_known_event, is_privileged, PRE_AUTH_STATES, SEVERITY_ORDER

END_OF_LOG = "END_OF_LOG"

END_STATE_REASONS = {
    "q0": "The log ends in q0 (START) without any successful login — no "
          "session was ever established.",
    "q1": "The log ends in q1 (LOGIN_ATTEMPT) before an authentication "
          "outcome was recorded.",
    "q1f1": "The log ends in q1f1 (AUTH_FAIL_1) before an authentication "
            "outcome was recorded.",
    "q1f2": "The log ends in q1f2 (AUTH_FAIL_2) before an authentication "
            "outcome was recorded.",
    "q1f3": "The log ends in q1f3 (AUTH_FAIL_3+) with repeated failures "
            "unresolved and no authentication outcome.",
    "q4": "The log ends in q4 (PRIVILEGE_CHANGE) — the session terminates "
          "while privileges were recently elevated and no logout was recorded.",
    "q5": "The log ends in q5 (ADMIN_ACCESS) — the session terminates while "
          "administrative privileges are still active and no logout was recorded.",
}


def _fmt_expected(expected: List[str]) -> str:
    return ", ".join(expected) if expected else "(none)"


def _state_tag(state: str) -> str:
    label = STATES.get(state)
    return f"{state} ({label})" if label else state


def classify_invalid_transition(state: str, event: str):
    """Severity + anomaly class of an invalid transition (state, event)."""
    if state in PRE_AUTH_STATES and is_privileged(event):
        return "CRITICAL", "INVALID_TRANSITION"
    if event == "DATABASE_ACCESS" and state == "q2":
        return "HIGH", "SUSPICIOUS_DATABASE_ACCESS"
    if state == "q3":
        return ("HIGH" if is_privileged(event) else "MEDIUM"), "INVALID_WORKFLOW"
    if state == "q2" and is_privileged(event):
        return "HIGH", "INVALID_TRANSITION"
    return "MEDIUM", "INVALID_TRANSITION"


def _invalid_transition_reason(state: str, event: str, expected: List[str]) -> str:
    exp = _fmt_expected(expected)
    if state in PRE_AUTH_STATES and is_privileged(event):
        if state == "q1f3":
            return (f"No transition for {event} in {_state_tag(state)}. A privileged "
                    f"action occurred after repeated authentication failures — strong "
                    f"indicator of an account-takeover attempt. Expected one of: {exp}.")
        return (f"No transition for {event} in {_state_tag(state)}. {event} is a "
                f"privileged action, but the session has not been authenticated — "
                f"possible unauthorized privilege use. Expected one of: {exp}.")
    if state == "q3":
        return (f"No transition for {event} in {_state_tag(state)}. The session had "
                f"already ended, so this event belongs to a session that no longer "
                f"exists (invalid workflow). Only LOGIN may follow a logout. "
                f"Expected: {exp}.")
    if event == "DATABASE_ACCESS" and state == "q2":
        return (f"No transition for {event} in {_state_tag(state)}. Direct database "
                f"access is only permitted from an elevated administrative context, "
                f"but no PRIVILEGE_CHANGE was recorded. Expected one of: {exp}.")
    if state == "q2" and is_privileged(event):
        return (f"No transition for {event} in {_state_tag(state)}. Administrative/"
                f"privileged action performed without the required PRIVILEGE_CHANGE "
                f"→ ADMIN_ACCESS workflow. Expected one of: {exp}.")
    if event == "AUTH_FAILURE" and state == "q2":
        return (f"No transition for {event} in {_state_tag(state)}. An authentication "
                f"failure occurred while the session was already authenticated — "
                f"possible session misuse or credential stuffing. Expected one of: {exp}.")
    return (f"No transition for {event} in {_state_tag(state)}. This event is not "
            f"valid in the current context. Expected one of: {exp}.")


def _verdict_for(max_severity: str) -> str:
    if max_severity == "CRITICAL":
        return "CRITICAL"
    if SEVERITY_ORDER[max_severity] >= SEVERITY_ORDER["MEDIUM"]:
        return "ANOMALY"
    return "NORMAL"


def analyze_log_text(text: str, filename: str = "log.txt",
                     source: str = "upload") -> dict:
    """Analyse a raw log string and return the full structured result."""
    started = time.perf_counter()
    parse = parse_log(text)
    dfa = LogDFA()

    results: List[dict] = []
    consecutive_failures = 0

    for ev in parse["events"]:
        step = dfa.step(ev["event"])
        base = {
            "position": ev["position"],
            "event": ev["event"],
            "timestamp": ev["timestamp"],
            "user": ev["user"],
            "ip": ev["ip"],
        }

        if not is_known_event(ev["event"]):
            results.append({
                **base,
                "previous_state": step.from_state,
                "current_state": step.to_state,
                "status": "ANOMALY",
                "severity": "MEDIUM",
                "anomaly_type": "UNRECOGNIZED_EVENT",
                "expected_events": step.expected,
                "reason": (f"The symbol \"{ev['event']}\" is not in the automaton "
                           f"alphabet Σ, so the DFA cannot process it. The machine "
                           f"stays in {_state_tag(step.from_state)}."),
            })
            continue

        if step.allowed:
            if ev["event"] == "AUTH_FAILURE":
                consecutive_failures += 1
            else:
                consecutive_failures = 0

            brute_force = (ev["event"] == "AUTH_FAILURE"
                           and consecutive_failures >= BRUTE_FORCE_THRESHOLD)
            escalation = (ev["event"] == "ADMIN_ACCESS"
                          and step.to_state == "q5" and step.from_state == "q4")

            if brute_force:
                results.append({
                    **base,
                    "previous_state": step.from_state,
                    "current_state": step.to_state,
                    "status": "ANOMALY",
                    "severity": "HIGH",
                    "anomaly_type": "BRUTE_FORCE",
                    "expected_events": [],
                    "reason": (f"{consecutive_failures} consecutive authentication "
                               f"failures (threshold {BRUTE_FORCE_THRESHOLD}) — "
                               f"possible brute-force login attempt"
                               f"{' from ' + ev['ip'] if ev['ip'] else ''}. The "
                               f"automaton has climbed the failure ladder to "
                               f"{_state_tag(step.to_state)}."),
                })
            elif escalation:
                results.append({
                    **base,
                    "previous_state": step.from_state,
                    "current_state": step.to_state,
                    "status": "ANOMALY",
                    "severity": "CRITICAL",
                    "anomaly_type": "PRIVILEGE_ESCALATION",
                    "expected_events": [],
                    "reason": (f"The transition {_state_tag(step.from_state)} → "
                               f"{_state_tag(step.to_state)} on {ev['event']} is "
                               f"valid, but PRIVILEGE_CHANGE followed by "
                               f"ADMIN_ACCESS is flagged CRITICAL by security "
                               f"policy: a privilege change was immediately used "
                               f"for administrative access (escalation pattern)."),
                })
            else:
                reason = (
                    f"Self-transition in {_state_tag(step.to_state)} — normal "
                    f"{ev['event']} activity."
                    if step.from_state == step.to_state
                    else f"{ev['event']}: {_state_tag(step.from_state)} → "
                         f"{_state_tag(step.to_state)}."
                )
                results.append({
                    **base,
                    "previous_state": step.from_state,
                    "current_state": step.to_state,
                    "status": "NORMAL",
                    "severity": "NONE",
                    "anomaly_type": None,
                    "expected_events": [],
                    "reason": reason,
                })
        else:
            consecutive_failures = 0
            severity, anomaly_type = classify_invalid_transition(step.from_state,
                                                                 ev["event"])
            results.append({
                **base,
                "previous_state": step.from_state,
                "current_state": step.to_state,
                "status": "ANOMALY",
                "severity": severity,
                "anomaly_type": anomaly_type,
                "expected_events": step.expected,
                "reason": _invalid_transition_reason(step.from_state, ev["event"],
                                                     step.expected),
            })

    # Final-state acceptance: δ*(q0, w) ∈ F ?
    final_state = dfa.current_state
    accepted = dfa.is_accepting(final_state)
    if not parse["events"]:
        results.append({
            "position": 1,
            "event": END_OF_LOG,
            "previous_state": final_state,
            "current_state": final_state,
            "status": "ANOMALY" if parse["warnings"] else "NORMAL",
            "severity": "MEDIUM" if parse["warnings"] else "NONE",
            "anomaly_type": "INCOMPLETE_SESSION" if parse["warnings"] else None,
            "expected_events": dfa.expected_events(final_state),
            "reason": ("No processable events were found in this input (empty or "
                       "unparseable log)."
                       if parse["warnings"]
                       else "The log contains no events."),
            "timestamp": None,
            "user": None,
            "ip": None,
        })
    elif not accepted:
        results.append({
            "position": parse["events"][-1]["position"] + 1,
            "event": END_OF_LOG,
            "previous_state": final_state,
            "current_state": final_state,
            "status": "ANOMALY",
            "severity": "MEDIUM",
            "anomaly_type": "INCOMPLETE_SESSION",
            "expected_events": dfa.expected_events(final_state),
            "reason": (END_STATE_REASONS.get(final_state,
                        "The log ends in a non-accepting state.") + " A complete "
                       "session must end in an accepting state (F = {q2, q3})."),
            "timestamp": None,
            "user": None,
            "ip": None,
        })

    anomaly_rows = [r for r in results if r["status"] == "ANOMALY"]
    max_severity = "NONE"
    for r in anomaly_rows:
        if SEVERITY_ORDER[r["severity"]] > SEVERITY_ORDER[max_severity]:
            max_severity = r["severity"]

    detection_ms = round((time.perf_counter() - started) * 1000, 2)
    summary = {
        "verdict": _verdict_for(max_severity),
        "total_events": parse["events"].__len__(),
        "normal_events": parse["events"].__len__() - len(anomaly_rows) + (
            1 if (not parse["events"] and not parse["warnings"]) else 0),
        "anomalies": len(anomaly_rows),
        "critical_anomalies": sum(1 for r in anomaly_rows
                                  if r["severity"] == "CRITICAL"),
        "high_anomalies": sum(1 for r in anomaly_rows if r["severity"] == "HIGH"),
        "medium_anomalies": sum(1 for r in anomaly_rows
                                if r["severity"] == "MEDIUM"),
        "max_severity": max_severity,
        "detection_ms": detection_ms,
        "final_state": final_state,
        "accepted": accepted,
    }

    return {
        "filename": filename,
        "source": source,
        "parse": parse,
        "event_sequence": [ev["event"] for ev in parse["events"]],
        "results": results,
        "summary": summary,
    }
