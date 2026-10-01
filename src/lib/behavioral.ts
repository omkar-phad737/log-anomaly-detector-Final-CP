/**
 * OPTIONAL FEATURE — Behavioural Automaton.
 *
 * A second, *learned* machine kept strictly separate from the hand-defined
 * LogDFA. It is trained on normal logs: every consecutive event pair becomes
 * a transition of a bigram automaton (states = "previous event", alphabet =
 * the event alphabet, start state = a virtual START symbol).
 *
 *   Normal logs → event sequences → common transitions → behavioural DFA
 *   → new logs are validated against the learned transitions.
 *
 * This is deliberately simple and transparent: it flags transitions that were
 * never observed in training data as MEDIUM findings. It complements — it
 * does not replace — the manually defined DFA.
 */

import type { AnomalyType, ParsedEvent, Severity } from "./types";

export interface BehavioralModel {
  /** key: `${prev}|${event}` where prev is "START" or an event symbol. */
  transitions: Record<string, number>;
  /** Number of training sequences. */
  sequences: number;
  /** Total transitions learned. */
  learned: number;
}

export interface BehavioralFinding {
  position: number;
  event: string;
  previousEvent: string;
  severity: Severity;
  anomalyType: AnomalyType;
  reason: string;
}

export function buildBehavioralModel(sequences: string[][]): BehavioralModel {
  const transitions: Record<string, number> = {};
  for (const seq of sequences) {
    let prev = "START";
    for (const event of seq) {
      const key = `${prev}|${event}`;
      transitions[key] = (transitions[key] ?? 0) + 1;
      prev = event;
    }
  }
  return {
    transitions,
    sequences: sequences.length,
    learned: Object.keys(transitions).length,
  };
}

/** Validate a new sequence against the learned transition set. */
export function analyzeWithBehavioralModel(
  model: BehavioralModel,
  events: ParsedEvent[],
): { findings: BehavioralFinding[]; seen: number; unseen: number } {
  const findings: BehavioralFinding[] = [];
  let seen = 0;
  let unseen = 0;
  let prev = "START";

  for (const ev of events) {
    const key = `${prev}|${ev.event}`;
    if (model.transitions[key]) {
      seen += 1;
    } else {
      unseen += 1;
      findings.push({
        position: ev.position,
        event: ev.event,
        previousEvent: prev,
        severity: "MEDIUM",
        anomalyType: "INVALID_TRANSITION",
        reason: `The behavioural model (learned from ${model.sequences} normal log${model.sequences === 1 ? "" : "s"}) never observed the transition ${prev} → ${ev.event}.`,
      });
    }
    prev = ev.event;
  }

  return { findings, seen, unseen };
}
