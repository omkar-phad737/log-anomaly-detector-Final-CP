"""OPTIONAL FEATURE — Behavioural Automaton (Python edition).

A second, *learned* machine kept strictly separate from the hand-defined
LogDFA. It is trained on normal logs: every consecutive event pair becomes a
transition of a bigram automaton.

    Normal logs → event sequences → common transitions → behavioural DFA
    → new logs are validated against the learned transitions.

Deliberately simple and transparent: transitions never observed in training
data are flagged MEDIUM. It complements — it does not replace — the manual
DFA.
"""

from __future__ import annotations

from typing import Dict, List

START = "START"


def build_model(sequences: List[List[dict]]) -> dict:
    """sequences: lists of parsed-event dicts (from log_parser.parse_log)."""
    transitions: Dict[str, int] = {}
    for seq in sequences:
        prev = START
        for ev in seq:
            key = f"{prev}|{ev['event']}"
            transitions[key] = transitions.get(key, 0) + 1
            prev = ev["event"]
    return {
        "transitions": transitions,
        "sequences": len(sequences),
        "learned": len(transitions),
    }


def analyze_with_model(model: dict, events: List[dict]) -> List[dict]:
    findings: List[dict] = []
    prev = START
    for ev in events:
        key = f"{prev}|{ev['event']}"
        if key not in model["transitions"]:
            findings.append({
                "position": ev["position"],
                "event": ev["event"],
                "previous_event": prev,
                "severity": "MEDIUM",
                "reason": (
                    f"The behavioural model (learned from {model['sequences']} "
                    f"normal log{'s' if model['sequences'] != 1 else ''}) never "
                    f"observed the transition {prev} → {ev['event']}."
                ),
            })
        prev = ev["event"]
    return findings
