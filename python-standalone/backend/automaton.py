"""LogDFA — a hand-built deterministic finite automaton (no DFA library).

M = (Q, Σ, δ, q0, F)

  Q  = 9 states (STATES). The three AUTH_FAIL_n states encode a *bounded
       counter*: "3 consecutive authentication failures" is a fixed threshold,
       so it is expressible in a pure DFA without memory.
  Σ  = the event alphabet defined in rules.py.
  δ  = DELTA, a table (state, symbol) → state. Missing entries are
       *instrumented error edges*: the machine stays in its current state
       (so analysis can continue) but reports an invalid transition.
  q0 = "q0" (START).
  F  = {"q2", "q3"} — valid resting states at the end of a log.

The class contains only machine mechanics. Severity, thresholds and
explanations live in detector.py / rules.py.
"""

from __future__ import annotations

from typing import Dict, List, Tuple

from .rules import ALPHABET

# --------------------------------------------------------------------------
# Q — the set of states
# --------------------------------------------------------------------------

STATES: Dict[str, str] = {
    "q0": "START",
    "q1": "LOGIN_ATTEMPT",
    "q1f1": "AUTH_FAIL_1",
    "q1f2": "AUTH_FAIL_2",
    "q1f3": "AUTH_FAIL_3+",
    "q2": "AUTHENTICATED",
    "q3": "LOGGED_OUT",
    "q4": "PRIVILEGE_CHANGE",
    "q5": "ADMIN_ACCESS",
}

START_STATE = "q0"
ACCEPTING_STATES = ("q2", "q3")  # F
BRUTE_FORCE_THRESHOLD = 3


# --------------------------------------------------------------------------
# δ — the transition function: (state, event) -> state
# --------------------------------------------------------------------------

DELTA: Dict[str, Dict[str, str]] = {
    "q0": {"LOGIN": "q1"},
    "q1": {
        "AUTH_SUCCESS": "q2",
        "AUTH_FAILURE": "q1f1",
        "LOGOUT": "q3",
        "SESSION_TIMEOUT": "q3",
    },
    "q1f1": {
        "AUTH_FAILURE": "q1f2",
        "AUTH_SUCCESS": "q2",
        "LOGOUT": "q3",
        "SESSION_TIMEOUT": "q3",
    },
    "q1f2": {
        "AUTH_FAILURE": "q1f3",
        "AUTH_SUCCESS": "q2",
        "LOGOUT": "q3",
        "SESSION_TIMEOUT": "q3",
    },
    "q1f3": {
        "AUTH_FAILURE": "q1f3",
        "AUTH_SUCCESS": "q2",
        "LOGOUT": "q3",
        "SESSION_TIMEOUT": "q3",
    },
    "q2": {
        "FILE_ACCESS": "q2",
        "FILE_DELETE": "q2",
        "PASSWORD_CHANGE": "q2",
        "USER_ACCESS": "q2",
        "API_ACCESS": "q2",
        "PRIVILEGE_CHANGE": "q4",
        "LOGOUT": "q3",
        "SESSION_TIMEOUT": "q3",
    },
    "q3": {"LOGIN": "q1"},
    "q4": {
        "ADMIN_ACCESS": "q5",
        "FILE_ACCESS": "q4",
        "FILE_DELETE": "q4",
        "CONFIG_CHANGE": "q4",
        "PASSWORD_CHANGE": "q4",
        "USER_ACCESS": "q4",
        "LOGOUT": "q3",
        "SESSION_TIMEOUT": "q3",
    },
    "q5": {
        "DATABASE_ACCESS": "q5",
        "FILE_ACCESS": "q5",
        "FILE_DELETE": "q5",
        "CONFIG_CHANGE": "q5",
        "API_ACCESS": "q5",
        "PASSWORD_CHANGE": "q5",
        "USER_ACCESS": "q5",
        "LOGOUT": "q3",
        "SESSION_TIMEOUT": "q3",
    },
}


class StepResult:
    """Outcome of consuming one symbol."""

    __slots__ = ("allowed", "from_state", "to_state", "event", "expected")

    def __init__(self, allowed: bool, from_state: str, to_state: str,
                 event: str, expected: List[str]) -> None:
        self.allowed = allowed
        self.from_state = from_state
        self.to_state = to_state
        self.event = event
        self.expected = expected

    def as_dict(self) -> dict:
        return {
            "allowed": self.allowed,
            "from": self.from_state,
            "to": self.to_state,
            "event": self.event,
            "expected": self.expected,
        }


def _expected_from(state: str) -> List[str]:
    """Legal events from a state, in alphabet order (for explanations)."""
    table = DELTA.get(state, {})
    return [e for e in ALPHABET if e in table]


class LogDFA:
    """A fresh instance starts in q0; step() consumes one symbol of the input."""

    def __init__(self, start: str = START_STATE) -> None:
        self._state = start

    def reset(self) -> None:
        self._state = START_STATE

    @property
    def current_state(self) -> str:
        return self._state

    def state_label(self, state: str | None = None) -> str:
        return STATES.get(state or self._state, state or "")

    def is_accepting(self, state: str | None = None) -> bool:
        return (state or self._state) in ACCEPTING_STATES

    def expected_events(self, state: str | None = None) -> List[str]:
        return _expected_from(state or self._state)

    def has_transition(self, state: str, event: str) -> bool:
        return event in DELTA.get(state, {})

    def step(self, event: str) -> StepResult:
        """Consume one symbol. On an undefined transition the machine stays
        in its current state (an instrumented error edge)."""
        src = self._state
        expected = _expected_from(src)
        dst = DELTA.get(src, {}).get(event)
        if dst is None:
            return StepResult(False, src, src, event, expected)
        self._state = dst
        return StepResult(True, src, dst, event, expected)

    def run(self, events: List[str]) -> List[StepResult]:
        """Consume a whole string w = e1·e2·…·en."""
        self.reset()
        return [self.step(e) for e in events]


def automaton_definition() -> dict:
    """Machine-readable description of M = (Q, Σ, δ, q0, F) for /api/automaton."""
    transitions = [
        {"from": s, "event": e, "to": t}
        for s, table in DELTA.items()
        for e, t in table.items()
    ]
    return {
        "states": [{"name": n, "label": l} for n, l in STATES.items()],
        "alphabet": list(ALPHABET),
        "start_state": START_STATE,
        "accepting_states": list(ACCEPTING_STATES),
        "transitions": transitions,
        "brute_force_threshold": BRUTE_FORCE_THRESHOLD,
        "policy_notes": [
            "Undefined (state, event) pairs are instrumented error edges: the DFA "
            "stays in its current state and the detector records an anomaly.",
            f"Entering q1f3 (AUTH_FAIL_3+) flags a brute-force pattern "
            f"(threshold = {BRUTE_FORCE_THRESHOLD} consecutive failures).",
            "Entering q5 (ADMIN_ACCESS) after a privilege change is a legal "
            "transition but flagged CRITICAL by security policy.",
            "A log is accepted iff δ*(q0, w) ∈ F = {q2, q3}; otherwise an "
            "incomplete-session note is recorded.",
        ],
    }
