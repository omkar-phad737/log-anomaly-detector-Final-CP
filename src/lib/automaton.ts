/**
 * LogDFA — a hand-built deterministic finite automaton (no DFA library).
 *
 * M = (Q, Σ, δ, q0, F)
 *
 *   Q  = 9 states (see STATES below). The three AUTH_FAIL_n states encode a
 *        *bounded counter*: "3 consecutive authentication failures" is a fixed
 *        threshold, so it is expressible in a pure DFA without extra memory.
 *   Σ  = the 14-event alphabet in alphabet.ts.
 *   δ  = DELTA, a table (state × symbol) → state. Missing entries are
 *        *instrumented error edges*: the machine stays in its current state
 *        (so analysis can continue) but reports an invalid transition.
 *   q0 = "q0" (START).
 *   F  = {q2 AUTHENTICATED, q3 LOGGED_OUT} — valid resting states at the end
 *        of a log. Ending anywhere else yields an "incomplete session" note.
 */

import { ALPHABET } from "./alphabet";

export interface DfaState {
  name: string;
  label: string;
  description: string;
}

export const STATES: Record<string, DfaState> = {
  q0: {
    name: "q0",
    label: "START",
    description: "No session activity has been observed yet.",
  },
  q1: {
    name: "q1",
    label: "LOGIN_ATTEMPT",
    description: "A LOGIN was received; awaiting the authentication outcome.",
  },
  q1f1: {
    name: "q1f1",
    label: "AUTH_FAIL_1",
    description: "One consecutive authentication failure (tolerated).",
  },
  q1f2: {
    name: "q1f2",
    label: "AUTH_FAIL_2",
    description: "Two consecutive authentication failures (tolerated).",
  },
  q1f3: {
    name: "q1f3",
    label: "AUTH_FAIL_3+",
    description:
      "Three or more consecutive failures — brute-force territory (flagged).",
  },
  q2: {
    name: "q2",
    label: "AUTHENTICATED",
    description: "A normal, authenticated working session.",
  },
  q3: {
    name: "q3",
    label: "LOGGED_OUT",
    description: "The session has been terminated or timed out.",
  },
  q4: {
    name: "q4",
    label: "PRIVILEGE_CHANGE",
    description: "An authenticated actor had their privileges modified.",
  },
  q5: {
    name: "q5",
    label: "ADMIN_ACCESS",
    description: "A privileged administrative context (policy-flagged).",
  },
};

export const START_STATE = "q0";
export const ACCEPTING_STATES: readonly string[] = ["q2", "q3"];

export const BRUTE_FORCE_THRESHOLD = 3;

/**
 * δ: (state, event) → state.  Keys are state names, values map event → next
 * state.  A missing (state, event) pair means "no valid transition".
 */
export const DELTA: Record<string, Record<string, string>> = {
  q0: {
    LOGIN: "q1",
  },
  q1: {
    AUTH_SUCCESS: "q2",
    AUTH_FAILURE: "q1f1",
    LOGOUT: "q3",
    SESSION_TIMEOUT: "q3",
  },
  q1f1: {
    AUTH_FAILURE: "q1f2",
    AUTH_SUCCESS: "q2",
    LOGOUT: "q3",
    SESSION_TIMEOUT: "q3",
  },
  q1f2: {
    AUTH_FAILURE: "q1f3",
    AUTH_SUCCESS: "q2",
    LOGOUT: "q3",
    SESSION_TIMEOUT: "q3",
  },
  q1f3: {
    AUTH_FAILURE: "q1f3",
    AUTH_SUCCESS: "q2",
    LOGOUT: "q3",
    SESSION_TIMEOUT: "q3",
  },
  q2: {
    FILE_ACCESS: "q2",
    FILE_DELETE: "q2",
    PASSWORD_CHANGE: "q2",
    USER_ACCESS: "q2",
    API_ACCESS: "q2",
    PRIVILEGE_CHANGE: "q4",
    LOGOUT: "q3",
    SESSION_TIMEOUT: "q3",
  },
  q3: {
    LOGIN: "q1",
  },
  q4: {
    ADMIN_ACCESS: "q5",
    FILE_ACCESS: "q4",
    FILE_DELETE: "q4",
    CONFIG_CHANGE: "q4",
    PASSWORD_CHANGE: "q4",
    USER_ACCESS: "q4",
    LOGOUT: "q3",
    SESSION_TIMEOUT: "q3",
  },
  q5: {
    DATABASE_ACCESS: "q5",
    FILE_ACCESS: "q5",
    FILE_DELETE: "q5",
    CONFIG_CHANGE: "q5",
    PASSWORD_CHANGE: "q5",
    API_ACCESS: "q5",
    USER_ACCESS: "q5",
    LOGOUT: "q3",
    SESSION_TIMEOUT: "q3",
  },
};

export interface StepResult {
  /** false when δ has no entry for (currentState, event). */
  allowed: boolean;
  from: string;
  to: string;
  event: string;
  /** Sorted legal events from the previous state (empty for unknown symbols). */
  expected: string[];
}

/** Deterministic order for listing expected events in explanations. */
function expectedFrom(state: string): string[] {
  const table = DELTA[state] ?? {};
  return ALPHABET.filter((e) => e in table);
}

/**
 * The automaton. A fresh instance starts in q0; `step` consumes one symbol of
 * the input string. The class contains *only* machine mechanics — severity,
 * thresholds and explanations live in detector.ts.
 */
export class LogDFA {
  private stateName: string;

  constructor(start: string = START_STATE) {
    this.stateName = start;
  }

  reset(): void {
    this.stateName = START_STATE;
  }

  get currentState(): string {
    return this.stateName;
  }

  get stateLabel(): string {
    return STATES[this.stateName]?.label ?? this.stateName;
  }

  isAccepting(state: string = this.stateName): boolean {
    return ACCEPTING_STATES.includes(state);
  }

  /** Legal events from a state (used for "expected events" explanations). */
  expectedEvents(state: string = this.stateName): string[] {
    return expectedFrom(state);
  }

  hasTransition(state: string, event: string): boolean {
    return Boolean(DELTA[state]?.[event]);
  }

  /**
   * Consume one symbol. On an undefined transition the machine remains in its
   * current state (an instrumented error edge) so the rest of the log can
   * still be analysed.
   */
  step(event: string): StepResult {
    const from = this.stateName;
    const expected = expectedFrom(from);
    const to = DELTA[from]?.[event];
    if (to === undefined) {
      return { allowed: false, from, to: from, event, expected };
    }
    this.stateName = to;
    return { allowed: true, from, to, event, expected };
  }

  /** Consume a whole string w = e1·e2·…·en, returning every instrumented step. */
  run(events: string[]): StepResult[] {
    this.reset();
    return events.map((e) => this.step(e));
  }
}

export interface AutomatonDefinition {
  states: DfaState[];
  alphabet: string[];
  startState: string;
  acceptingStates: string[];
  transitions: { from: string; event: string; to: string }[];
  bruteForceThreshold: number;
  policyNotes: string[];
}

/** Machine-readable description of M = (Q, Σ, δ, q0, F) — powers /api/automaton. */
export function automatonDefinition(): AutomatonDefinition {
  const transitions: AutomatonDefinition["transitions"] = [];
  for (const [from, table] of Object.entries(DELTA)) {
    for (const [event, to] of Object.entries(table)) {
      transitions.push({ from, event, to });
    }
  }
  return {
    states: Object.values(STATES),
    alphabet: [...ALPHABET],
    startState: START_STATE,
    acceptingStates: [...ACCEPTING_STATES],
    transitions,
    bruteForceThreshold: BRUTE_FORCE_THRESHOLD,
    policyNotes: [
      "Undefined (state, event) pairs are instrumented error edges: the DFA stays in its current state and the detector records an anomaly.",
      `Entering q1f3 (AUTH_FAIL_3+) flags a brute-force pattern (threshold = ${BRUTE_FORCE_THRESHOLD} consecutive failures).`,
      "Entering q5 (ADMIN_ACCESS) after a privilege change is a legal transition but flagged CRITICAL by security policy (privilege-escalation review).",
      "A log is accepted iff δ*(q0, w) ∈ F = {q2, q3}; otherwise an incomplete-session note is recorded.",
    ],
  };
}
