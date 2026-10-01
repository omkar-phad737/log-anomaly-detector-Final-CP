# Automatic Log Anomaly Detector Using Finite Automata

A Formal Language Theory project that detects security anomalies in system
logs by modelling session behaviour as a **Deterministic Finite Automaton
(DFA)**. Events are the input alphabet; the DFA consumes a log token by
token; any illegal move is an anomaly.

| | |
|---|---|
| **Stack** | Python 3.12 · FastAPI · SQLite · vanilla HTML/CSS/JS · pytest |
| **Runs on** | Windows (Git Bash) / macOS / Linux — no Docker, no ML, no cloud |
| **Entry point** | `backend/main.py` (FastAPI app) |
| **Tests** | `tests/` — 28 pytest cases (parser, automaton, detector) |

---

## 1. Problem Statement

System and application logs are the primary evidence for detecting
intrusions, brute-force attempts and misuse, but they arrive as unstructured
text. Manual inspection does not scale, and machine-learning detectors need
training data and are hard to explain.

This project takes a *formal-methods* approach: define the set of **legal
event sequences** as a regular language, recognise it with a finite
automaton, and flag everything the automaton cannot accept as an anomaly.
The result is a deterministic, auditable detector with zero training data.

## 2. Objective

1. Model a user session over a log file as a DFA `(Q, Σ, δ, q0, F)`.
2. Parse real log lines into tokens of a 14-symbol alphabet.
3. Simulate the machine event by event, recording every undefined
   transition as a policy violation.
4. Attach severity levels (INFO → CRITICAL) via a policy layer on top of
   the machine.
5. Serve results through a REST API and a simple web dashboard, with scan
   history persisted in SQLite.

## 3. Features

- **DFA engine** — 9 states, 14-event alphabet, explicit transition table;
  illegal (state, event) pairs fire an instrumented *error edge* that stays
  in the current state and records a finding.
- **Anomaly policies** — brute force, privilege escalation, pre-auth
  privileged events, suspicious database access, invalid workflows,
  unrecognized events, incomplete sessions.
- **Upload & analyze** — drag a `.txt/.log/.out` file (≤ 512 KB) or paste a
  log; sample logs included for one-click demos.
- **History** — every scan and its findings are stored in SQLite and can be
  listed, opened or deleted from the dashboard.
- **Evaluation harness** — `GET /api/evaluation` scores the engine against
  the labelled logs in `data/normal_logs` and `data/anomalous_logs`
  (accuracy, precision, recall, F1) and reports a per-sample breakdown.
- **Behavioral view** — `GET /api/behavioral/analyze` summarises event
  frequencies and state-visits for a log.
- **Tests** — 28 pytest cases covering the parser, every transition class
  of the DFA, and every anomaly policy.

## 4. Technology Used

| Layer | Choice | Why |
|---|---|---|
| Language | Python 3.12 | Course requirement, readable formal-logic code |
| API | FastAPI | Typed request/response models (Pydantic), auto docs at `/docs` |
| Server | Uvicorn | ASGI dev server with `--reload` |
| Database | SQLite (stdlib `sqlite3`) | Zero-config persistence, single-file DB |
| Frontend | HTML + CSS + vanilla JS | No build step; served statically by FastAPI |
| Testing | pytest | Fixture-based unit tests over all three modules |

## 5. System Architecture

```
            ┌──────────────────────────── FastAPI app (backend/main.py) ───────────────────────────┐
            │                                                                                      │
 log file ──►  log_parser.py ──►  detector.py ──► findings + summary                                 │
  or text       (tokenise)          │                                                                  │
                                   ├── automaton.py  (LogDFA: step / run / is_accepted)               │
                                   └── rules.py      (policy: severity, anomaly_type, reasons)        │
                                                                                                      │
            │  database.py (SQLite: scans, findings)   schemas.py (Pydantic DTOs)   models.py        │
            └───────────────┬──────────────────────────────────────────────────┬─────────────────────┘
                            │ /api/* JSON                                      │ /
                            ▼                                                  ▼
                  browser dashboard  (frontend/index.html + style.css + script.js)
```

Flow: a log is tokenised into `LogEvent`s → the DFA consumes them one by
one → each illegal transition is handed to the policy layer which decides
`anomaly_type` and `severity` → the result set plus a summary is returned
and persisted.

## 6. How Finite Automata Are Used

A **finite automaton** is the 5-tuple `M = (Q, Σ, δ, q0, F)`:

- **Q** — a finite set of states,
- **Σ** — a finite input alphabet,
- **δ : Q × Σ → Q** — the transition function,
- **q0 ∈ Q** — the start state,
- **F ⊆ Q** — the set of accepting states.

Here each *state* is a stage of a user session (unauthenticated,
authenticating, authenticated, logged out, elevated …) and each *symbol*
is a normalised log event (`LOGIN`, `AUTH_SUCCESS`, …). Feeding a whole log
to `δ` in sequence answers: *is this session consistent with the way the
system is supposed to be used?* A log is accepted iff the machine ends in
`F`. Everything that forces the machine off its legal rails — an event in
the wrong state, too many auth failures, an escalation — is reported as an
anomaly with the exact `(state, event)` evidence.

Because the language of "normal sessions" is regular, this needs no
machine learning: correctness is by construction and every decision can be
traced to a transition.

## 7. The DFA Design

**States** `Q` (9):

| State | Name | Meaning |
|---|---|---|
| `q0` | `START` | Unauthenticated session start (initial state) |
| `q1` | `LOGIN_ATTEMPT` | A `LOGIN` was seen, awaiting auth result |
| `q1f1` | `AUTH_FAIL_1` | 1 consecutive auth failure |
| `q1f2` | `AUTH_FAIL_2` | 2 consecutive auth failures |
| `q1f3` | `AUTH_FAIL_3` | 3 consecutive auth failures — brute-force bound |
| `q2` | `AUTHENTICATED` | Valid session established (accepting) |
| `q3` | `LOGGED_OUT` | Session ended cleanly (accepting) |
| `q4` | `PRIVILEGE_CHANGE` | User changed privileges while authenticated |
| `q5` | `ADMIN_ACCESS` | Admin functions accessed — monitored state |

**Alphabet** `Σ` (14 events): `LOGIN`, `LOGOUT`, `AUTH_SUCCESS`,
`AUTH_FAILURE`, `FILE_ACCESS`, `FILE_DELETE`, `PASSWORD_CHANGE`,
`USER_ACCESS`, `PRIVILEGE_CHANGE`, `ADMIN_ACCESS`, `DATABASE_ACCESS`,
`API_ACCESS`, `CONFIG_CHANGE`, `SESSION_TIMEOUT`.

**Start state**: `q0`. **Accepting states**: `F = {q2, q3}`.
**Brute-force threshold**: 3 consecutive `AUTH_FAILURE`s (the `q1f3` rung).

### 7.1 Transition table (δ)

| State | Event(s) | Next state | Notes |
|---|---|---|---|
| `q0` | `LOGIN` | `q1` | Session attempt begins |
| `q0` | `SESSION_TIMEOUT` | `q0` | Idle timeout is harmless pre-auth |
| `q0` | anything else | `q0` | **Undefined** → error edge, anomaly recorded |
| `q1` | `AUTH_SUCCESS` | `q2` | Valid login |
| `q1` | `AUTH_FAILURE` | `q1f1` | Failure counter = 1 |
| `q1` | `SESSION_TIMEOUT` | `q0` | Attempt abandoned |
| `q1f1` | `AUTH_FAILURE` | `q1f2` | Failure counter = 2 |
| `q1f1` | `AUTH_SUCCESS` | `q2` | Recovered login |
| `q1f1` | `SESSION_TIMEOUT` | `q0` | Attempt abandoned |
| `q1f2` | `AUTH_FAILURE` | `q1f3` | Failure counter = 3 → brute-force bound |
| `q1f2` | `AUTH_SUCCESS` | `q2` | Recovered login |
| `q1f2` | `SESSION_TIMEOUT` | `q0` | Attempt abandoned |
| `q1f3` | `AUTH_SUCCESS` | `q2` | (Also flagged: threshold already crossed) |
| `q1f3` | `AUTH_FAILURE`, `SESSION_TIMEOUT` | `q0` / `q0` | Reset after the bound |
| `q2` | `FILE_ACCESS`, `FILE_DELETE`, `USER_ACCESS`, `API_ACCESS`, `DATABASE_ACCESS`, `PASSWORD_CHANGE` | `q2` | Normal authenticated activity |
| `q2` | `PRIVILEGE_CHANGE` | `q4` | Enters monitored privilege state |
| `q2` | `LOGOUT` | `q3` | Clean session end |
| `q2` | anything else | `q2` | **Undefined** → error edge, anomaly recorded |
| `q4` | `ADMIN_ACCESS` | `q5` | **Escalation** → CRITICAL policy hit |
| `q4` | `LOGOUT`, `SESSION_TIMEOUT` | `q3` / `q0` | Leaving the privilege state |
| `q4` | anything else | `q4` | **Undefined** → error edge, anomaly recorded |
| `q5` | `LOGOUT`, `SESSION_TIMEOUT` | `q3` / `q0` | Admin session ends |
| `q5` | anything else | `q5` | **Undefined** → error edge, anomaly recorded |
| `q3` | `LOGIN` | `q1` | New session on same connection |
| `q3` | anything else | `q3` | **Undefined** → error edge, anomaly recorded |

### 7.2 Instrumented error edges

A plain DFA would *crash* on an undefined `(state, event)` pair. The engine
instead implements each undefined pair as an **error edge**: the machine
stays in its current state, and the detector records the offending row
(previous state, event, expected transitions). This is what turns the FA
into a practical anomaly detector — violations never silently pass and
never halt the run.

## 8. Anomaly Types Detected

| Anomaly | Trigger | Severity | Example log |
|---|---|---|---|
| `BRUTE_FORCE` | 3rd consecutive `AUTH_FAILURE` (state `q1f3`) | HIGH | attacker retries 3+ passwords |
| `PRIVILEGE_ESCALATION` | `ADMIN_ACCESS` in state `q4` (right after a `PRIVILEGE_CHANGE`) | CRITICAL | user promotes self then opens admin panel |
| `INVALID_TRANSITION` | privileged event (`ADMIN_ACCESS`, `PRIVILEGE_CHANGE`, `CONFIG_CHANGE`, `FILE_DELETE`) while pre-auth / logged out | CRITICAL | admin action without a session |
| `SUSPICIOUS_DATABASE_ACCESS` | `DATABASE_ACCESS` outside a normal authenticated flow | HIGH | DB dump after logout or from odd states |
| `INVALID_WORKFLOW` | ordinary event in a state that doesn't allow it (e.g. `FILE_ACCESS` after `LOGOUT`) | MEDIUM/HIGH | post-logout file browsing |
| `UNRECOGNIZED_EVENT` | event token outside Σ (parser can't normalise the line) | MEDIUM | malformed or foreign log rows |
| `INCOMPLETE_SESSION` | end-of-log reached while not in `F` | MEDIUM | log cuts off mid-login |

A run's summary reports `verdict` (`NORMAL` / `ANOMALY` / `CRITICAL`),
total events, anomaly count, and a severity breakdown.

## 9. Project Structure

```
python-standalone/
├── backend/
│   ├── __init__.py
│   ├── main.py          # FastAPI app: routes, static files, startup
│   ├── automaton.py     # LogDFA — states, alphabet, DELTA, step/run
│   ├── log_parser.py    # raw log text → LogEvent tokens
│   ├── detector.py      # analyze_log_text(): DFA + policy + summary
│   ├── rules.py         # policy layer: anomaly types, severities, reasons
│   ├── database.py      # SQLite connection, schema, scan/findings CRUD
│   ├── schemas.py       # Pydantic request/response models
│   ├── models.py        # dataclasses shared across the engine
│   ├── behavioral.py    # event-frequency / state-visit summaries
│   └── evaluation.py    # accuracy/precision/recall over data/ samples
├── frontend/
│   ├── index.html       # dashboard shell
│   ├── style.css        # styling (no framework)
│   └── script.js        # fetch() calls to /api/*, renders results
├── data/
│   ├── normal_logs/     # normal_login.txt, normal_file_access.txt
│   └── anomalous_logs/  # brute_force.txt, privilege_escalation.txt,
│                        # suspicious_database_access.txt, invalid_workflow.txt
├── tests/
│   ├── test_parser.py   # tokenisation tests
│   ├── test_automaton.py# transition-table / acceptance tests
│   └── test_detector.py # end-to-end anomaly-policy tests
├── uploads/             # runtime upload dir (git-ignored)
├── requirements.txt
├── pytest.ini
├── run.sh               # Git Bash one-command launcher
└── README.md            # ← this file
```

## 10. Installation & Running (Windows Git Bash)

Prerequisite: Python 3.12 installed and on PATH (verify with `py -3.12 --version`).

**Option A — one command:**

```bash
cd python-standalone
bash run.sh          # creates .venv, installs deps, starts the API
bash run.sh test     # ... or just run the pytest suite
```

**Option B — step by step:**

```bash
cd python-standalone

# 1. create and activate a virtual environment
py -3.12 -m venv .venv
source .venv/Scripts/activate      # Git Bash path (cmd: .venv\Scripts\activate)

# 2. install dependencies
pip install -r requirements.txt

# 3. run the API (from python-standalone/, so 'backend' is importable)
python -m uvicorn backend.main:app --reload
```

Then open:

- Dashboard: <http://127.0.0.1:8000>
- Swagger docs: <http://127.0.0.1:8000/docs>
- Health check: <http://127.0.0.1:8000/api/health>

## 11. Running the Tests

```bash
cd python-standalone
source .venv/Scripts/activate
python -m pytest -v          # or: bash run.sh test
```

Expected output: **28 passed** (parser 8 · automaton 8 · detector 12).

## 12. REST API Reference

Base URL: `http://127.0.0.1:8000` — interactive docs at `/docs`.

| Method | Endpoint | Purpose |
|---|---|---|
| `GET` | `/api/health` | Liveness + engine info |
| `GET` | `/api/automaton` | Full DFA definition (states, alphabet, δ, start, accepting) — rendered as the graph on the dashboard |
| `GET` | `/api/samples` | List built-in sample logs |
| `GET` | `/api/sample/{sample_name}` | Fetch one sample's raw text |
| `POST` | `/api/analyze` | Upload a `.txt/.log/.out` file (≤ 512 KB), analyze, save to history |
| `POST` | `/api/analyze-text` | Analyze pasted log text (`{"text": "...", "filename": "..."}`) |
| `GET` | `/api/history` | Recent scans (newest first) |
| `GET` | `/api/history/stats` | Aggregate counts (total scans, anomalies, verdicts) |
| `GET` | `/api/history/{scan_id}` | One scan with all finding rows |
| `DELETE` | `/api/history/{scan_id}` | Delete a scan |
| `DELETE` | `/api/history` | Clear all history |
| `GET` | `/api/evaluation` | Run the engine over `data/` and report accuracy / precision / recall / F1 |
| `GET` | `/api/behavioral/analyze?text=...` | Event-frequency + state-visit profile of a log |
| `GET` | `/` | Serves the dashboard (`frontend/index.html`) |

## 13. Sample Input & Output

**Input format** — one event per line; timestamp and user fields are kept
for display, the `event=` token is what the automaton consumes:

```text
2026-09-30 23:41:02 user=101 ip=203.0.113.45 event=LOGIN
2026-09-30 23:41:05 user=101 ip=203.0.113.45 event=AUTH_FAILURE status=FAILURE
2026-09-30 23:41:11 user=101 ip=203.0.113.45 event=AUTH_FAILURE status=FAILURE
2026-09-30 23:41:18 user=101 ip=203.0.113.45 event=AUTH_FAILURE status=FAILURE
2026-09-30 23:42:40 user=101 ip=203.0.113.45 event=ADMIN_ACCESS
```

**Result** (abridged) for `data/anomalous_logs/brute_force.txt`:

```json
{
  "summary": {
    "verdict": "CRITICAL",
    "total_events": 4,
    "normal_events": 1,
    "anomalies": 3,
    "critical_anomalies": 1,
    "final_state": "q0",
    "accepted": false
  },
  "results": [
    {"position": 1, "event": "LOGIN",        "previous_state": "q0", "current_state": "q1", "status": "NORMAL"},
    {"position": 2, "event": "AUTH_FAILURE", "previous_state": "q1",   "current_state": "q1f1", "status": "NORMAL"},
    {"position": 3, "event": "AUTH_FAILURE", "previous_state": "q1f1", "current_state": "q1f2", "status": "NORMAL"},
    {"position": 4, "event": "AUTH_FAILURE", "previous_state": "q1f2", "current_state": "q1f3", "status": "ANOMALY",
     "anomaly_type": "BRUTE_FORCE", "severity": "HIGH",
     "reason": "3 consecutive authentication failures (threshold reached)"},
    {"position": 5, "event": "ADMIN_ACCESS", "previous_state": "q1f3", "current_state": "q1f3", "status": "ANOMALY",
     "anomaly_type": "INVALID_TRANSITION", "severity": "CRITICAL",
     "reason": "Admin action without an authenticated session"}
  ]
}
```

## 14. Screenshots

> Add your own screenshots here before submission.

| Screen | Placeholder |
|---|---|
| Dashboard with DFA graph | `docs/screenshot-dashboard.png` |
| Analysis results table (brute force) | `docs/screenshot-results.png` |
| History panel | `docs/screenshot-history.png` |
| Swagger docs page | `docs/screenshot-swagger.png` |

## 15. Future Scope

- **Nondeterministic extensions (NFA/ε-NFA):** accept overlapping session
  models (multiple concurrent logins) by converting an NFA to a DFA via
  subset construction.
- **Regex → automaton compiler:** let analysts define acceptable workflows
  as regular expressions and auto-generate the DFA (Thompson's construction
  + minimisation).
- **Live ingestion:** tail syslog/Windows Event Log streams via WebSocket
  instead of static files.
- **Per-user machines:** one DFA instance per user/IP so a noisy session
  can't mask another's anomalies.
- **Severity learning:** calibrate policy weights from analyst feedback
  (keeping the DFA itself deterministic and explainable).

## 16. Limitations

- The alphabet is fixed at 14 normalised events; unknown log formats need
  parser rules before the machine can consume them.
- The DFA is per-file: it models one session timeline, not correlated
  multi-session attacks.
- Thresholds (e.g. brute force = 3) are policy constants, not learned.
- No user authentication on the dashboard or API — it is a course
  prototype, not a hardened production service.

## 17. Team

| Name | Roll No. | Contribution |
|---|---|---|
| *Add member 1* | — | DFA design & engine |
| *Add member 2* | — | Policy layer & tests |
| *Add member 3* | — | API, dashboard & docs |

**Course:** Formal Language Theory · **Guide:** *Faculty name* · **Year:** 2026

## 18. Viva Q&A (quick revision)

**Q1. Why a DFA and not an NFA here?**
Determinism gives a unique next state per (state, event), so every verdict
is reproducible and auditable — important for a security tool. An NFA's
multiple choices would make "which path failed?" ambiguous.

**Q2. Where is the transition function δ in the code?**
`backend/automaton.py` — the `DELTA` table maps `(state, event) → next
state`; `LogDFA.step()` applies it and returns a `Step` record.

**Q3. How do you count "3 consecutive failures" in a memoryless FA?**
The counter is *encoded in the states* `q1f1 → q1f2 → q1f3`. This is the
classic FA technique: bounded counting is free, unbounded counting is
impossible — hence the threshold.

**Q4. What happens on an undefined transition?**
A *plain* DFA would reject/crash. We implement undefined pairs as
instrumented error edges: the machine stays in the current state and the
detector records the row. That's how one bad event surfaces as a finding
without killing the scan.

**Q5. Is the language of normal sessions regular? Prove your design is
enough.**
Yes — it's a finite union of fixed-prefix patterns (login-fail ladder,
login→activity→logout, …). Every accepted string is a finite concatenation
over a finite set of legal fragments, so a DFA suffices; no stack (PDA) is
needed because nothing is unboundedly nested or counted.

**Q6. What are the accepting states and what does rejection mean?**
`F = {q2, q3}` — a healthy session ends authenticated or logged out.
Ending elsewhere (e.g. still pre-auth, stuck in the failure ladder) means
`INCOMPLETE_SESSION` — the log is *not accepted*.

**Q7. Why is the brute-force counter 3 and not unbounded?**
FA cannot count without bound (pumping lemma). The policy fixes a bound;
raising it just means adding more ladder states — still finite, still
regular.

**Q8. Difference between this and an ML anomaly detector?**
No training data, no false-drift: the model *is* the specification.
Every alert maps to an exact (state, event) rule. The trade-off is that
new legitimate workflows require updating the machine.
