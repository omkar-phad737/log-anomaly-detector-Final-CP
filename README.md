# LogSense — Automatic Log Anomaly Detector Using Finite Automata

A security log analyzer that models user sessions as a **Deterministic
Finite Automaton (DFA)**: log events are the input alphabet, the DFA walks
the session state-by-state, and every illegal `(state, event)` move is
flagged as an anomaly with a severity — no machine learning, fully
explainable, correct by construction.

This repo contains **two complete editions** of the same project:

| Edition | Location | Stack | Purpose |
|---|---|---|---|
| **Live web app** (this app) | `src/` | TypeScript, React 19, Vite, Convex, Tailwind, shadcn/ui | Runs right here — hosted UI, DFA graph, scan history |
| **Standalone Python edition** | `python-standalone/` | Python 3.12, FastAPI, SQLite, vanilla HTML/CSS/JS, pytest | Copy-paste and run locally on Windows Git Bash per the project spec — see [`python-standalone/README.md`](python-standalone/README.md) |

Both editions implement the identical DFA and anomaly policies; the TS
engine (`src/lib/`) and Python engine (`python-standalone/backend/`) are
verified against the same sample traces and each carries its own tests.

---

## The DFA at a glance

`M = (Q, Σ, δ, q0, F)`

- **Q (9 states):** `q0 START`, `q1 LOGIN_ATTEMPT`, `q1f1/q1f2/q1f3`
  (the auth-failure ladder = bounded brute-force counter), `q2
  AUTHENTICATED`, `q3 LOGGED_OUT`, `q4 PRIVILEGE_CHANGE`, `q5 ADMIN_ACCESS`
- **Σ (14 events):** `LOGIN`, `LOGOUT`, `AUTH_SUCCESS`, `AUTH_FAILURE`,
  `FILE_ACCESS`, `FILE_DELETE`, `PASSWORD_CHANGE`, `USER_ACCESS`,
  `PRIVILEGE_CHANGE`, `ADMIN_ACCESS`, `DATABASE_ACCESS`, `API_ACCESS`,
  `CONFIG_CHANGE`, `SESSION_TIMEOUT`
- **q0:** `START` · **F:** `{q2, q3}` (session ends healthy)
- **Undefined (state, event) pairs** become *instrumented error edges*: the
  machine stays put and the detector records a finding — violations never
  crash the run.

### Anomaly policies

| Anomaly | Trigger | Severity |
|---|---|---|
| `BRUTE_FORCE` | 3rd consecutive `AUTH_FAILURE` (reaching `q1f3`) | HIGH |
| `PRIVILEGE_ESCALATION` | `ADMIN_ACCESS` from `q4` (right after a privilege change) | CRITICAL |
| `INVALID_TRANSITION` | privileged event while pre-auth / logged out | CRITICAL |
| `SUSPICIOUS_DATABASE_ACCESS` | `DATABASE_ACCESS` outside a normal authenticated flow | HIGH |
| `INVALID_WORKFLOW` | ordinary event in a state that forbids it (e.g. `FILE_ACCESS` after `LOGOUT`) | MEDIUM/HIGH |
| `UNRECOGNIZED_EVENT` | token outside Σ | MEDIUM |
| `INCOMPLETE_SESSION` | log ends outside `F` (not accepted) | MEDIUM |

## Live web app

- **Landing (`/`)** — themed hero with a live animated DFA graph, anomaly
  showcase, features, and how-it-works; CTAs lead into sign-in.
- **Auth (`/auth`)** — email OTP sign-in/sign-up; protected routes return
  here with their original path preserved.
- **Dashboard (`/dashboard`)** — upload/paste/sample tabs (≤ 512 KB,
  `.txt/.log/.out`), full per-event transition trace, severity-cards,
  anomaly details, interactive **AutomatonGraph** with the DFA transition
  table, evaluation metrics panel, and **scan history** persisted per user
  in Convex (`scans` + `findings` tables).

### Key files

```
src/lib/automaton.ts       LogDFA — Q, Σ, DELTA, start/accepting states
src/lib/parser.ts          log text → normalized event tokens
src/lib/detector.ts        analyzeLogText() — DFA + policy + summary
src/lib/evaluation.ts      accuracy/precision/recall/F1 over sample corpus
src/lib/behavioral.ts      event-frequency / state-visit profiles
src/components/automaton/AutomatonGraph.tsx   SVG DFA graph + transition table
src/pages/Landing.tsx      public landing page
src/pages/Dashboard.tsx    authenticated workspace
src/convex/schema.ts       scans + findings tables (indexed)
src/convex/scans.ts        saveScan / listScans / getScan / deleteScan / clearHistory
```

## Development

The dev server and Convex backend run as managed background sessions on
this platform — edits hot-apply automatically. Useful checks:

```bash
bun tsc -b --noEmit          # typecheck the web app
bun convex dev --once        # regenerate Convex types after backend edits
```

## Standalone Python edition (Git Bash quickstart)

```bash
cd python-standalone
bash run.sh                  # creates .venv, installs deps, starts FastAPI on :8000
bash run.sh test             # runs the pytest suite (28 tests)

# or manually:
py -3.12 -m venv .venv
source .venv/Scripts/activate
pip install -r requirements.txt
python -m uvicorn backend.main:app --reload      # dashboard at http://127.0.0.1:8000
python -m pytest -v
```

Full documentation — architecture, DFA transition table, API reference,
sample inputs/outputs, viva Q&A — lives in
[`python-standalone/README.md`](python-standalone/README.md).
