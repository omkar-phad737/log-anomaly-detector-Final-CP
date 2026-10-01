import { motion } from "framer-motion";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { AutomatonGraph } from "@/components/automaton/AutomatonGraph";
import { useAuth } from "@/hooks/use-auth";
import { Link } from "react-router";
import {
  ArrowRight,
  Binary,
  Cpu,
  Radar,
  ShieldCheck,
  Siren,
  Workflow,
} from "lucide-react";

const fadeUp = {
  initial: { opacity: 0, y: 24 },
  animate: { opacity: 1, y: 0 },
};

const FEATURES = [
  {
    icon: Workflow,
    title: "Sequence-aware detection",
    body: "A log is a string w over an event alphabet Σ. The DFA consumes it symbol by symbol — a chain of AUTH_FAILUREs ending in ADMIN_ACCESS is caught by its state transitions, not by keyword search.",
  },
  {
    icon: Binary,
    title: "Hand-built DFA — no ML",
    body: "M = (Q, Σ, δ, q0, F) with 9 states and a fully explicit transition table. Undefined transitions are instrumented error edges that produce an explained finding.",
  },
  {
    icon: Cpu,
    title: "Explained anomalies",
    body: "Every finding reports the event, previous state, expected events, a programmatic reason and a severity: MEDIUM, HIGH or CRITICAL.",
  },
  {
    icon: ShieldCheck,
    title: "Formal-language theory, applied",
    body: "Regular expressions extract the alphabet symbols; a finite automaton validates the behavior. Kleene's theorem is the bridge between the two layers.",
  },
];

const ANOMALY_TYPES = [
  ["Brute-force login", "3× AUTH_FAILURE", "HIGH", "border-amber-500/30 bg-amber-500/10 text-amber-300"],
  ["Privilege escalation", "PRIVILEGE_CHANGE → ADMIN_ACCESS", "CRITICAL", "border-red-500/30 bg-red-500/10 text-red-300"],
  ["Suspicious DB access", "ADMIN/DB without elevation", "HIGH", "border-orange-500/30 bg-orange-500/10 text-orange-300"],
  ["Invalid workflow", "FILE_ACCESS after LOGOUT", "MEDIUM", "border-yellow-500/30 bg-yellow-500/10 text-yellow-300"],
];

export default function Landing() {
  const { isAuthenticated } = useAuth();

  return (
    <div className="min-h-screen bg-background text-foreground">
      {/* ambient grid background */}
      <div
        className="pointer-events-none absolute inset-0 opacity-[0.13]"
        style={{
          backgroundImage:
            "linear-gradient(oklch(0.7 0.08 210 / 0.5) 1px, transparent 1px), linear-gradient(90deg, oklch(0.7 0.08 210 / 0.5) 1px, transparent 1px)",
          backgroundSize: "44px 44px",
          maskImage: "radial-gradient(ellipse 90% 60% at 50% 0%, black 30%, transparent 75%)",
          WebkitMaskImage: "radial-gradient(ellipse 90% 60% at 50% 0%, black 30%, transparent 75%)",
        }}
      />

      {/* nav */}
      <header className="relative z-10 mx-auto flex w-full max-w-7xl items-center justify-between px-4 py-5 sm:px-6 lg:px-8">
        <div className="flex items-center gap-2.5">
          <div className="flex size-9 items-center justify-center rounded-lg bg-cyan-500/10 text-cyan-400">
            <Radar className="size-5" />
          </div>
          <div className="leading-tight">
            <div className="text-sm font-bold tracking-tight">Log Anomaly Detector</div>
            <div className="text-[11px] text-muted-foreground">Finite Automata edition</div>
          </div>
        </div>
        <div className="flex items-center gap-2">
          {isAuthenticated ? (
            <Button asChild size="sm" className="gap-1.5 bg-cyan-500 text-cyan-950 hover:bg-cyan-400">
              <Link to="/dashboard">
                Open dashboard <ArrowRight className="size-3.5" />
              </Link>
            </Button>
          ) : (
            <>
              <Button asChild variant="ghost" size="sm">
                <Link to="/auth">Sign in</Link>
              </Button>
              <Button asChild size="sm" className="gap-1.5 bg-cyan-500 text-cyan-950 hover:bg-cyan-400">
                <Link to="/auth">
                  Launch app <ArrowRight className="size-3.5" />
                </Link>
              </Button>
            </>
          )}
        </div>
      </header>

      {/* hero */}
      <section className="relative z-10 mx-auto w-full max-w-7xl px-4 pb-10 pt-10 sm:px-6 lg:px-8">
        <div className="grid items-center gap-10 lg:grid-cols-[minmax(0,5fr)_minmax(0,7fr)]">
          <motion.div
            {...fadeUp}
            transition={{ duration: 0.55 }}
            className="flex flex-col items-start gap-5"
          >
            <Badge variant="outline" className="gap-1.5 border-cyan-500/30 bg-cyan-500/10 text-cyan-300">
              <Siren className="size-3.5" />
              Theory of Computation · Cybersecurity project
            </Badge>
            <h1 className="text-4xl font-extrabold leading-[1.08] tracking-tight sm:text-5xl">
              Automatic Log Anomaly Detector{" "}
              <span className="bg-gradient-to-r from-cyan-300 via-sky-400 to-teal-300 bg-clip-text text-transparent">
                Using Finite Automata
              </span>
            </h1>
            <p className="max-w-xl text-base leading-7 text-muted-foreground">
              Detect suspicious behavioral sequences using DFA-based analysis.
              The system models valid event behavior as a deterministic finite
              automaton and flags every log that drives the machine through an
              unexpected transition — with a full explanation of{" "}
              <em>why</em>.
            </p>
            <div className="flex flex-wrap items-center gap-3">
              <Button asChild size="lg" className="gap-2 bg-cyan-500 text-cyan-950 hover:bg-cyan-400">
                <Link to={isAuthenticated ? "/dashboard" : "/auth"}>
                  {isAuthenticated ? "Open the dashboard" : "Analyze your first log"}
                  <ArrowRight className="size-4" />
                </Link>
              </Button>
              <Button asChild size="lg" variant="outline" className="gap-2">
                <a href="#how">How the DFA works</a>
              </Button>
            </div>
            <div className="flex flex-wrap gap-x-5 gap-y-1 pt-2 font-mono text-xs text-muted-foreground">
              <span>Q = 9 states</span>
              <span>Σ = 14 events</span>
              <span>F = {"{q2, q3}"}</span>
              <span>5 anomaly classes</span>
            </div>
          </motion.div>

          <motion.div
            initial={{ opacity: 0, scale: 0.97 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ duration: 0.65, delay: 0.15 }}
            className="rounded-xl border border-border/60 bg-card/40 p-3 shadow-2xl shadow-cyan-500/[0.03]"
          >
            <AutomatonGraph
              highlight={{
                from: "q1f3",
                event: "ADMIN_ACCESS",
                to: "q1f3",
                kind: "invalid",
              }}
            />
            <p className="px-2 pb-1 pt-2 text-center text-[11px] text-muted-foreground">
              Live view of M = (Q, Σ, δ, q0, F) — here flagging{" "}
              <span className="font-mono text-red-400">ADMIN_ACCESS</span> from{" "}
              <span className="font-mono">q1f3 (AUTH_FAIL_3+)</span>, where no
              legal transition exists.
            </p>
          </motion.div>
        </div>
      </section>

      {/* anomaly showcase */}
      <section className="relative z-10 mx-auto w-full max-w-7xl px-4 py-10 sm:px-6 lg:px-8">
        <motion.div {...fadeUp} transition={{ duration: 0.5 }} className="flex flex-col gap-4">
          <h2 className="text-2xl font-bold tracking-tight">
            One machine, five explained anomaly classes
          </h2>
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
            {ANOMALY_TYPES.map(([title, pattern, severity, cls]) => (
              <div
                key={title}
                className="flex flex-col gap-2 rounded-xl border border-border/60 bg-card/40 p-4 transition-colors hover:border-cyan-400/30"
              >
                <div className="flex items-center justify-between">
                  <span className="text-sm font-semibold">{title}</span>
                  <Badge variant="outline" className={cls}>
                    {severity}
                  </Badge>
                </div>
                <code className="rounded bg-background/60 px-2 py-1 font-mono text-[11px] text-muted-foreground">
                  {pattern}
                </code>
              </div>
            ))}
          </div>
        </motion.div>
      </section>

      {/* features */}
      <section className="relative z-10 mx-auto w-full max-w-7xl px-4 py-10 sm:px-6 lg:px-8">
        <div className="grid gap-4 sm:grid-cols-2">
          {FEATURES.map((f, i) => (
            <motion.div
              key={f.title}
              initial={{ opacity: 0, y: 18 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true, margin: "-60px" }}
              transition={{ duration: 0.45, delay: i * 0.06 }}
              className="flex gap-4 rounded-xl border border-border/60 bg-card/40 p-5"
            >
              <div className="flex size-10 shrink-0 items-center justify-center rounded-lg bg-cyan-500/10 text-cyan-400">
                <f.icon className="size-5" />
              </div>
              <div>
                <h3 className="font-semibold">{f.title}</h3>
                <p className="mt-1 text-sm leading-6 text-muted-foreground">{f.body}</p>
              </div>
            </motion.div>
          ))}
        </div>
      </section>

      {/* how it works */}
      <section id="how" className="relative z-10 mx-auto w-full max-w-7xl scroll-mt-8 px-4 py-10 sm:px-6 lg:px-8">
        <motion.div {...fadeUp} transition={{ duration: 0.5 }} className="flex flex-col gap-6 rounded-xl border border-border/60 bg-card/40 p-6 sm:p-8">
          <h2 className="text-2xl font-bold tracking-tight">
            From log file to accepted/rejected string
          </h2>
          <div className="grid gap-4 md:grid-cols-5">
            {[
              ["1 · Parse", "Regular expressions extract timestamp, user, IP and the event symbol from each line."],
              ["2 · Project", "Each line becomes one symbol of Σ: w = LOGIN · AUTH_SUCCESS · FILE_ACCESS · LOGOUT."],
              ["3 · Run the DFA", "δ* starts in q0 and consumes w symbol by symbol through the transition table."],
              ["4 · Inspect", "Undefined (state, event) pairs and policy rules (brute-force ladder, escalation) raise findings."],
              ["5 · Explain", "Each finding reports event, previous state, expected events, reason and severity."],
            ].map(([title, body]) => (
              <div key={title} className="flex flex-col gap-2 rounded-lg border border-border/50 bg-background/40 p-4">
                <span className="font-mono text-xs font-semibold text-cyan-300">{title}</span>
                <span className="text-xs leading-5 text-muted-foreground">{body}</span>
              </div>
            ))}
          </div>
          <div className="rounded-lg border border-cyan-500/20 bg-cyan-500/[0.05] p-4 font-mono text-xs leading-6">
            <span className="text-cyan-300">SUSPICIOUS:</span> w = LOGIN · AUTH_FAILURE · AUTH_FAILURE · AUTH_FAILURE · ADMIN_ACCESS
            <br />
            <span className="text-muted-foreground">
              δ climbs the failure ladder q1 → q1f1 → q1f2 → q1f3 (brute-force
              threshold), then <span className="text-red-400">ADMIN_ACCESS has no transition in q1f3</span> →
              CRITICAL anomaly, explained with expected events and reason.
            </span>
          </div>
        </motion.div>
      </section>

      {/* CTA */}
      <section className="relative z-10 mx-auto w-full max-w-7xl px-4 pb-16 pt-6 sm:px-6 lg:px-8">
        <motion.div
          {...fadeUp}
          transition={{ duration: 0.5 }}
          className="flex flex-col items-center gap-4 rounded-xl border border-cyan-500/20 bg-gradient-to-b from-cyan-500/[0.07] to-transparent p-10 text-center"
        >
          <h2 className="text-2xl font-bold tracking-tight sm:text-3xl">
            Load a sample log and watch the automaton decide
          </h2>
          <p className="max-w-xl text-sm leading-6 text-muted-foreground">
            Six built-in samples — two normal, four attacks — plus upload,
            paste and a full analysis history. Free, local, and honest about
            what a DFA can and cannot catch.
          </p>
          <Button asChild size="lg" className="gap-2 bg-cyan-500 text-cyan-950 hover:bg-cyan-400">
            <Link to={isAuthenticated ? "/dashboard" : "/auth"}>
              Start analyzing <ArrowRight className="size-4" />
            </Link>
          </Button>
        </motion.div>
        <footer className="pt-10 text-center text-xs text-muted-foreground">
          Academic prototype · Formal Language &amp; Automata Theory ·
          deterministic finite automata, no machine learning
        </footer>
      </section>
    </div>
  );
}
