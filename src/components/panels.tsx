import { Badge } from "@/components/ui/badge";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { ALPHABET, EVENT_DESCRIPTIONS } from "@/lib/alphabet";
import { runEvaluation } from "@/lib/evaluation";
import { cn } from "@/lib/utils";
import { AlertCircle, Info } from "lucide-react";

const PCT = (x: number) => `${(x * 100).toFixed(1)}%`;

export function EvaluationPanel() {
  // Sample set is static, so a single synchronous evaluation run is fine.
  const report = runEvaluation();
  return (
    <div className="flex flex-col gap-3">
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        {[
          ["Accuracy", PCT(report.accuracy)],
          ["Precision", PCT(report.precision)],
          ["Recall", PCT(report.recall)],
          ["F1-score", PCT(report.f1)],
        ].map(([label, value]) => (
          <div
            key={label}
            className="rounded-lg border border-border/60 bg-background/40 p-3"
          >
            <div className="text-xs text-muted-foreground">{label}</div>
            <div className="text-xl font-bold tabular-nums">{value}</div>
          </div>
        ))}
      </div>

      <div className="flex flex-wrap gap-x-5 gap-y-1 text-xs text-muted-foreground">
        <span>
          TP {report.truePositive} · FP {report.falsePositive} · TN{" "}
          {report.trueNegative} · FN {report.falseNegative}
        </span>
        <span>
          Events processed {report.totalEvents} · anomalies{" "}
          {report.totalAnomalies} · critical {report.totalCritical}
        </span>
        <span>avg detection time {report.avgDetectionMs} ms</span>
      </div>

      <div className="overflow-hidden rounded-lg border">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Sample file</TableHead>
              <TableHead>Label</TableHead>
              <TableHead>Predicted</TableHead>
              <TableHead className="text-right">Events</TableHead>
              <TableHead className="text-right">Anomalies</TableHead>
              <TableHead className="text-right">Critical</TableHead>
              <TableHead className="text-right">Time (ms)</TableHead>
              <TableHead className="text-right">Result</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {report.samples.map((s) => (
              <TableRow key={s.filename}>
                <TableCell className="font-mono text-xs">{s.filename}</TableCell>
                <TableCell>
                  <Badge
                    variant="outline"
                    className="border-border/60 text-xs text-muted-foreground"
                  >
                    {s.label}
                  </Badge>
                </TableCell>
                <TableCell>
                  <Badge
                    variant="outline"
                    className={cn(
                      "text-xs",
                      s.predicted === "normal"
                        ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-400"
                        : "border-red-500/30 bg-red-500/10 text-red-400",
                    )}
                  >
                    {s.predicted}
                  </Badge>
                </TableCell>
                <TableCell className="text-right font-mono text-xs">
                  {s.events}
                </TableCell>
                <TableCell className="text-right font-mono text-xs">
                  {s.anomalies}
                </TableCell>
                <TableCell className="text-right font-mono text-xs">
                  {s.critical}
                </TableCell>
                <TableCell className="text-right font-mono text-xs">
                  {s.detectionMs}
                </TableCell>
                <TableCell
                  className={cn(
                    "text-right text-xs font-semibold",
                    s.correct ? "text-emerald-400" : "text-red-400",
                  )}
                >
                  {s.correct ? "✓ correct" : "✗ wrong"}
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </div>

      <p className="flex items-start gap-1.5 rounded-lg border border-amber-500/30 bg-amber-500/[0.06] p-2.5 text-xs leading-5 text-amber-300/90">
        <AlertCircle className="mt-0.5 size-3.5 shrink-0" />
        {report.disclaimer}
      </p>
    </div>
  );
}

export function AlphabetPanel() {
  return (
    <div className="flex flex-col gap-2">
      <div className="flex flex-wrap gap-1.5">
        {ALPHABET.map((event) => (
          <Badge
            key={event}
            variant="outline"
            className="border-border/60 bg-background/40 font-mono text-[11px] font-normal"
            title={EVENT_DESCRIPTIONS[event]}
          >
            {event}
          </Badge>
        ))}
      </div>
      <p className="text-xs leading-5 text-muted-foreground">
        Σ = the set of all events the automaton understands. A log line is
        reduced to exactly one symbol of Σ by the parser's regular expressions;
        any other token is outside Σ* and is reported as an unknown-symbol
        anomaly. Adding a new event means adding it here plus its transitions
        in δ.
      </p>
    </div>
  );
}

export function TheoryPanel() {
  return (
    <div className="flex flex-col gap-3 text-sm leading-6">
      <div className="rounded-lg border border-border/60 bg-background/40 p-3">
        <div className="mb-1 font-mono text-xs text-cyan-300">
          M = (Q, Σ, δ, q0, F)
        </div>
        <ul className="list-disc space-y-1 pl-5 text-muted-foreground">
          <li>
            <span className="font-mono text-foreground">Q</span> = 9 states: q0,
            q1, q1f1, q1f2, q1f3, q2, q3, q4, q5
          </li>
          <li>
            <span className="font-mono text-foreground">Σ</span> = 14 event
            symbols (see the Alphabet panel)
          </li>
          <li>
            <span className="font-mono text-foreground">δ: Q × Σ → Q</span> —
            the transition table (see the Transition table tab); undefined
            pairs are instrumented error edges
          </li>
          <li>
            <span className="font-mono text-foreground">q0</span> = START
          </li>
          <li>
            <span className="font-mono text-foreground">F</span> = {"{q2, q3}"}{" "}
            — a log is accepted iff δ*(q0, w) ∈ F
          </li>
        </ul>
      </div>

      <div className="rounded-lg border border-border/60 bg-background/40 p-3">
        <div className="mb-1 font-semibold">From log file to string over Σ</div>
        <div className="font-mono text-xs leading-6 text-muted-foreground">
          2026-09-30 10:00:01 user=101 event=LOGIN
          <br />→ regex → <span className="text-cyan-300">LOGIN</span>
          <br />
          2026-09-30 10:00:02 user=101 event=AUTH_SUCCESS
          <br />→ regex → <span className="text-cyan-300">AUTH_SUCCESS</span>
          <br />
          <br />w = LOGIN · AUTH_SUCCESS · FILE_ACCESS · LOGOUT
        </div>
      </div>

      <div className="rounded-lg border border-border/60 bg-background/40 p-3">
        <div className="mb-1 font-semibold">
          Regular expression → NFA → DFA — the theory chain
        </div>
        <p className="text-muted-foreground">
          Each parser regex describes a regular language over ASCII; a regex
          engine compiles it (regex → NFA via Thompson's construction → DFA via
          subset construction) to match lines. Our DFA then validates the
          extracted <em>sequence</em> — regular expressions validate what a
          single line looks like, the finite automaton validates how the lines
          follow one another. Kleene's theorem guarantees both layers are
          exactly regular languages.
        </p>
      </div>

      <p className="flex items-start gap-1.5 text-xs text-muted-foreground">
        <Info className="mt-0.5 size-3.5 shrink-0" />
        The "3 consecutive failures" ladder (q1f1 → q1f2 → q1f3) is a bounded
        counter — a fixed threshold is expressible in a pure DFA without
        memory, which is exactly why this design stays within the power of
        regular languages.
      </p>
    </div>
  );
}
