import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { STATES } from "@/lib/automaton";
import { EVENT_DESCRIPTIONS } from "@/lib/alphabet";
import type { AnalysisResult, ResultRow, Severity } from "@/lib/types";
import { cn } from "@/lib/utils";
import {
  Activity,
  AlertTriangle,
  MousePointerClick,
  ShieldCheck,
  Siren,
} from "lucide-react";

export const ANOMALY_TYPE_LABELS: Record<string, string> = {
  INVALID_TRANSITION: "Invalid transition",
  INVALID_WORKFLOW: "Invalid workflow",
  BRUTE_FORCE: "Brute-force login",
  PRIVILEGE_ESCALATION: "Privilege escalation",
  SUSPICIOUS_DATABASE_ACCESS: "Suspicious database access",
  UNRECOGNIZED_EVENT: "Unknown symbol (∉ Σ)",
  INCOMPLETE_SESSION: "Incomplete session",
};

export const SEVERITY_TEXT: Record<Severity, string> = {
  NONE: "text-emerald-400",
  MEDIUM: "text-amber-400",
  HIGH: "text-orange-400",
  CRITICAL: "text-red-400",
};

const SEVERITY_BADGE: Record<Severity, string> = {
  NONE: "bg-emerald-500/10 text-emerald-400 border-emerald-500/30",
  MEDIUM: "bg-amber-500/10 text-amber-400 border-amber-500/30",
  HIGH: "bg-orange-500/10 text-orange-400 border-orange-500/30",
  CRITICAL: "bg-red-500/10 text-red-400 border-red-500/30",
};

const ROW_TINT: Record<Severity, string> = {
  NONE: "",
  MEDIUM: "bg-amber-500/[0.06]",
  HIGH: "bg-orange-500/[0.08]",
  CRITICAL: "bg-red-500/[0.09]",
};

export function SeverityBadge({ severity }: { severity: Severity }) {
  if (severity === "NONE") {
    return (
      <Badge
        variant="outline"
        className="border-emerald-500/30 bg-emerald-500/10 text-emerald-400"
      >
        —
      </Badge>
    );
  }
  return (
    <Badge variant="outline" className={SEVERITY_BADGE[severity]}>
      {severity}
    </Badge>
  );
}

function stateTag(state: string) {
  const label = STATES[state]?.label;
  return label ? `${state} · ${label}` : state;
}

// ---------------------------------------------------------------- stats

export function StatsCards({ result }: { result: AnalysisResult | null }) {
  const s = result?.summary;
  const cards = [
    {
      label: "Total Events",
      value: s ? s.totalEvents : "—",
      icon: Activity,
      accent: "text-cyan-400",
      bg: "bg-cyan-500/10",
    },
    {
      label: "Normal Events",
      value: s ? s.normalEvents : "—",
      icon: ShieldCheck,
      accent: "text-emerald-400",
      bg: "bg-emerald-500/10",
    },
    {
      label: "Anomalies",
      value: s ? s.anomalies : "—",
      icon: AlertTriangle,
      accent: "text-amber-400",
      bg: "bg-amber-500/10",
    },
    {
      label: "Critical Anomalies",
      value: s ? s.criticalAnomalies : "—",
      icon: Siren,
      accent: "text-red-400",
      bg: "bg-red-500/10",
    },
  ];
  return (
    <div className="flex flex-col gap-3">
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        {cards.map((c) => (
          <Card
            key={c.label}
            className="border-border/60 bg-card/60 shadow-none"
          >
            <CardContent className="flex items-center gap-3 p-4">
              <div
                className={cn(
                  "flex size-10 shrink-0 items-center justify-center rounded-lg",
                  c.bg,
                )}
              >
                <c.icon className={cn("size-5", c.accent)} />
              </div>
              <div className="min-w-0">
                <div className="truncate text-2xl font-bold tabular-nums">
                  {c.value}
                </div>
                <div className="truncate text-xs text-muted-foreground">
                  {c.label}
                </div>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>
      {s && (
        <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-muted-foreground">
          <span>
            Verdict:{" "}
            <span
              className={cn(
                "font-semibold",
                s.verdict === "CRITICAL"
                  ? "text-red-400"
                  : s.verdict === "ANOMALY"
                    ? "text-amber-400"
                    : "text-emerald-400",
              )}
            >
              {s.verdict}
            </span>
          </span>
          <span>
            Final state δ*(q0, w):{" "}
            <span className="font-mono">{stateTag(s.finalState)}</span>{" "}
            {s.accepted ? (
              <span className="text-emerald-400">(∈ F, accepted)</span>
            ) : (
              <span className="text-amber-400">(∉ F)</span>
            )}
          </span>
          <span>Detection time: {s.detectionMs} ms</span>
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------- sequence

export function EventSequence({
  result,
  selected,
  onSelect,
}: {
  result: AnalysisResult | null;
  selected: number | null;
  onSelect: (index: number) => void;
}) {
  if (!result) {
    return (
      <p className="text-sm text-muted-foreground">
        Analyze a log to see its event sequence w = e₁·e₂·…·eₙ.
      </p>
    );
  }
  return (
    <div className="flex flex-wrap items-center gap-1.5">
      {result.results.map((row, i) => (
        <span key={i} className="flex items-center gap-1.5">
          {i > 0 && <span className="text-muted-foreground/50">→</span>}
          <button
            type="button"
            onClick={() => onSelect(i)}
            title={
              row.status === "ANOMALY"
                ? `${ANOMALY_TYPE_LABELS[row.anomalyType ?? ""]}: ${row.reason}`
                : row.reason
            }
            className={cn(
              "rounded-md border px-2 py-0.5 font-mono text-[11px] transition-colors",
              row.status === "ANOMALY"
                ? SEVERITY_BADGE[row.severity]
                : "border-emerald-500/30 bg-emerald-500/[0.07] text-emerald-300 hover:bg-emerald-500/15",
              selected === i && "ring-2 ring-cyan-400/70",
            )}
          >
            {row.event}
          </button>
        </span>
      ))}
    </div>
  );
}

// ---------------------------------------------------------------- results table

export function ResultsTable({
  result,
  selected,
  onSelect,
}: {
  result: AnalysisResult | null;
  selected: number | null;
  onSelect: (index: number) => void;
}) {
  if (!result) {
    return (
      <p className="flex items-center gap-2 text-sm text-muted-foreground">
        <MousePointerClick className="size-4" />
        Run an analysis to populate the detection results table.
      </p>
    );
  }
  return (
    <div className="overflow-hidden rounded-lg border">
      <div className="max-h-96 overflow-auto">
        <Table>
          <TableHeader className="sticky top-0 bg-muted/80 backdrop-blur">
            <TableRow>
              <TableHead className="w-14">#</TableHead>
              <TableHead>Event</TableHead>
              <TableHead>Previous state</TableHead>
              <TableHead>Current state</TableHead>
              <TableHead>Status</TableHead>
              <TableHead>Severity</TableHead>
              <TableHead className="min-w-72">Reason</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {result.results.map((row, i) => (
              <TableRow
                key={i}
                onClick={() => onSelect(i)}
                className={cn(
                  "cursor-pointer",
                  ROW_TINT[row.severity],
                  selected === i && "ring-1 ring-inset ring-cyan-400/60",
                )}
              >
                <TableCell className="font-mono text-xs tabular-nums">
                  {row.event === "END_OF_LOG" ? "⟂" : row.position}
                </TableCell>
                <TableCell className="font-mono text-xs font-semibold">
                  {row.event}
                </TableCell>
                <TableCell className="font-mono text-xs">
                  {stateTag(row.previousState)}
                </TableCell>
                <TableCell className="font-mono text-xs">
                  {stateTag(row.currentState)}
                </TableCell>
                <TableCell>
                  <span
                    className={cn(
                      "text-xs font-semibold",
                      row.status === "ANOMALY" ? "text-red-400" : "text-emerald-400",
                    )}
                  >
                    {row.status}
                  </span>
                </TableCell>
                <TableCell>
                  <SeverityBadge severity={row.severity} />
                </TableCell>
                <TableCell
                  className="max-w-96 truncate text-xs text-muted-foreground"
                  title={row.reason}
                >
                  {row.reason}
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------- details

export function AnomalyDetails({
  row,
}: {
  row: ResultRow | null | undefined;
}) {
  if (!row) {
    return (
      <p className="text-sm text-muted-foreground">
        Click a row in the results table (or a chip in the event sequence) to
        inspect it here. Anomalies show the offending event, previous DFA
        state, expected events and a generated explanation.
      </p>
    );
  }
  const anomaly = row.status === "ANOMALY";
  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap items-center gap-2">
        <span className="font-mono text-lg font-bold">{row.event}</span>
        <SeverityBadge severity={row.severity} />
        {anomaly && row.anomalyType && (
          <Badge variant="outline" className="border-border/60 text-xs">
            {ANOMALY_TYPE_LABELS[row.anomalyType] ?? row.anomalyType}
          </Badge>
        )}
        {!anomaly && (
          <Badge
            variant="outline"
            className="border-emerald-500/30 bg-emerald-500/10 text-xs text-emerald-400"
          >
            NORMAL
          </Badge>
        )}
      </div>

      <div className="grid grid-cols-2 gap-3 text-sm sm:grid-cols-4">
        <div>
          <div className="text-[11px] uppercase tracking-wide text-muted-foreground">
            Position
          </div>
          <div className="font-mono">
            {row.event === "END_OF_LOG" ? "⟂ end of log" : row.position}
          </div>
        </div>
        <div>
          <div className="text-[11px] uppercase tracking-wide text-muted-foreground">
            Previous state
          </div>
          <div className="font-mono">{stateTag(row.previousState)}</div>
        </div>
        <div>
          <div className="text-[11px] uppercase tracking-wide text-muted-foreground">
            Current state
          </div>
          <div className="font-mono">{stateTag(row.currentState)}</div>
        </div>
        <div>
          <div className="text-[11px] uppercase tracking-wide text-muted-foreground">
            Expected events
          </div>
          <div className="mt-0.5 flex flex-wrap gap-1">
            {row.expectedEvents.length ? (
              row.expectedEvents.map((e) => (
                <Badge
                  key={e}
                  variant="outline"
                  className="px-1.5 py-0 font-mono text-[10px]"
                  title={EVENT_DESCRIPTIONS[e]}
                >
                  {e}
                </Badge>
              ))
            ) : (
              <span className="text-xs text-muted-foreground">—</span>
            )}
          </div>
        </div>
      </div>

      <div className="rounded-lg border bg-background/40 p-3 text-sm leading-6">
        <span className="mr-2 font-semibold uppercase tracking-wide text-muted-foreground">
          Reason
        </span>
        {row.reason}
      </div>

      {(row.user || row.timestamp || row.ip) && (
        <div className="flex flex-wrap gap-x-4 gap-y-1 font-mono text-[11px] text-muted-foreground">
          {row.timestamp && <span>timestamp: {row.timestamp}</span>}
          {row.user && <span>user: {row.user}</span>}
          {row.ip && <span>ip: {row.ip}</span>}
        </div>
      )}
    </div>
  );
}
