import { useState } from "react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { ANOMALY_TYPE_LABELS, SeverityBadge } from "@/components/analysis";
import { useMutation, useQuery } from "convex/react";
import { format } from "date-fns";
import { api } from "@/convex/_generated/api";
import type { Id } from "@/convex/_generated/dataModel";
import { toast } from "sonner";
import { History, Trash2, X } from "lucide-react";
import { cn } from "@/lib/utils";

const VERDICT_CLASS: Record<string, string> = {
  NORMAL: "border-emerald-500/30 bg-emerald-500/10 text-emerald-400",
  ANOMALY: "border-amber-500/30 bg-amber-500/10 text-amber-400",
  CRITICAL: "border-red-500/30 bg-red-500/10 text-red-400",
};

export function HistoryPanel() {
  const scans = useQuery(api.scans.listScans, {});
  const [viewId, setViewId] = useState<Id<"scans"> | null>(null);
  const detail = useQuery(
    api.scans.getScan,
    viewId ? { scanId: viewId } : "skip",
  );
  const removeScan = useMutation(api.scans.deleteScan);
  const clearAll = useMutation(api.scans.clearHistory);

  return (
    <div className="flex flex-col gap-3">
      {!scans ? (
        <p className="text-sm text-muted-foreground">Loading history…</p>
      ) : scans.length === 0 ? (
        <p className="text-sm text-muted-foreground">
          No analyses yet. Every log you analyze is recorded here
          automatically.
        </p>
      ) : (
        <div className="overflow-hidden rounded-lg border">
          <div className="max-h-72 overflow-auto">
            <Table>
              <TableHeader className="sticky top-0 bg-muted/80 backdrop-blur">
                <TableRow>
                  <TableHead>When</TableHead>
                  <TableHead>File</TableHead>
                  <TableHead>Verdict</TableHead>
                  <TableHead className="text-right">Events</TableHead>
                  <TableHead className="text-right">Anomalies</TableHead>
                  <TableHead className="text-right">Critical</TableHead>
                  <TableHead className="w-20 text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {scans.map((scan) => (
                  <TableRow key={scan._id}>
                    <TableCell className="whitespace-nowrap text-xs text-muted-foreground">
                      {format(new Date(scan.createdAt), "MMM d, HH:mm:ss")}
                    </TableCell>
                    <TableCell className="max-w-44 truncate font-mono text-xs" title={scan.filename}>
                      {scan.filename}
                    </TableCell>
                    <TableCell>
                      <Badge
                        variant="outline"
                        className={VERDICT_CLASS[scan.verdict]}
                      >
                        {scan.verdict}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-right font-mono text-xs">
                      {scan.totalEvents}
                    </TableCell>
                    <TableCell className="text-right font-mono text-xs">
                      {scan.anomalies}
                    </TableCell>
                    <TableCell
                      className={cn(
                        "text-right font-mono text-xs",
                        scan.criticalAnomalies > 0 && "font-semibold text-red-400",
                      )}
                    >
                      {scan.criticalAnomalies}
                    </TableCell>
                    <TableCell className="text-right">
                      <div className="flex justify-end gap-1">
                        <Button
                          size="sm"
                          variant="ghost"
                          className="h-7 px-2 text-xs"
                          onClick={() => setViewId(scan._id)}
                        >
                          View
                        </Button>
                        <Button
                          size="sm"
                          variant="ghost"
                          className="h-7 w-7 px-0 text-muted-foreground hover:text-red-400"
                          onClick={() => {
                            removeScan({ scanId: scan._id });
                            toast.success("Scan deleted");
                          }}
                        >
                          <Trash2 className="size-3.5" />
                        </Button>
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </div>
      )}

      <div className="flex justify-end">
        <Button
          variant="outline"
          size="sm"
          disabled={!scans || scans.length === 0}
          onClick={() => {
            if (window.confirm("Delete the entire analysis history?")) {
              clearAll({});
              toast.success("History cleared");
            }
          }}
          className="gap-1.5 text-xs text-muted-foreground"
        >
          <X className="size-3.5" /> Clear history
        </Button>
      </div>

      <Dialog open={viewId !== null} onOpenChange={(o) => !o && setViewId(null)}>
        <DialogContent className="max-w-2xl">
          <DialogHeader>
            <DialogTitle className="font-mono text-base">
              {detail?.scan.filename ?? "Scan"}
            </DialogTitle>
            <DialogDescription>
              {detail
                ? `${detail.scan.verdict} · ${detail.scan.totalEvents} events · ${detail.scan.anomalies} anomalies · δ*(q0,w) = ${detail.scan.finalState}${detail.scan.accepted ? " (accepted)" : " (not accepting)"}`
                : "Loading…"}
            </DialogDescription>
          </DialogHeader>
          {detail && (
            <div className="max-h-[50vh] overflow-auto rounded-lg border">
              <Table>
                <TableHeader className="sticky top-0 bg-muted/80">
                  <TableRow>
                    <TableHead className="w-12">#</TableHead>
                    <TableHead>Event</TableHead>
                    <TableHead>State</TableHead>
                    <TableHead>Severity</TableHead>
                    <TableHead>Type</TableHead>
                    <TableHead className="min-w-56">Reason</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {detail.findings.map((f, i) => (
                    <TableRow key={i}>
                      <TableCell className="font-mono text-xs">{f.position}</TableCell>
                      <TableCell className="font-mono text-xs">{f.event}</TableCell>
                      <TableCell className="font-mono text-xs">
                        {f.previousState} → {f.currentState}
                      </TableCell>
                      <TableCell>
                        <SeverityBadge
                          severity={f.severity as "MEDIUM" | "HIGH" | "CRITICAL"}
                        />
                      </TableCell>
                      <TableCell className="text-xs text-muted-foreground">
                        {ANOMALY_TYPE_LABELS[f.anomalyType] ?? f.anomalyType}
                      </TableCell>
                      <TableCell
                        className="max-w-72 truncate text-xs text-muted-foreground"
                        title={f.reason}
                      >
                        {f.reason}
                      </TableCell>
                    </TableRow>
                  ))}
                  {detail.findings.length === 0 && (
                    <TableRow>
                      <TableCell
                        colSpan={6}
                        className="py-6 text-center text-sm text-emerald-400"
                      >
                        No anomalies were recorded for this scan.
                      </TableCell>
                    </TableRow>
                  )}
                </TableBody>
              </Table>
            </div>
          )}
        </DialogContent>
      </Dialog>

      <p className="flex items-center gap-1.5 text-[11px] text-muted-foreground">
        <History className="size-3.5" />
        Stored in the Convex database (scans + findings tables) — the web
        equivalent of the SQLite history in the Python edition.
      </p>
    </div>
  );
}
