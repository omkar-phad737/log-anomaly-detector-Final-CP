import { useState } from "react";
import { AutomatonGraph, TransitionTable } from "@/components/automaton/AutomatonGraph";
import {
  AnomalyDetails,
  EventSequence,
  ResultsTable,
  StatsCards,
} from "@/components/analysis";
import { InputPanel } from "@/components/input-panel";
import { HistoryPanel } from "@/components/history-panel";
import {
  AlphabetPanel,
  EvaluationPanel,
  TheoryPanel,
} from "@/components/panels";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useAuth } from "@/hooks/use-auth";
import { useMutation } from "convex/react";
import { api } from "@/convex/_generated/api";
import { analyzeLogText } from "@/lib/detector";
import { getSample, type SampleLog } from "@/lib/samples";
import type { AnalysisResult, ResultRow } from "@/lib/types";
import { toast } from "sonner";
import { ShieldCheck, LogOut, Radar } from "lucide-react";
import { useNavigate } from "react-router";

export default function Dashboard() {
  const { user, signOut } = useAuth();
  const navigate = useNavigate();
  const saveScan = useMutation(api.scans.saveScan);

  const [logText, setLogText] = useState("");
  const [filename, setFilename] = useState("");
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [selectedIdx, setSelectedIdx] = useState<number | null>(null);

  const loadSample = (sample: SampleLog) => {
    setLogText(sample.content);
    setFilename(sample.filename);
    setResult(null);
    setSelectedIdx(null);
    toast.success(`Loaded ${sample.filename}`);
  };

  const handleAnalyze = () => {
    if (!logText.trim()) {
      toast.error("Load, paste or upload a log first.");
      return;
    }
    const isSample = Boolean(getSample(filename));
    const res = analyzeLogText(
      logText,
      filename || "pasted-log.txt",
      isSample ? "sample" : "paste",
    );
    setResult(res);
    setSelectedIdx(null);
    saveScan({
      scan: {
        filename: res.filename,
      source: res.source,
      verdict: res.summary.verdict,
      totalEvents: res.summary.totalEvents,
      normalEvents: res.summary.normalEvents,
      anomalies: res.summary.anomalies,
      criticalAnomalies: res.summary.criticalAnomalies,
      maxSeverity: res.summary.maxSeverity,
      finalState: res.summary.finalState,
      accepted: res.summary.accepted,
      detectionMs: res.summary.detectionMs,
      eventSequence: res.eventSequence,
      findings: res.results
        .filter((r) => r.status === "ANOMALY")
        .map((r) => ({
          position: r.position,
          event: r.event,
          previousState: r.previousState,
          currentState: r.currentState,
          severity: r.severity as string,
          anomalyType: r.anomalyType ?? "INVALID_TRANSITION",
          reason: r.reason,
          expectedEvents: r.expectedEvents,
        })),
      },
    });
    toast.success(
      `Analysis complete — ${res.summary.verdict} (${res.summary.anomalies} anomal${res.summary.anomalies === 1 ? "y" : "ies"})`,
    );
  };

  const handleSignOut = async () => {
    await signOut();
    navigate("/");
  };

  const selectedRow: ResultRow | undefined =
    selectedIdx !== null ? result?.results[selectedIdx] : undefined;

  // Which transition (if any) should the graph highlight?
  const graphHighlight = (() => {
    if (!result || selectedIdx === null) return null;
    const row = result.results[selectedIdx];
    if (!row || row.status !== "ANOMALY" || row.event === "END_OF_LOG") {
      return null;
    }
    if (
      row.anomalyType === "PRIVILEGE_ESCALATION" ||
      row.anomalyType === "BRUTE_FORCE"
    ) {
      return {
        from: row.previousState,
        event: row.event,
        to: row.currentState,
        kind: "policy" as const,
      };
    }
    return {
      from: row.previousState,
      event: row.event,
      to: row.currentState,
      kind: "invalid" as const,
    };
  })();

  return (
    <main className="min-h-screen bg-background text-foreground">
      <div className="mx-auto flex w-full max-w-7xl flex-col gap-6 px-4 py-8 sm:px-6 lg:px-8">
        {/* header */}
        <header className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
          <div className="flex items-start gap-3">
            <div className="flex size-11 shrink-0 items-center justify-center rounded-lg bg-cyan-500/10 text-cyan-400">
              <Radar className="size-6" />
            </div>
            <div>
              <h1 className="text-xl font-bold tracking-tight sm:text-2xl">
                Automatic Log Anomaly Detector{" "}
                <span className="text-cyan-400">Using Finite Automata</span>
              </h1>
              <p className="text-sm text-muted-foreground">
                Detect suspicious behavioral sequences using DFA-based analysis
                {user?.name ? ` — signed in as ${user.name}` : ""}
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <Badge
              variant="outline"
              className="gap-1 border-cyan-500/30 bg-cyan-500/10 text-cyan-300"
            >
              <ShieldCheck className="size-3.5" /> DFA engine · 9 states
            </Badge>
            <Button
              variant="outline"
              size="sm"
              onClick={handleSignOut}
              className="gap-1.5"
            >
              <LogOut className="size-3.5" /> Sign out
            </Button>
          </div>
        </header>

        <StatsCards result={result} />

        <div className="grid gap-6 lg:grid-cols-[minmax(0,5fr)_minmax(0,7fr)]">
          {/* left column */}
          <div className="flex flex-col gap-6">
            <Card className="border-border/60 bg-card/60 shadow-none">
              <CardHeader className="pb-3">
                <CardTitle className="text-base">1 · Input log</CardTitle>
              </CardHeader>
              <CardContent>
                <InputPanel
                  logText={logText}
                  filename={filename}
                  onTextChange={(t) => {
                    setLogText(t);
                    if (!filename) setFilename("");
                  }}
                  onFilenameChange={setFilename}
                  onAnalyze={handleAnalyze}
                  onLoadSample={loadSample}
                />
              </CardContent>
            </Card>

            <Card className="border-border/60 bg-card/60 shadow-none">
              <CardHeader className="pb-3">
                <CardTitle className="text-base">3 · Detection results</CardTitle>
              </CardHeader>
              <CardContent>
                <ResultsTable
                  result={result}
                  selected={selectedIdx}
                  onSelect={(i) => setSelectedIdx(i === selectedIdx ? null : i)}
                />
              </CardContent>
            </Card>
          </div>

          {/* right column */}
          <div className="flex flex-col gap-6">
            <Card className="border-border/60 bg-card/60 shadow-none">
              <CardHeader className="pb-3">
                <CardTitle className="text-base">2 · Event sequence</CardTitle>
              </CardHeader>
              <CardContent>
                <EventSequence
                  result={result}
                  selected={selectedIdx}
                  onSelect={(i) => setSelectedIdx(i === selectedIdx ? null : i)}
                />
              </CardContent>
            </Card>

            <Card className="border-border/60 bg-card/60 shadow-none">
              <CardHeader className="pb-3">
                <CardTitle className="text-base">4 · Anomaly details</CardTitle>
              </CardHeader>
              <CardContent>
                <AnomalyDetails row={selectedRow} />
              </CardContent>
            </Card>

            <Card className="border-border/60 bg-card/60 shadow-none">
              <CardHeader className="pb-3">
                <CardTitle className="flex items-center justify-between text-base">
                  <span>7 · Automaton visualization</span>
                  <span className="font-mono text-xs font-normal text-muted-foreground">
                    M = (Q, Σ, δ, q0, F)
                  </span>
                </CardTitle>
              </CardHeader>
              <CardContent>
                <AutomatonGraph
                  highlight={graphHighlight}
                  currentState={selectedRow ? selectedRow.currentState : result ? result.summary.finalState : null}
                />
              </CardContent>
            </Card>
          </div>
        </div>
        {/* theory, transition table, evaluation, history */}
        <Card className="border-border/60 bg-card/60 shadow-none">
          <CardHeader className="pb-3">
            <CardTitle className="text-base">Automaton reference &amp; self-evaluation</CardTitle>
          </CardHeader>
          <CardContent>
            <Tabs defaultValue="table">
              <TabsList className="mb-3 flex flex-wrap gap-1">
                <TabsTrigger value="table" className="text-xs">Transition table</TabsTrigger>
                <TabsTrigger value="theory" className="text-xs">Theory (Q, Σ, δ, q0, F)</TabsTrigger>
                <TabsTrigger value="alphabet" className="text-xs">Alphabet Σ</TabsTrigger>
                <TabsTrigger value="eval" className="text-xs">Evaluation</TabsTrigger>
                <TabsTrigger value="history" className="text-xs">History</TabsTrigger>
              </TabsList>
              <TabsContent value="table">
                <TransitionTable />
              </TabsContent>
              <TabsContent value="theory">
                <TheoryPanel />
              </TabsContent>
              <TabsContent value="alphabet">
                <AlphabetPanel />
              </TabsContent>
              <TabsContent value="eval">
                <EvaluationPanel />
              </TabsContent>
              <TabsContent value="history">
                <HistoryPanel />
              </TabsContent>
            </Tabs>
          </CardContent>
        </Card>

        <footer className="pb-4 text-center text-xs text-muted-foreground">
          Rule/DFA-based academic prototype · Formal Language &amp; Automata Theory ·
          no machine learning involved
        </footer>
      </div>
    </main>
  );
}
