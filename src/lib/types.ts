/**
 * Shared types for the Log Anomaly Detector.
 *
 * The system models a log as a string w over an event alphabet Σ and runs a
 * deterministic finite automaton M = (Q, Σ, δ, q0, F) over it, instrumenting
 * every step so anomalies can be explained (not just flagged).
 */

export type Severity = "NONE" | "MEDIUM" | "HIGH" | "CRITICAL";

export type RowStatus = "NORMAL" | "ANOMALY";

export type Verdict = "NORMAL" | "ANOMALY" | "CRITICAL";

/** Classes of anomalies the detector can produce. */
export type AnomalyType =
  | "INVALID_TRANSITION"
  | "INVALID_WORKFLOW"
  | "BRUTE_FORCE"
  | "PRIVILEGE_ESCALATION"
  | "SUSPICIOUS_DATABASE_ACCESS"
  | "UNRECOGNIZED_EVENT"
  | "INCOMPLETE_SESSION";

/** One parsed log line. */
export interface ParsedEvent {
  /** 1-based position in the extracted event sequence. */
  position: number;
  /** 1-based line number in the raw log file. */
  lineNo: number;
  raw: string;
  event: string;
  timestamp?: string;
  user?: string;
  ip?: string;
  status?: string;
}

export interface ParseWarning {
  lineNo: number;
  raw: string;
  message: string;
}

export interface ParseResult {
  events: ParsedEvent[];
  warnings: ParseWarning[];
  totalLines: number;
  skippedLines: number;
}

/** One row of the detection result table (per event + final state check). */
export interface ResultRow {
  position: number;
  event: string;
  previousState: string;
  currentState: string;
  status: RowStatus;
  severity: Severity;
  anomalyType?: AnomalyType;
  expectedEvents: string[];
  reason: string;
  timestamp?: string;
  user?: string;
  ip?: string;
}

export interface AnalysisSummary {
  verdict: Verdict;
  totalEvents: number;
  normalEvents: number;
  anomalies: number;
  criticalAnomalies: number;
  highAnomalies: number;
  mediumAnomalies: number;
  maxSeverity: Severity;
  detectionMs: number;
  finalState: string;
  /** true when δ*(q0, w) ∈ F */
  accepted: boolean;
}

export interface AnalysisResult {
  filename: string;
  source: "upload" | "paste" | "sample";
  parse: ParseResult;
  eventSequence: string[];
  results: ResultRow[];
  summary: AnalysisSummary;
}

/** Serialisable finding used when persisting scans to Convex. */
export interface StoredFinding {
  position: number;
  event: string;
  previousState: string;
  currentState: string;
  severity: string;
  anomalyType: string;
  reason: string;
  expectedEvents: string[];
}
