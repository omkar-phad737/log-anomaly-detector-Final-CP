/**
 * Self-evaluation over the labelled sample set.
 *
 * IMPORTANT (academic honesty): the six built-in samples form a tiny sanity
 * check, not a benchmark. Accuracy/precision/recall/F1 here mean "does the
 * DFA prototype separate these labelled examples correctly". Real-world
 * performance cannot be claimed from six files.
 */

import { analyzeLogText } from "./detector";
import { SAMPLE_LOGS } from "./samples";
import type { Verdict } from "./types";

export interface SampleEvaluation {
  filename: string;
  label: "normal" | "anomalous";
  predicted: "normal" | "anomalous";
  correct: boolean;
  anomalies: number;
  critical: number;
  events: number;
  detectionMs: number;
}

export interface EvaluationReport {
  samples: SampleEvaluation[];
  totalEvents: number;
  totalAnomalies: number;
  totalCritical: number;
  avgDetectionMs: number;
  truePositive: number;
  falsePositive: number;
  trueNegative: number;
  falseNegative: number;
  accuracy: number;
  precision: number;
  recall: number;
  f1: number;
  disclaimer: string;
}

export function runEvaluation(): EvaluationReport {
  const samples: SampleEvaluation[] = SAMPLE_LOGS.map((s) => {
    const result = analyzeLogText(s.content, s.filename, "sample");
    const predicted: "normal" | "anomalous" =
      result.summary.anomalies > 0 ? "anomalous" : "normal";
    return {
      filename: s.filename,
      label: s.label,
      predicted,
      correct: predicted === s.label,
      anomalies: result.summary.anomalies,
      critical: result.summary.criticalAnomalies,
      events: result.summary.totalEvents,
      detectionMs: result.summary.detectionMs,
    };
  });

  let tp = 0;
  let fp = 0;
  let tn = 0;
  let fn = 0;
  for (const s of samples) {
    if (s.label === "anomalous" && s.predicted === "anomalous") tp += 1;
    else if (s.label === "normal" && s.predicted === "anomalous") fp += 1;
    else if (s.label === "normal" && s.predicted === "normal") tn += 1;
    else fn += 1;
  }

  const precision = tp + fp > 0 ? tp / (tp + fp) : 0;
  const recall = tp + fn > 0 ? tp / (tp + fn) : 0;
  const f1 =
    precision + recall > 0 ? (2 * precision * recall) / (precision + recall) : 0;

  return {
    samples,
    totalEvents: samples.reduce((a, s) => a + s.events, 0),
    totalAnomalies: samples.reduce((a, s) => a + s.anomalies, 0),
    totalCritical: samples.reduce((a, s) => a + s.critical, 0),
    avgDetectionMs:
      Math.round(
        (samples.reduce((a, s) => a + s.detectionMs, 0) / samples.length) * 100,
      ) / 100,
    truePositive: tp,
    falsePositive: fp,
    trueNegative: tn,
    falseNegative: fn,
    accuracy: (tp + tn) / samples.length,
    precision,
    recall,
    f1,
    disclaimer:
      "Computed on 6 labelled sample files (2 normal, 4 anomalous). This is a sanity check of a rule/DFA-based academic prototype — not a real-world benchmark, and no general detection accuracy is claimed.",
  };
}
