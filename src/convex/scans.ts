import { v } from "convex/values";
import { mutation, query } from "./_generated/server";

const findingValidator = v.object({
  position: v.number(),
  event: v.string(),
  previousState: v.string(),
  currentState: v.string(),
  severity: v.string(),
  anomalyType: v.string(),
  reason: v.string(),
  expectedEvents: v.array(v.string()),
});

const scanValidator = v.object({
  filename: v.string(),
  source: v.string(),
  verdict: v.string(),
  totalEvents: v.number(),
  normalEvents: v.number(),
  anomalies: v.number(),
  criticalAnomalies: v.number(),
  maxSeverity: v.string(),
  finalState: v.string(),
  accepted: v.boolean(),
  detectionMs: v.number(),
  eventSequence: v.array(v.string()),
  findings: v.array(findingValidator),
});

/** Persist a completed analysis (scan + its anomaly findings). */
export const saveScan = mutation({
  args: { scan: scanValidator },
  handler: async (ctx, { scan }) => {
    const { findings, ...meta } = scan;
    const scanId = await ctx.db.insert("scans", {
      ...meta,
      createdAt: Date.now(),
    });
    for (const f of findings) {
      await ctx.db.insert("findings", { ...f, scanId });
    }
    return scanId;
  },
});

/** Recent scans, newest first (dashboard history panel). */
export const listScans = query({
  args: {},
  handler: async (ctx) => {
    return await ctx.db
      .query("scans")
      .withIndex("by_createdAt")
      .order("desc")
      .take(50);
  },
});

/** One scan with its findings (history detail view). */
export const getScan = query({
  args: { scanId: v.id("scans") },
  handler: async (ctx, { scanId }) => {
    const scan = await ctx.db.get(scanId);
    if (!scan) return null;
    const findings = await ctx.db
      .query("findings")
      .withIndex("by_scanId", (q) => q.eq("scanId", scanId))
      .collect();
    findings.sort((a, b) => a.position - b.position);
    return { scan, findings };
  },
});

/** Delete one scan and its findings. */
export const deleteScan = mutation({
  args: { scanId: v.id("scans") },
  handler: async (ctx, { scanId }) => {
    const findings = await ctx.db
      .query("findings")
      .withIndex("by_scanId", (q) => q.eq("scanId", scanId))
      .collect();
    for (const f of findings) {
      await ctx.db.delete(f._id);
    }
    await ctx.db.delete(scanId);
  },
});

/** Wipe the whole history. */
export const clearHistory = mutation({
  args: {},
  handler: async (ctx) => {
    const findings = await ctx.db.query("findings").collect();
    for (const f of findings) {
      await ctx.db.delete(f._id);
    }
    const scans = await ctx.db.query("scans").collect();
    for (const s of scans) {
      await ctx.db.delete(s._id);
    }
  },
});
