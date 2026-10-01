import { authTables } from "@convex-dev/auth/server";
import { defineSchema, defineTable } from "convex/server";
import { Infer, v } from "convex/values";

// default user roles. can add / remove based on the project as needed
export const ROLES = {
  ADMIN: "admin",
  USER: "user",
  MEMBER: "member",
} as const;

export const roleValidator = v.union(
  v.literal(ROLES.ADMIN),
  v.literal(ROLES.USER),
  v.literal(ROLES.MEMBER),
);
export type Role = Infer<typeof roleValidator>;

const schema = defineSchema(
  {
    // default auth tables using convex auth.
    ...authTables, // do not remove or modify

    // the users table is the default users table that is brought in by the authTables
    users: defineTable({
      name: v.optional(v.string()), // name of the user. do not remove
      image: v.optional(v.string()), // image of the user. do not remove
      email: v.optional(v.string()), // email of the user. do not remove
      emailVerificationTime: v.optional(v.number()), // email verification time. do not remove
      isAnonymous: v.optional(v.boolean()), // is the user anonymous. do not remove

      role: v.optional(roleValidator), // role of the user. do not remove
    }).index("email", ["email"]), // index for the email. do not remove or modify

    // add other tables here

    // Analysis history: one row per completed log analysis.
    scans: defineTable({
      filename: v.string(),
      source: v.string(), // "upload" | "paste" | "sample"
      verdict: v.string(), // "NORMAL" | "ANOMALY" | "CRITICAL"
      totalEvents: v.number(),
      normalEvents: v.number(),
      anomalies: v.number(),
      criticalAnomalies: v.number(),
      maxSeverity: v.string(), // "NONE" | "MEDIUM" | "HIGH" | "CRITICAL"
      finalState: v.string(),
      accepted: v.boolean(),
      detectionMs: v.number(),
      eventSequence: v.array(v.string()),
      createdAt: v.number(),
    }).index("by_createdAt", ["createdAt"]),

    // Anomaly findings belonging to a scan.
    findings: defineTable({
      scanId: v.id("scans"),
      position: v.number(),
      event: v.string(),
      previousState: v.string(),
      currentState: v.string(),
      severity: v.string(),
      anomalyType: v.string(),
      reason: v.string(),
      expectedEvents: v.array(v.string()),
    }).index("by_scanId", ["scanId"]),
  },
  {
    schemaValidation: false,
  },
);

export default schema;
