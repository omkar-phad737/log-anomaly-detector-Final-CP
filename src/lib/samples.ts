export interface SampleLog {
  id: string;
  /** Button label on the dashboard. */
  name: string;
  filename: string;
  /** Expected verdict, used by the self-evaluation. */
  label: "normal" | "anomalous";
  description: string;
  content: string;
}

const normalLogin = `# Normal user session — expected workflow
2026-09-30 10:00:01 user=101 ip=10.0.4.12 event=LOGIN
2026-09-30 10:00:02 user=101 ip=10.0.4.12 event=AUTH_SUCCESS status=SUCCESS
2026-09-30 10:02:10 user=101 ip=10.0.4.12 event=FILE_ACCESS
2026-09-30 10:03:15 user=101 ip=10.0.4.12 event=FILE_ACCESS
2026-09-30 10:05:20 user=101 ip=10.0.4.12 event=LOGOUT
`;

const normalFileAccess = `# Normal file-server activity
2026-09-30 09:12:00 user=202 ip=10.0.4.35 event=LOGIN
2026-09-30 09:12:01 user=202 ip=10.0.4.35 event=AUTH_SUCCESS status=SUCCESS
2026-09-30 09:13:00 user=202 ip=10.0.4.35 event=USER_ACCESS
2026-09-30 09:15:30 user=202 ip=10.0.4.35 event=API_ACCESS
2026-09-30 09:16:00 user=202 ip=10.0.4.35 event=FILE_ACCESS
2026-09-30 09:18:45 user=202 ip=10.0.4.35 event=FILE_DELETE
2026-09-30 09:20:00 user=202 ip=10.0.4.35 event=LOGOUT
`;

const bruteForce = `# Repeated authentication failures followed by admin access
2026-09-30 23:41:02 user=101 ip=203.0.113.45 event=LOGIN
2026-09-30 23:41:05 user=101 ip=203.0.113.45 event=AUTH_FAILURE status=FAILURE
2026-09-30 23:41:11 user=101 ip=203.0.113.45 event=AUTH_FAILURE status=FAILURE
2026-09-30 23:41:18 user=101 ip=203.0.113.45 event=AUTH_FAILURE status=FAILURE
2026-09-30 23:42:40 user=101 ip=203.0.113.45 event=ADMIN_ACCESS
`;

const privilegeEscalation = `# Privilege change followed by administrative access
2026-09-30 14:02:11 user=302 ip=10.0.7.61 event=LOGIN
2026-09-30 14:02:12 user=302 ip=10.0.7.61 event=AUTH_SUCCESS status=SUCCESS
2026-09-30 14:04:30 user=302 ip=10.0.7.61 event=USER_ACCESS
2026-09-30 14:06:15 user=302 ip=10.0.7.61 event=PRIVILEGE_CHANGE
2026-09-30 14:06:40 user=302 ip=10.0.7.61 event=ADMIN_ACCESS
2026-09-30 14:08:02 user=302 ip=10.0.7.61 event=DATABASE_ACCESS
2026-09-30 14:09:11 user=302 ip=10.0.7.61 event=CONFIG_CHANGE
2026-09-30 14:12:00 user=302 ip=10.0.7.61 event=LOGOUT
`;

const suspiciousDatabaseAccess = `# Administrative + database access without any privilege change
2026-09-30 16:20:04 user=405 ip=10.0.9.8 event=LOGIN
2026-09-30 16:20:05 user=405 ip=10.0.9.8 event=AUTH_SUCCESS status=SUCCESS
2026-09-30 16:21:30 user=405 ip=10.0.9.8 event=ADMIN_ACCESS
2026-09-30 16:22:12 user=405 ip=10.0.9.8 event=DATABASE_ACCESS
`;

const invalidWorkflow = `# Valid session, then activity after logout
2026-09-30 11:00:00 user=204 ip=10.0.4.90 event=LOGIN
2026-09-30 11:00:01 user=204 ip=10.0.4.90 event=AUTH_SUCCESS status=SUCCESS
2026-09-30 11:05:00 user=204 ip=10.0.4.90 event=FILE_ACCESS
2026-09-30 11:06:00 user=204 ip=10.0.4.90 event=LOGOUT
2026-09-30 11:09:00 user=204 ip=10.0.4.90 event=FILE_ACCESS
2026-09-30 11:09:30 user=204 ip=10.0.4.90 event=FILE_DELETE
`;

export const SAMPLE_LOGS: SampleLog[] = [
  {
    id: "normal-login",
    name: "Load Normal Log",
    filename: "normal_login.txt",
    label: "normal",
    description: "Login → auth success → file access → logout",
    content: normalLogin,
  },
  {
    id: "normal-file-access",
    name: "Load Normal File Activity",
    filename: "normal_file_access.txt",
    label: "normal",
    description: "Everyday file/API activity, clean logout",
    content: normalFileAccess,
  },
  {
    id: "brute-force",
    name: "Load Brute Force",
    filename: "brute_force.txt",
    label: "anomalous",
    description: "3× auth failure, then ADMIN_ACCESS",
    content: bruteForce,
  },
  {
    id: "privilege-escalation",
    name: "Load Privilege Escalation",
    filename: "privilege_escalation.txt",
    label: "anomalous",
    description: "PRIVILEGE_CHANGE → ADMIN_ACCESS chain",
    content: privilegeEscalation,
  },
  {
    id: "database-attack",
    name: "Load Database Attack",
    filename: "suspicious_database_access.txt",
    label: "anomalous",
    description: "Admin + DB access without privilege change",
    content: suspiciousDatabaseAccess,
  },
  {
    id: "invalid-workflow",
    name: "Load Invalid Workflow",
    filename: "invalid_workflow.txt",
    label: "anomalous",
    description: "File access after LOGOUT",
    content: invalidWorkflow,
  },
];

export function getSample(id: string): SampleLog | undefined {
  return SAMPLE_LOGS.find((s) => s.id === id);
}
