/**
 * The event alphabet Σ of the automaton.
 *
 * Each log line is reduced (via regular expressions) to exactly one symbol of
 * Σ. Unknown symbols are not in Σ* and are reported as anomalies by the
 * detector instead of being silently ignored.
 */

export const ALPHABET = [
  "LOGIN",
  "LOGOUT",
  "AUTH_SUCCESS",
  "AUTH_FAILURE",
  "FILE_ACCESS",
  "FILE_DELETE",
  "PASSWORD_CHANGE",
  "USER_ACCESS",
  "PRIVILEGE_CHANGE",
  "ADMIN_ACCESS",
  "DATABASE_ACCESS",
  "API_ACCESS",
  "CONFIG_CHANGE",
  "SESSION_TIMEOUT",
] as const;

export type EventSymbol = (typeof ALPHABET)[number];

/** Human-readable meaning of each symbol (used in tooltips and explanations). */
export const EVENT_DESCRIPTIONS: Record<string, string> = {
  LOGIN: "A login attempt has started",
  LOGOUT: "The session was explicitly terminated",
  AUTH_SUCCESS: "Credentials were verified successfully",
  AUTH_FAILURE: "Credential verification failed",
  FILE_ACCESS: "A file was read or opened",
  FILE_DELETE: "A file was deleted",
  PASSWORD_CHANGE: "A password was changed",
  USER_ACCESS: "A user resource was accessed",
  PRIVILEGE_CHANGE: "The actor's privilege level was modified",
  ADMIN_ACCESS: "An administrative interface or action was used",
  DATABASE_ACCESS: "A direct database query/console access occurred",
  API_ACCESS: "An API endpoint was called",
  CONFIG_CHANGE: "A system or application configuration was modified",
  SESSION_TIMEOUT: "The session expired after inactivity",
};

/** Events that should only occur from a privileged context. */
export const PRIVILEGED_EVENTS: readonly string[] = [
  "ADMIN_ACCESS",
  "PRIVILEGE_CHANGE",
  "DATABASE_ACCESS",
  "CONFIG_CHANGE",
];

export function isPrivileged(event: string): boolean {
  return PRIVILEGED_EVENTS.includes(event);
}

export function isKnownEvent(event: string): boolean {
  return (ALPHABET as readonly string[]).includes(event);
}
