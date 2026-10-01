/**
 * Log parsing and event extraction (regular expressions).
 *
 * A regular expression is compiled (conceptually) to an NFA and then to a DFA
 * by the regex engine; here the DFA of interest is our own LogDFA, which
 * validates the *sequence* of events that the regexes extract.
 *
 * Supported line shapes (timestamp, user, ip and status are all optional):
 *
 *   2026-09-30 10:00:01 user=101 ip=10.0.4.12 event=LOGIN
 *   2026-09-30 10:00:02 user=101 event=AUTH_SUCCESS status=FAILURE
 *   LOGIN
 *   2026-09-30 10:00:01 101 LOGIN OK        (bare uppercase token fallback)
 *
 * Lines starting with '#' and blank lines are skipped. Lines that contain no
 * recognisable event produce a warning — malformed input never crashes the
 * analyser.
 */

import { isKnownEvent } from "./alphabet";
import type { ParseResult, ParseWarning, ParsedEvent } from "./types";

const TIMESTAMP_RE =
  /(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:\s?[+-]\d{2}:?\d{2})?)/;
const USER_RE = /\buser(?:[_-]?id)?=([A-Za-z0-9._@\\-]+)/i;
const IP_RE = /\b((?:\d{1,3}\.){3}\d{1,3})\b/;
const STATUS_RE = /\bstatus=([A-Za-z_]+)/i;
const EVENT_KEY_RE = /\bevent=([A-Za-z_][A-Za-z0-9_]*)/;
const BARE_TOKEN_RE = /\b([A-Z][A-Z0-9_]{2,})\b/;

export function parseLog(text: string): ParseResult {
  const lines = text.split(/\r?\n/);
  const events: ParsedEvent[] = [];
  const warnings: ParseWarning[] = [];
  let skippedLines = 0;

  lines.forEach((rawLine, idx) => {
    const lineNo = idx + 1;
    const raw = rawLine.trim();
    if (!raw || raw.startsWith("#")) {
      if (raw) skippedLines += 1;
      return;
    }

    // 1) Explicit event=<SYMBOL> key, 2) bare uppercase token fallback.
    const keyMatch = raw.match(EVENT_KEY_RE);
    let event = keyMatch ? keyMatch[1].toUpperCase() : undefined;
    if (!event) {
      const bare = raw.match(BARE_TOKEN_RE);
      if (bare) event = bare[1];
    }

    if (!event) {
      warnings.push({
        lineNo,
        raw: rawLine,
        message: "No event symbol found — line skipped.",
      });
      skippedLines += 1;
      return;
    }

    const ts = raw.match(TIMESTAMP_RE);
    const user = raw.match(USER_RE);
    const ip = raw.match(IP_RE);
    const status = raw.match(STATUS_RE);

    events.push({
      position: events.length + 1,
      lineNo,
      raw: rawLine,
      event,
      timestamp: ts?.[1]?.replace("T", " ")?.replace(",", "."),
      user: user?.[1],
      ip: ip?.[1],
      status: status?.[1]?.toUpperCase(),
    });
  });

  // Symbols outside Σ are kept in the sequence; the detector flags them as
  // UNRECOGNIZED_EVENT (they are simply not part of the automaton's language).
  const unknown = events.filter((e) => !isKnownEvent(e.event));
  for (const e of unknown) {
    warnings.push({
      lineNo: e.lineNo,
      raw: e.raw,
      message: `"${e.event}" is not in the automaton alphabet Σ.`,
    });
  }

  return { events, warnings, totalLines: lines.length, skippedLines };
}
