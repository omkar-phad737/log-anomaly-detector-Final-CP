"""Log parsing and event extraction (regular expressions).

A regular expression describes a regular language over ASCII; the regex
engine compiles it (regex → NFA → DFA) to match each line. Our own LogDFA
then validates the *sequence* of extracted events.

Supported line shapes (timestamp, user, ip and status are all optional):

  2026-09-30 10:00:01 user=101 ip=10.0.4.12 event=LOGIN
  2026-09-30 10:00:02 user=101 event=AUTH_SUCCESS status=FAILURE
  LOGIN
  2026-09-30 10:00:01 101 LOGIN OK        (bare uppercase token fallback)

Lines starting with '#' and blank lines are skipped. Lines without any
recognisable event produce a warning — malformed input never crashes the
analyser.
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional

from .rules import is_known_event

TIMESTAMP_RE = re.compile(
    r"(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:\s?[+-]\d{2}:?\d{2})?)"
)
USER_RE = re.compile(r"\buser(?:[_-]?id)?=([A-Za-z0-9._@\\-]+)", re.IGNORECASE)
IP_RE = re.compile(r"\b((?:\d{1,3}\.){3}\d{1,3})\b")
STATUS_RE = re.compile(r"\bstatus=([A-Za-z_]+)", re.IGNORECASE)
EVENT_KEY_RE = re.compile(r"\bevent=([A-Za-z_][A-Za-z0-9_]*)")
BARE_TOKEN_RE = re.compile(r"\b([A-Z][A-Z0-9_]{2,})\b")


def parse_log(text: str) -> dict:
    """Parse raw log text into an event sequence plus metadata.

    Returns {"events": [...], "warnings": [...], "total_lines": int,
             "skipped_lines": int}.
    """
    lines = text.splitlines()
    events: List[dict] = []
    warnings: List[dict] = []
    skipped = 0

    for line_no, raw_line in enumerate(lines, start=1):
        raw = raw_line.strip()
        if not raw or raw.startswith("#"):
            if raw:
                skipped += 1
            continue

        match = EVENT_KEY_RE.search(raw)
        event: Optional[str] = match.group(1).upper() if match else None
        if not event:
            bare = BARE_TOKEN_RE.search(raw)
            event = bare.group(1) if bare else None

        if not event:
            warnings.append({
                "line_no": line_no,
                "raw": raw_line,
                "message": "No event symbol found — line skipped.",
            })
            skipped += 1
            continue

        ts = TIMESTAMP_RE.search(raw)
        user = USER_RE.search(raw)
        ip = IP_RE.search(raw)
        status = STATUS_RE.search(raw)

        events.append({
            "position": len(events) + 1,
            "line_no": line_no,
            "raw": raw_line,
            "event": event,
            "timestamp": ts.group(1).replace("T", " ").replace(",", ".") if ts else None,
            "user": user.group(1) if user else None,
            "ip": ip.group(1) if ip else None,
            "status": status.group(1).upper() if status else None,
        })

    # Symbols outside Σ are kept in the sequence; the detector flags them as
    # UNRECOGNIZED_EVENT (they are simply not part of the automaton's language).
    for ev in events:
        if not is_known_event(ev["event"]):
            warnings.append({
                "line_no": ev["line_no"],
                "raw": ev["raw"],
                "message": f"\"{ev['event']}\" is not in the automaton alphabet Σ.",
            })

    return {
        "events": events,
        "warnings": warnings,
        "total_lines": len(lines),
        "skipped_lines": skipped,
    }
