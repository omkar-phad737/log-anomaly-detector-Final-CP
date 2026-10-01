"""Domain models and shared constants.

The persistence shapes live in database.py (SQLite tables `scans` and
`findings`); the API shapes live in schemas.py (Pydantic). This module holds
the small plain-Python records used in between, plus upload validation rules.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Optional

# --------------------------------------------------------------------------
# Upload security (see README "Security" section)
# --------------------------------------------------------------------------

MAX_UPLOAD_BYTES = 512 * 1024          # 512 KB
ALLOWED_EXTENSIONS = {".txt", ".log", ".out"}

_FILENAME_SAFE_RE = re.compile(r"[^A-Za-z0-9._-]")


def sanitize_filename(name: str) -> str:
    """Reduce an uploaded filename to a safe basename.

    - strips any directory components (Windows '\\' and POSIX '/'),
    - keeps only letters, digits, dot, underscore and hyphen,
    - caps the length at 80 characters,
    - guarantees a non-empty result.
    """
    base = re.split(r"[\\/]", name.strip())[-1] if name.strip() else ""
    base = _FILENAME_SAFE_RE.sub("_", base)[:80] or "log.txt"
    return base


def validate_upload(filename: str, size: int) -> Optional[str]:
    """Return an error message when the upload must be rejected, else None."""
    import os
    ext = os.path.splitext(filename)[1].lower()
    if ext not in ALLOWED_EXTENSIONS:
        return f"Only {', '.join(sorted(ALLOWED_EXTENSIONS))} files are accepted."
    if size <= 0:
        return "The uploaded file is empty."
    if size > MAX_UPLOAD_BYTES:
        return f"File too large ({size} bytes); the limit is {MAX_UPLOAD_BYTES} bytes."
    return None


# --------------------------------------------------------------------------
# Small records shared between layers
# --------------------------------------------------------------------------

@dataclass
class ParsedEvent:
    position: int
    line_no: int
    raw: str
    event: str
    timestamp: Optional[str] = None
    user: Optional[str] = None
    ip: Optional[str] = None
    status: Optional[str] = None


@dataclass
class Finding:
    """One anomaly finding (persisted as a row of the `findings` table)."""
    position: int
    event: str
    previous_state: str
    current_state: str
    severity: str
    anomaly_type: str
    reason: str
    expected_events: List[str] = field(default_factory=list)
    scan_id: Optional[int] = None


@dataclass
class ScanMeta:
    """Summary of one analysis (persisted as a row of the `scans` table)."""
    filename: str
    verdict: str
    total_events: int
    normal_events: int
    anomalies: int
    critical_anomalies: int
    max_severity: str
    final_state: str
    accepted: bool
    detection_ms: float
    source: str = "upload"
    event_sequence: List[str] = field(default_factory=list)
    id: Optional[int] = None
