"""FastAPI application — Automatic Log Anomaly Detector using Finite Automata.

Run with (Git Bash, Windows):

    uvicorn backend.main:app --reload

then open http://127.0.0.1:8000
"""

from __future__ import annotations

import shutil
import time
from pathlib import Path
from typing import List, Optional

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from . import database
from .detector import analyze_log_text
from .automaton import automaton_definition
from .log_parser import parse_log
from .models import sanitize_filename, validate_upload
from .schemas import (
    AnalysisResponse,
    ClearResponse,
    DeleteResponse,
    FindingOut,
    HistoryStatsOut,
    ParseMetaOut,
    ScanDetailOut,
    ScanOut,
    SummaryOut,
    TextAnalyzeRequest,
    WarningOut,
)

BASE_DIR = Path(__file__).resolve().parent.parent
FRONTEND_DIR = BASE_DIR / "frontend"
DATA_DIR = BASE_DIR / "data"
UPLOAD_DIR = BASE_DIR / "uploads"
SAMPLE_DIRS = {"normal": DATA_DIR / "normal_logs",
               "anomalous": DATA_DIR / "anomalous_logs"}

app = FastAPI(
    title="Automatic Log Anomaly Detector using Finite Automata",
    description=(
        "Detects anomalous behavioral sequences in system logs using a "
        "hand-built deterministic finite automaton M = (Q, Σ, δ, q0, F). "
        "Academic prototype for Formal Language Theory / Theory of Computation."
    ),
    version="1.0.0",
)

database.init_db()
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)


# --------------------------------------------------------------------------
# Sample registry (files under data/normal_logs and data/anomalous_logs)
# --------------------------------------------------------------------------

SAMPLES = {
    "normal_login": ("normal", "normal_login.txt", "Load Normal Log",
                     "Login → auth success → file access → logout"),
    "normal_file_access": ("normal", "normal_file_access.txt",
                           "Load Normal File Activity",
                           "Everyday file/API activity, clean logout"),
    "brute_force": ("anomalous", "brute_force.txt", "Load Brute Force",
                    "3× auth failure, then ADMIN_ACCESS"),
    "privilege_escalation": ("anomalous", "privilege_escalation.txt",
                             "Load Privilege Escalation",
                             "PRIVILEGE_CHANGE → ADMIN_ACCESS chain"),
    "database_attack": ("anomalous", "suspicious_database_access.txt",
                        "Load Database Attack",
                        "Admin + DB access without privilege change"),
    "invalid_workflow": ("anomalous", "invalid_workflow.txt",
                         "Load Invalid Workflow",
                         "File access after LOGOUT"),
}


def _sample_path(sample_name: str) -> Path:
    if sample_name not in SAMPLES:
        raise HTTPException(status_code=404,
                            detail=f"Unknown sample '{sample_name}'. Available: "
                                   f"{', '.join(sorted(SAMPLES))}")
    kind, fname, _, _ = SAMPLES[sample_name]
    return SAMPLE_DIRS[kind] / fname


# --------------------------------------------------------------------------
# Routes
# --------------------------------------------------------------------------

@app.get("/api/health")
def health() -> dict:
    return {"status": "ok", "service": "log-anomaly-detector",
            "version": app.version, "database": "sqlite"}


@app.get("/api/automaton")
def get_automaton() -> dict:
    """Machine-readable description of M = (Q, Σ, δ, q0, F)."""
    return automaton_definition()


@app.get("/api/samples", response_model=List[dict])
def list_samples() -> List[dict]:
    return [
        {"id": sid, "name": name, "filename": fname, "label": kind,
         "description": desc}
        for sid, (kind, fname, name, desc) in SAMPLES.items()
    ]


@app.get("/api/sample/{sample_name}")
def get_sample(sample_name: str) -> dict:
    """Return the raw text of a built-in sample log."""
    path = _sample_path(sample_name)
    if not path.exists():
        raise HTTPException(status_code=404,
                            detail=f"Sample file missing: {path.name}")
    return {"id": sample_name, "filename": path.name,
            "content": path.read_text(encoding="utf-8")}


@app.post("/api/analyze", response_model=AnalysisResponse)
async def analyze(file: UploadFile = File(...)) -> AnalysisResponse:
    """Upload a log file, run the DFA and return the full analysis."""
    raw_name = file.filename or "log.txt"
    filename = sanitize_filename(raw_name)

    error = validate_upload(filename, 1)
    if error:
        raise HTTPException(status_code=400, detail=error)

    content_bytes = await file.read()
    error = validate_upload(filename, len(content_bytes))
    if error:
        raise HTTPException(status_code=400, detail=error)

    try:
        text = content_bytes.decode("utf-8")
    except UnicodeDecodeError:
        text = content_bytes.decode("latin-1", errors="replace")

    result = analyze_log_text(text, filename, source="upload")

    # Keep a copy of the upload for reference (never executed).
    try:
        (UPLOAD_DIR / filename).write_text(text, encoding="utf-8")
    except OSError:
        pass  # history saving must not fail the analysis

    scan_id: Optional[int] = None
    try:
        scan_id = database.save_scan(result)
    except Exception:  # noqa: BLE001 — persistence is best-effort
        pass

    return _to_analysis_response(result, scan_id, saved=scan_id is not None)


@app.post("/api/analyze-text", response_model=AnalysisResponse)
def analyze_text(payload: TextAnalyzeRequest) -> AnalysisResponse:
    """Analyze pasted log text (used by the dashboard's Paste tab)."""
    filename = sanitize_filename(payload.filename or "pasted-log.txt")
    result = analyze_log_text(payload.text, filename, source="paste")
    scan_id: Optional[int] = None
    try:
        scan_id = database.save_scan(result)
    except Exception:  # noqa: BLE001
        pass
    return _to_analysis_response(result, scan_id, saved=scan_id is not None)


def _to_analysis_response(result: dict, scan_id: Optional[int],
                          saved: bool) -> AnalysisResponse:
    parse_meta = result["parse"]
    return AnalysisResponse(
        filename=result["filename"],
        source=result["source"],
        parse=ParseMetaOut(
            total_lines=parse_meta["total_lines"],
            skipped_lines=parse_meta["skipped_lines"],
            warnings=[WarningOut(**w) for w in parse_meta["warnings"]],
        ),
        event_sequence=result["event_sequence"],
        results=[FindingOut(**r) for r in result["results"]],
        summary=SummaryOut(**result["summary"]),
        scan_id=scan_id,
        saved=saved,
    )


@app.get("/api/history", response_model=List[ScanOut])
def get_history(limit: int = 50) -> List[ScanOut]:
    return [ScanOut(**s) for s in database.list_scans(limit=limit)]


@app.get("/api/history/stats", response_model=HistoryStatsOut)
def get_history_stats() -> HistoryStatsOut:
    return HistoryStatsOut(**database.history_stats())


@app.get("/api/history/{scan_id}", response_model=ScanDetailOut)
def get_history_scan(scan_id: int) -> ScanDetailOut:
    scan = database.get_scan(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")
    return ScanDetailOut(**scan)


@app.delete("/api/history/{scan_id}", response_model=DeleteResponse)
def delete_history_scan(scan_id: int) -> DeleteResponse:
    return DeleteResponse(deleted=database.delete_scan(scan_id), id=scan_id)


@app.delete("/api/history", response_model=ClearResponse)
def clear_history() -> ClearResponse:
    return ClearResponse(deleted_scans=database.clear_history())


@app.get("/api/evaluation")
def get_evaluation() -> dict:
    """Run the detector over the labelled samples and compute metrics."""
    from .evaluation import run_evaluation
    return run_evaluation()


@app.get("/api/behavioral/analyze")
def behavioral_analyze(sample_name: str) -> dict:
    """Train the behavioural (bigram) model on the normal samples and analyse
    one sample with it. Kept strictly separate from the manual DFA."""
    from .behavioral import build_model, analyze_with_model

    normal_texts = []
    for sid, (kind, fname, _, _) in SAMPLES.items():
        if kind == "normal":
            p = SAMPLE_DIRS[kind] / fname
            if p.exists():
                normal_texts.append(parse_log(
                    p.read_text(encoding="utf-8"))["events"])
    model = build_model(normal_texts)

    path = _sample_path(sample_name)
    if not path.exists():
        raise HTTPException(status_code=404,
                            detail=f"Sample file missing: {path.name}")
    events = parse_log(path.read_text(encoding="utf-8"))["events"]
    findings = analyze_with_model(model, events)
    return {
        "model": {"sequences": model["sequences"],
                  "learned_transitions": model["learned"]},
        "findings": findings,
    }


# --------------------------------------------------------------------------
# Frontend (served last so /api/* takes precedence)
# --------------------------------------------------------------------------

@app.get("/", include_in_schema=False)
def index() -> FileResponse:
    return FileResponse(FRONTEND_DIR / "index.html")


app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")
