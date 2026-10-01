"""Pydantic schemas for the FastAPI layer."""

from __future__ import annotations

from typing import List, Optional

from pydantic import BaseModel, Field


class FindingOut(BaseModel):
    position: int
    event: str
    previous_state: str
    current_state: str
    status: str
    severity: str
    anomaly_type: Optional[str] = None
    expected_events: List[str] = []
    reason: str
    timestamp: Optional[str] = None
    user: Optional[str] = None
    ip: Optional[str] = None


class WarningOut(BaseModel):
    line_no: int
    raw: str
    message: str


class ParseMetaOut(BaseModel):
    total_lines: int
    skipped_lines: int
    warnings: List[WarningOut] = []


class SummaryOut(BaseModel):
    verdict: str
    total_events: int
    normal_events: int
    anomalies: int
    critical_anomalies: int
    high_anomalies: int
    medium_anomalies: int
    max_severity: str
    detection_ms: float
    final_state: str
    accepted: bool


class AnalysisResponse(BaseModel):
    filename: str
    source: str
    parse: ParseMetaOut
    event_sequence: List[str]
    results: List[FindingOut]
    summary: SummaryOut
    scan_id: Optional[int] = None
    saved: bool = False


class ScanOut(BaseModel):
    id: int
    filename: str
    source: str
    verdict: str
    total_events: int
    normal_events: int
    anomalies: int
    critical_anomalies: int
    max_severity: str
    final_state: str
    accepted: bool
    detection_ms: float
    event_sequence: List[str]
    created_at: str


class FindingRecordOut(BaseModel):
    id: int
    scan_id: int
    position: int
    event: str
    previous_state: str
    current_state: str
    severity: str
    anomaly_type: str
    reason: str
    expected_events: List[str]


class ScanDetailOut(ScanOut):
    findings: List[FindingRecordOut] = []


class HistoryStatsOut(BaseModel):
    scans: int
    total_events: int
    anomalies: int
    critical_anomalies: int


class DeleteResponse(BaseModel):
    deleted: bool
    id: Optional[int] = None


class ClearResponse(BaseModel):
    deleted_scans: int


class ErrorResponse(BaseModel):
    detail: str


class SampleInfo(BaseModel):
    id: str
    name: str
    filename: str
    label: str
    description: str


class TextAnalyzeRequest(BaseModel):
    text: str = Field(min_length=1, max_length=512 * 1024)
    filename: str = Field(default="pasted-log.txt", max_length=80)
