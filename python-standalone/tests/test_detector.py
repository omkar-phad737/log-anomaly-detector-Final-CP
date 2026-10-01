"""End-to-end detector tests covering every required anomaly pattern."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.detector import analyze_log_text  # noqa: E402


def _lines(*events):
    return "\n".join(f"2026-09-30 10:00:0{i} user=1 event={e}"
                     for i, e in enumerate(events, start=1)) + "\n"


def _anomalies(result):
    return [r for r in result["results"] if r["status"] == "ANOMALY"]


# ---- 1-3: valid workflows -------------------------------------------------

def test_valid_login_sequence_is_normal():
    result = analyze_log_text(_lines("LOGIN", "AUTH_SUCCESS", "FILE_ACCESS",
                                     "LOGOUT"), "t.log")
    assert result["summary"]["verdict"] == "NORMAL"
    assert result["summary"]["anomalies"] == 0
    assert result["summary"]["accepted"] is True


def test_valid_file_access_is_normal():
    result = analyze_log_text(_lines("LOGIN", "AUTH_SUCCESS", "FILE_ACCESS",
                                     "FILE_ACCESS", "USER_ACCESS", "LOGOUT"),
                              "t.log")
    assert result["summary"]["anomalies"] == 0


def test_logout_only_after_session_is_normal():
    result = analyze_log_text(_lines("LOGIN", "AUTH_SUCCESS", "API_ACCESS",
                                     "LOGOUT"), "t.log")
    assert result["summary"]["verdict"] == "NORMAL"


# ---- 4: invalid workflow --------------------------------------------------

def test_invalid_file_access_after_logout():
    result = analyze_log_text(_lines("LOGIN", "AUTH_SUCCESS", "LOGOUT",
                                     "FILE_ACCESS"), "t.log")
    anomalies = _anomalies(result)
    assert anomalies, "expected an anomaly"
    assert anomalies[0]["anomaly_type"] == "INVALID_WORKFLOW"
    assert anomalies[0]["severity"] in ("MEDIUM", "HIGH")
    assert anomalies[0]["previous_state"] == "q3"
    assert "LOGIN" in anomalies[0]["expected_events"]
    # explanation must mention the ended session
    assert "session" in anomalies[0]["reason"].lower()


# ---- 5: repeated auth failures --------------------------------------------

def test_repeated_auth_failures_detected_as_brute_force():
    result = analyze_log_text(_lines("LOGIN", "AUTH_FAILURE", "AUTH_FAILURE",
                                     "AUTH_FAILURE", "AUTH_FAILURE"), "t.log")
    types = [a["anomaly_type"] for a in _anomalies(result)]
    assert "BRUTE_FORCE" in types
    bf = next(a for a in _anomalies(result)
              if a["anomaly_type"] == "BRUTE_FORCE")
    assert bf["severity"] == "HIGH"
    assert "3 consecutive" in bf["reason"] or "threshold" in bf["reason"]


# ---- 6: privilege escalation ----------------------------------------------

def test_privilege_escalation_critical():
    result = analyze_log_text(_lines("LOGIN", "AUTH_SUCCESS", "USER_ACCESS",
                                     "PRIVILEGE_CHANGE", "ADMIN_ACCESS"),
                              "t.log")
    escalations = [a for a in _anomalies(result)
                   if a["anomaly_type"] == "PRIVILEGE_ESCALATION"]
    assert escalations and escalations[0]["severity"] == "CRITICAL"
    assert result["summary"]["critical_anomalies"] >= 1


# ---- 7: suspicious database access -----------------------------------------

def test_suspicious_database_access_high():
    result = analyze_log_text(_lines("LOGIN", "AUTH_SUCCESS", "ADMIN_ACCESS",
                                     "DATABASE_ACCESS"), "t.log")
    types = [a["anomaly_type"] for a in _anomalies(result)]
    assert "SUSPICIOUS_DATABASE_ACCESS" in types
    db = next(a for a in _anomalies(result)
              if a["anomaly_type"] == "SUSPICIOUS_DATABASE_ACCESS")
    assert db["severity"] == "HIGH"
    assert "PRIVILEGE_CHANGE" in db["reason"]


# ---- 8: unexpected ADMIN_ACCESS pre-auth -----------------------------------

def test_unexpected_admin_access_is_critical():
    result = analyze_log_text(_lines("LOGIN", "AUTH_FAILURE", "AUTH_FAILURE",
                                     "AUTH_FAILURE", "ADMIN_ACCESS"), "t.log")
    assert result["summary"]["verdict"] == "CRITICAL"
    admin = next(a for a in _anomalies(result)
                 if a["event"] == "ADMIN_ACCESS")
    assert admin["severity"] == "CRITICAL"
    assert admin["previous_state"] == "q1f3"
    assert "AUTH_SUCCESS" in admin["expected_events"]
    assert admin["position"] == 5  # 4 events + END_OF_LOG row comes later


# ---- 9: empty log -----------------------------------------------------------

def test_empty_log_is_handled():
    result = analyze_log_text("", "empty.log")
    assert result["summary"]["total_events"] == 0
    assert result["event_sequence"] == []
    # empty input yields an explicit, explained outcome — no crash
    assert result["results"] and result["results"][0]["event"] == "END_OF_LOG"


# ---- 10: malformed log -------------------------------------------------------

def test_malformed_log_is_handled():
    result = analyze_log_text("### only comments\n\n~~~ !!!\n", "bad.log")
    assert result["summary"]["total_events"] == 0
    assert result["parse"]["warnings"], "expected parse warnings"
    row = result["results"][0]
    assert row["status"] == "ANOMALY"  # nothing processable → flagged


# ---- result contract ----------------------------------------------------------

def test_result_contract_fields():
    result = analyze_log_text(_lines("LOGIN", "AUTH_SUCCESS", "LOGOUT"),
                              "t.log")
    row = result["results"][0]
    for key in ("position", "event", "previous_state", "current_state",
                "status", "severity", "reason", "expected_events"):
        assert key in row
    summary = result["summary"]
    for key in ("verdict", "total_events", "normal_events", "anomalies",
                "critical_anomalies", "detection_ms", "final_state",
                "accepted"):
        assert key in summary


def test_normal_row_shape_matches_spec_example():
    result = analyze_log_text(_lines("LOGIN", "AUTH_SUCCESS", "FILE_ACCESS"),
                              "t.log")
    row = result["results"][2]  # FILE_ACCESS
    assert row["status"] == "NORMAL"
    assert row["previous_state"] == "q2"
    assert row["current_state"] == "q2"
