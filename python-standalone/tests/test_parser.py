"""Unit tests for the regex log parser."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.log_parser import parse_log  # noqa: E402


def test_valid_login_sequence_extraction():
    text = (
        "2026-09-30 10:00:01 user=101 ip=10.0.4.12 event=LOGIN\n"
        "2026-09-30 10:00:02 user=101 event=AUTH_SUCCESS status=SUCCESS\n"
        "2026-09-30 10:02:10 user=101 event=FILE_ACCESS\n"
        "2026-09-30 10:05:20 user=101 event=LOGOUT\n"
    )
    parsed = parse_log(text)
    assert [e["event"] for e in parsed["events"]] == [
        "LOGIN", "AUTH_SUCCESS", "FILE_ACCESS", "LOGOUT",
    ]
    assert parsed["total_lines"] == 4
    assert parsed["skipped_lines"] == 0
    first = parsed["events"][0]
    assert first["timestamp"].startswith("2026-09-30 10:00:01")
    assert first["user"] == "101"
    assert first["ip"] == "10.0.4.12"


def test_bare_token_line():
    parsed = parse_log("LOGIN\nAUTH_SUCCESS\nLOGOUT\n")
    assert [e["event"] for e in parsed["events"]] == ["LOGIN", "AUTH_SUCCESS",
                                                      "LOGOUT"]


def test_comments_and_blank_lines_are_skipped():
    parsed = parse_log("# a comment\n\n   \nLOGIN\n")
    assert [e["event"] for e in parsed["events"]] == ["LOGIN"]
    assert parsed["skipped_lines"] == 1  # the comment line


def test_malformed_line_produces_warning_not_crash():
    parsed = parse_log("this line has no event token at all\nLOGIN\n")
    assert len(parsed["warnings"]) == 1
    assert parsed["warnings"][0]["line_no"] == 1
    assert [e["event"] for e in parsed["events"]] == ["LOGIN"]


def test_empty_log():
    parsed = parse_log("")
    assert parsed["events"] == []
    assert parsed["total_lines"] == 0  # ''.splitlines() == []


def test_unknown_symbol_is_kept_and_warned():
    parsed = parse_log("event=TOTALLY_NEW_EVENT\n")
    assert [e["event"] for e in parsed["events"]] == ["TOTALLY_NEW_EVENT"]
    assert any("alphabet" in w["message"] for w in parsed["warnings"])
