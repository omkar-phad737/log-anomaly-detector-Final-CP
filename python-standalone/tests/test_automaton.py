"""Unit tests for the hand-built LogDFA."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.automaton import (  # noqa: E402
    ACCEPTING_STATES,
    LogDFA,
    START_STATE,
    STATES,
)


def test_dfa_definition_shape():
    assert START_STATE == "q0"
    assert set(ACCEPTING_STATES) == {"q2", "q3"}
    assert len(STATES) == 9  # Q has exactly nine states


def test_valid_login_sequence_is_accepted():
    dfa = LogDFA()
    steps = dfa.run(["LOGIN", "AUTH_SUCCESS", "FILE_ACCESS", "LOGOUT"])
    assert all(s.allowed for s in steps)
    assert dfa.current_state == "q3"
    assert dfa.is_accepting()


def test_valid_file_access_stays_in_q2():
    dfa = LogDFA()
    dfa.run(["LOGIN", "AUTH_SUCCESS", "FILE_ACCESS", "FILE_ACCESS",
             "USER_ACCESS"])
    assert dfa.current_state == "q2"
    assert dfa.is_accepting()


def test_logout_from_q2_is_accepted():
    dfa = LogDFA()
    dfa.run(["LOGIN", "AUTH_SUCCESS", "LOGOUT"])
    assert dfa.current_state == "q3" and dfa.is_accepting()


def test_file_access_after_logout_is_invalid():
    dfa = LogDFA()
    dfa.run(["LOGIN", "AUTH_SUCCESS", "LOGOUT", "FILE_ACCESS"])
    assert dfa.current_state == "q3"  # machine stays put on invalid input


def test_failure_ladder_climbs_to_q1f3():
    dfa = LogDFA()
    steps = dfa.run(["LOGIN", "AUTH_FAILURE", "AUTH_FAILURE", "AUTH_FAILURE"])
    assert [s.to_state for s in steps] == ["q1", "q1f1", "q1f2", "q1f3"]
    assert not dfa.is_accepting()


def test_recovery_after_failures_is_possible():
    dfa = LogDFA()
    dfa.run(["LOGIN", "AUTH_FAILURE", "AUTH_FAILURE", "AUTH_SUCCESS",
             "LOGOUT"])
    assert dfa.current_state == "q3" and dfa.is_accepting()


def test_privilege_escalation_chain():
    dfa = LogDFA()
    steps = dfa.run(["LOGIN", "AUTH_SUCCESS", "PRIVILEGE_CHANGE",
                     "ADMIN_ACCESS"])
    assert all(s.allowed for s in steps)
    assert dfa.current_state == "q5"


def test_admin_access_without_privilege_change_is_invalid():
    dfa = LogDFA()
    steps = dfa.run(["LOGIN", "AUTH_SUCCESS", "ADMIN_ACCESS"])
    assert not steps[-1].allowed
    assert steps[-1].from_state == "q2"
    assert "ADMIN_ACCESS" in steps[-1].expected or \
        "PRIVILEGE_CHANGE" in steps[-1].expected


def test_run_resets_the_machine():
    dfa = LogDFA()
    dfa.run(["LOGIN", "AUTH_SUCCESS", "LOGOUT"])
    dfa.run(["LOGIN", "AUTH_SUCCESS"])
    assert dfa.current_state == "q2"  # started fresh from q0
