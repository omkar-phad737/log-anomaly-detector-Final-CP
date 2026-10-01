"""Event alphabet, privileged-event classification and policy constants.

The alphabet is deliberately centralised: adding a new event means adding it
here plus its transitions in automaton.DELTA — nothing else changes.
"""

from typing import Dict, List

# --------------------------------------------------------------------------
# Σ — the event alphabet
# --------------------------------------------------------------------------

ALPHABET: List[str] = [
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
]

EVENT_DESCRIPTIONS: Dict[str, str] = {
    "LOGIN": "A login attempt has started",
    "LOGOUT": "The session was explicitly terminated",
    "AUTH_SUCCESS": "Credentials were verified successfully",
    "AUTH_FAILURE": "Credential verification failed",
    "FILE_ACCESS": "A file was read or opened",
    "FILE_DELETE": "A file was deleted",
    "PASSWORD_CHANGE": "A password was changed",
    "USER_ACCESS": "A user resource was accessed",
    "PRIVILEGE_CHANGE": "The actor's privilege level was modified",
    "ADMIN_ACCESS": "An administrative interface or action was used",
    "DATABASE_ACCESS": "A direct database query/console access occurred",
    "API_ACCESS": "An API endpoint was called",
    "CONFIG_CHANGE": "A system or application configuration was modified",
    "SESSION_TIMEOUT": "The session expired after inactivity",
}

# Events that should only occur from a privileged context.
PRIVILEGED_EVENTS = ("ADMIN_ACCESS", "PRIVILEGE_CHANGE", "DATABASE_ACCESS",
                     "CONFIG_CHANGE")

# States that exist before the actor has authenticated successfully.
PRE_AUTH_STATES = ("q0", "q1", "q1f1", "q1f2", "q1f3")


def is_privileged(event: str) -> bool:
    return event in PRIVILEGED_EVENTS


def is_known_event(event: str) -> bool:
    return event in ALPHABET


SEVERITY_ORDER = {"NONE": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
