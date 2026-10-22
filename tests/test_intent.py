"""Tests for User Intent & Provenance Verification Engine."""

from chronotrace.analysis.intent import UserIntentAnalyzer
from chronotrace.core.models import Event, EventEvidence, EventObject, EventSource


def _make_event(event_id, ts, action, path=""):
    return Event(
        event_id=event_id,
        timestamp_utc=ts,
        timestamp_type="occurred",
        action=action,
        host="SECURE-WORKSTATION",
        user="alice",
        object=EventObject(path=path),
        source=EventSource(artifact="TEST", plugin="test", evidence_id="EV-001"),
        evidence=EventEvidence(evidence_id="EV-001", sha256="0" * 64),
    )


def test_legitimate_user_transfer_detection():
    """Verify that a transfer accompanied by user input and wallet extension UI is marked legitimate."""
    analyzer = UserIntentAnalyzer(time_window_seconds=60)
    tx_time = "2026-10-22T12:00:00+00:00"

    # User activity surrounding the transaction:
    events = [
        _make_event("ev-1", "2026-10-22T11:59:40+00:00", "INTERACTIVE_LOGON"),
        _make_event("ev-2", "2026-10-22T11:59:50+00:00", "UI_INTERACTION", "chrome-extension://nkbihfbeogaeaoehlefnkodbefgpgknn/home.html#send"),
        _make_event("ev-3", "2026-10-22T11:59:58+00:00", "MOUSE_CLICK"),
    ]

    result = analyzer.evaluate_transfer(
        tx_hash="0xabc123legitimate",
        tx_timestamp_utc=tx_time,
        host_events=events,
    )

    assert result.is_authorized_user is True
    assert result.verdict == "LEGITIMATE_USER_TRANSFER"
    assert result.human_provenance_score >= 0.8
    assert len(result.corroborating_signals) >= 2
    assert len(result.risk_factors) == 0


def test_unauthorized_attacker_drain_detection():
    """Verify that an unauthorized drain occurring while machine has no human input or runs headless script is caught."""
    analyzer = UserIntentAnalyzer(time_window_seconds=60)
    tx_time = "2026-10-22T02:14:00+00:00"

    # Midnight scenario: Remote session + headless powershell script
    events = [
        _make_event("ev-bad-1", "2026-10-22T02:13:45+00:00", "NETWORK_LOGON"),
        _make_event("ev-bad-2", "2026-10-22T02:13:50+00:00", "HEADLESS_SCRIPT_EXEC", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"),
    ]

    result = analyzer.evaluate_transfer(
        tx_hash="0xdead456hacker",
        tx_timestamp_utc=tx_time,
        host_events=events,
    )

    assert result.is_authorized_user is False
    assert result.verdict == "UNAUTHORIZED_ATTACKER_DRAIN"
    assert result.human_provenance_score == 0.0
    assert len(result.risk_factors) > 0


def test_zero_host_activity_drain():
    """Verify that a transaction occurring while host has zero events (user asleep, machine off) is caught."""
    analyzer = UserIntentAnalyzer(time_window_seconds=60)
    tx_time = "2026-10-22T03:00:00+00:00"

    result = analyzer.evaluate_transfer(
        tx_hash="0x999attacker_offline",
        tx_timestamp_utc=tx_time,
        host_events=[],
    )

    assert result.is_authorized_user is False
    assert result.verdict == "UNAUTHORIZED_ATTACKER_DRAIN"
    assert result.human_provenance_score == 0.0
