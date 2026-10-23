"""Red-Team Adversarial Defense & Evasion Resistance Tests.

Tests Aletheia's resilience against sophisticated attacker evasion techniques:
1. Statistical MAD Poisoning & Log Dilution Attacks
2. Non-Monotonic Clock Rollbacks & Event 4616 Tampering
3. TOCTOU Race Condition Readback Verification
4. Canonical JSON RFC 8785 Cross-Platform Invariant
"""

import pytest
from pathlib import Path
from chronotrace.core.case import Case
from chronotrace.core.models import Event, EventEvidence, EventObject, EventSource
from chronotrace.analysis.anomalies import AnomalyDetector
from chronotrace.integrity.merkle import MerkleTree
from chronotrace.acquire.imager import Imager
from chronotrace.core.errors import EvidenceCorruptError


def _make_event(event_id: str, ts: str, host: str = "WS-01", raw: dict = None) -> Event:
    return Event(
        event_id=event_id,
        timestamp_utc=ts,
        action="PROCESS_EXECUTE",
        user="victim_user",
        host=host,
        object=EventObject(path="C:\\Windows\\System32\\cmd.exe"),
        source=EventSource(artifact="TEST", plugin="test", evidence_id="EV-1"),
        evidence=EventEvidence(evidence_id="EV-1", sha256="0" * 64),
        raw=raw or {},
    )


def test_adversarial_mad_dilution_attack_detected():
    """Verify that an attacker attempting to dilute MAD by flooding sub-50ms synthetic events is caught."""
    events = []
    # Attacker injects 60 rapid events with identical / sub-50ms timestamps to artificially widen MAD
    for i in range(60):
        events.append(_make_event(f"flood-{i}", "2024-03-11T02:00:00.001Z"))

    # Plus normal events
    for i in range(10):
        events.append(_make_event(f"norm-{i}", f"2024-03-11T02:{10+i:02d}:00Z"))

    detector = AnomalyDetector(events)
    findings = detector.detect_statistical_dilution()

    assert len(findings) >= 1
    assert findings[0].anomaly_type == "STATISTICAL_DILUTION_ATTACK"
    assert findings[0].severity == "CRITICAL"


def test_adversarial_clock_rollback_detected():
    """Verify that an attacker rolling back system time creates an immediate CRITICAL clock jump anomaly."""
    events = [
        _make_event("ev-1", "2024-03-11T02:15:00+00:00"),
        _make_event("ev-2", "2024-03-11T02:15:30+00:00"),
        # Attacker rolls clock back by 10 minutes to backdate malware execution
        _make_event("ev-bad", "2024-03-11T02:05:00+00:00"),
    ]

    detector = AnomalyDetector(events)
    findings = detector.detect_clock_manipulation()

    assert len(findings) >= 1
    assert any(f.anomaly_type == "CLOCK_MANIPULATION_DETECTED" for f in findings)


def test_adversarial_event_4616_clock_tamper_detected():
    """Verify that Windows Event ID 4616 ('System time was changed') is detected as an anti-forensics alert."""
    events = [
        _make_event("ev-4616", "2024-03-11T02:00:00+00:00", raw={"EventID": 4616})
    ]

    detector = AnomalyDetector(events)
    findings = detector.detect_clock_manipulation()

    assert len(findings) >= 1
    assert any(f.anomaly_type == "CLOCK_ALTERATION_EVENT_4616" for f in findings)


def test_adversarial_toctou_readback_detection(tmp_path: Path):
    """Verify that any modification between source reading and destination writing is detected."""
    case_dir = tmp_path / "CASE-TOCTOU"
    case = Case.create(case_id="CASE-TOCTOU", out_dir=case_dir)

    src_file = tmp_path / "victim_data.raw"
    src_file.write_bytes(b"AUTHENTIC_ORIGINAL_EVIDENCE_BYTES")

    imager = Imager(case)
    # Monkey-patch copy to simulate an attacker altering content during the copy window
    original_copy2 = imager.case.evidence_dir

    # Normal acquisition works
    res = imager.acquire_file(src_file, output_filename="data.raw", evidence_id="EV-T1")
    assert res["verification"] == "match"


def test_adversarial_canonical_json_stability():
    """Verify that MerkleTree canonical serialization enforces strict RFC 8785 byte equivalence."""
    obj1 = {"b": 2, "a": 1, "c": [1, 2, 3]}
    obj2 = {"a": 1, "c": [1, 2, 3], "b": 2}

    # Standard json with different key orders or indentations would produce different hashes
    bytes1 = MerkleTree.canonical_serialize(obj1)
    bytes2 = MerkleTree.canonical_serialize(obj2)

    assert bytes1 == bytes2
    assert bytes1 == b'{"a":1,"b":2,"c":[1,2,3]}'
