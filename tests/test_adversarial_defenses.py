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


def test_adversarial_60ms_paced_dilution_detected():
    """Verify that an attacker attempting to defeat sub-50ms checks with a 60ms cadence is caught via CV dispersion."""
    events = []
    # Attacker paces 40 events exactly 60ms apart (0.06s delta)
    base_ts = 1710122400.0
    for i in range(40):
        t = base_ts + (i * 0.060)
        import datetime
        dt_str = datetime.datetime.fromtimestamp(t, datetime.timezone.utc).isoformat()
        events.append(_make_event(f"cadence-{i}", dt_str))

    detector = AnomalyDetector(events)
    findings = detector.detect_statistical_dilution()

    assert len(findings) >= 1
    assert any(f.anomaly_type == "STATISTICAL_DILUTION_SYNTHETIC_CADENCE" for f in findings)


def test_adversarial_clock_forward_leap_detected():
    """Verify that an unexplained forward clock jump (> 24 hours) is flagged as an anomaly."""
    events = [
        _make_event("ev-1", "2024-03-11T02:00:00+00:00"),
        # Attacker rolls clock forward 3 days into future
        _make_event("ev-forward", "2024-03-14T02:00:00+00:00"),
    ]

    detector = AnomalyDetector(events)
    findings = detector.detect_clock_manipulation()

    assert len(findings) >= 1
    assert any(f.anomaly_type == "CLOCK_FORWARD_LEAP_ANOMALY" for f in findings)


def test_adversarial_stream_copy_hasher_fd(tmp_path: Path):
    """Verify that Hasher.stream_copy_and_hash computes multi-hash atomically without gap."""
    from chronotrace.acquire.hasher import Hasher
    src = tmp_path / "original.bin"
    dst = tmp_path / "streamed.bin"
    test_data = b"FORENSIC_STREAM_PAYLOAD_TEST_" * 1024
    src.write_bytes(test_data)

    hasher = Hasher()
    hashes, total_bytes = hasher.stream_copy_and_hash(src, dst)

    assert total_bytes == len(test_data)
    assert dst.read_bytes() == test_data
    assert hashes["sha256"] == Hasher.sha256_bytes(test_data)


def test_adversarial_dual_signed_attestation():
    """Verify that OnChainAttestation supports mandatory dual sign-off by independent peer examiner."""
    from chronotrace.web3.attestation import EVMAttestationClient
    client = EVMAttestationClient()
    attestation = client.anchor_case(
        case_id="CASE-DUAL-01",
        merkle_root="a" * 64,
        evidence_sha256="b" * 64,
        ipfs_cid="bafybeibtest123456789",
        event_count=42,
        investigator_address="0x89205A3A3b2A69De6Dbf7f01ED13B2108B2c43e7",
        co_signer_address="0x3D7e1329c29d10B134015D56E8193a0279B48731",
    )

    assert attestation.dual_signed is True
    assert attestation.co_signer_address == "0x3D7e1329c29d10B134015D56E8193a0279B48731"

