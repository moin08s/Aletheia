"""Automated Performance SLAs, Scalability, and New Feature Tests for Aletheia.

Tests:
1. Streaming atomic hash throughput.
2. RFC 6962 domain-separated Merkle tree scalability (10k leaves in < 1.5s).
3. AES-256-GCM encrypted container bundling, round-trip extraction, and single-bit tamper rejection.
4. Network C2 & Flow Artifact Plugin (Zeek conn.log & Suricata EVE JSON parsing with threat tagging).
"""

import hashlib
import json
import os
import time
from pathlib import Path
import pytest

from chronotrace.acquire.hasher import Hasher
from chronotrace.integrity.merkle import MerkleTree, compute_root
from chronotrace.core.case import Case
from chronotrace.core.bundle import CaseBundleManager
from chronotrace.artifacts.network import NetworkLogPlugin
from chronotrace.ingest.evidence_view import EvidenceView


def test_benchmark_streaming_hash_throughput(tmp_path: Path):
    """SLA: Streaming atomic copy-and-hash must execute cleanly and report throughput."""
    src = tmp_path / "stream_source.bin"
    dst = tmp_path / "stream_dest.bin"

    # 10 MB payload
    chunk = b"FORENSIC_EVIDENCE_STREAM_BLOCK_12345678" * 256  # 10 KB
    total_chunks = 1000
    with open(src, "wb") as f:
        for _ in range(total_chunks):
            f.write(chunk)

    total_bytes = src.stat().st_size
    hasher = Hasher()

    start_time = time.perf_counter()
    hashes, bytes_copied = hasher.stream_copy_and_hash(src, dst)
    elapsed = time.perf_counter() - start_time

    assert bytes_copied == total_bytes
    throughput_mb_s = (total_bytes / (1024 * 1024)) / elapsed
    assert throughput_mb_s >= 5.0, f"Throughput too low: {throughput_mb_s:.2f} MB/s"
    assert dst.stat().st_size == total_bytes


def test_benchmark_merkle_tree_scale():
    """SLA: RFC 6962 Merkle tree synthesis must process 10,000 leaves in < 1.5s."""
    dummy_leaves_10k = [hashlib.sha256(f"leaf-{i}".encode()).hexdigest() for i in range(10_000)]
    start = time.perf_counter()
    root_10k = compute_root(dummy_leaves_10k)
    elapsed_10k = time.perf_counter() - start

    assert len(root_10k) == 64
    assert elapsed_10k < 1.5, f"10k Merkle tree took too long: {elapsed_10k:.2f}s"

    # Determinism check
    assert compute_root(dummy_leaves_10k) == root_10k


def test_aes_gcm_bundle_encryption_and_tamper_detection(tmp_path: Path):
    """Verify that CaseBundleManager encrypts with AES-256-GCM and detects any bit-flipping."""
    case_dir = tmp_path / "CASE-GCM-TEST"
    case = Case.create(case_id="CASE-GCM-TEST", out_dir=case_dir)

    # Add evidence file
    ev_file = case.evidence_dir / "sample_auth.log"
    ev_file.write_text("Mar 11 02:14:00 server sshd[123]: Accepted password for root from 192.168.1.50\n")

    passphrase = "ForensicVaultSecretKey2026!"
    output_bundle = tmp_path / "CASE-GCM-TEST.wasp.enc"

    # 1. Export encrypted bundle
    bundle_path = CaseBundleManager.export_bundle(
        case_dir=case_dir,
        output_file=output_bundle,
        passphrase=passphrase,
        encrypt=True,
    )
    assert bundle_path.exists()
    assert bundle_path.read_bytes().startswith(b"WASPENC1")

    # 2. Verify encrypted bundle with correct passphrase
    res_valid = CaseBundleManager.verify_bundle(bundle_path, passphrase=passphrase)
    assert res_valid.is_valid is True
    assert res_valid.is_encrypted is True
    assert res_valid.files_checked >= 1

    # 3. Verify encrypted bundle without passphrase fails cleanly
    res_no_pw = CaseBundleManager.verify_bundle(bundle_path, passphrase=None)
    assert res_no_pw.is_valid is False
    assert "passphrase is required" in res_no_pw.errors[0]

    # 4. Extract bundle with passphrase
    extracted_dir = tmp_path / "extracted_case"
    CaseBundleManager.extract_bundle(bundle_path, extracted_dir, passphrase=passphrase)
    assert (extracted_dir / "evidence" / "sample_auth.log").exists()

    # 5. Adversarial Bit-Flipping Test: Alter a byte in the ciphertext
    raw_bytes = bytearray(bundle_path.read_bytes())
    raw_bytes[-10] ^= 0xFF  # Flip bits in ciphertext
    tampered_bundle = tmp_path / "tampered.wasp.enc"
    tampered_bundle.write_bytes(raw_bytes)

    res_tampered = CaseBundleManager.verify_bundle(tampered_bundle, passphrase=passphrase)
    assert res_tampered.is_valid is False
    assert "authentication failed" in res_tampered.errors[0].lower() or "decryption failed" in res_tampered.errors[0].lower()


def test_network_log_parser_zeek_and_suricata(tmp_path: Path):
    """Verify that NetworkLogPlugin parses Zeek and Suricata logs, identifying C2 and burst anomalies."""
    evidence_root = tmp_path / "net_evidence"
    evidence_root.mkdir()

    # 1. Mock Zeek conn.log with suspicious port 4444 and mass exfiltration
    zeek_file = evidence_root / "conn.log"
    zeek_content = (
        "#separator \\x09\n"
        "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration\torig_bytes\tresp_bytes\tconn_state\n"
        "1710122400.000000\tC12345\t192.168.1.100\t49152\t198.51.100.25\t4444\ttcp\t-\t120.5\t15000000\t500\tSF\n"
        "1710122500.000000\tC12346\t192.168.1.100\t49153\t8.8.8.8\t53\tudp\tdns\t0.05\t60\t120\tSF\n"
    )
    zeek_file.write_text(zeek_content, encoding="utf-8")

    # 2. Mock Suricata eve.json
    suricata_file = evidence_root / "eve.json"
    suricata_record = {
        "timestamp": "2024-03-11T02:00:00.000000+0000",
        "event_type": "alert",
        "src_ip": "192.168.1.100",
        "src_port": 50123,
        "dest_ip": "203.0.113.88",
        "dest_port": 1337,
        "proto": "TCP",
        "alert": {"signature": "ET TROJAN Potential Metasploit Payload Connection"},
    }
    suricata_file.write_text(json.dumps(suricata_record) + "\n", encoding="utf-8")

    manifest_evidence = [
        {"evidence_id": "EV-01", "path": "conn.log", "hashes": {"sha256": "dummy1"}},
        {"evidence_id": "EV-02", "path": "eve.json", "hashes": {"sha256": "dummy2"}},
    ]
    view = EvidenceView(evidence_root, manifest_evidence)
    plugin = NetworkLogPlugin()
    events = list(plugin.parse(view))

    assert len(events) >= 3

    # Check Zeek C2 detection and exfiltration burst
    c2_event = next(e for e in events if e.object and e.object.path.endswith(":4444"))
    assert "THREAT:SUSPICIOUS_C2_PORT" in c2_event.tags
    assert "ANOMALY:EXFILTRATION_BURST" in c2_event.tags

    # Check Suricata alert
    suricata_event = next(e for e in events if "THREAT:SURICATA_ALERT" in e.tags)
    assert "THREAT:SUSPICIOUS_C2_PORT" in suricata_event.tags
