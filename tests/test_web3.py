"""Tests for WASP Web3, EVM attestation, and decentralized storage module."""

from pathlib import Path
import tempfile
from chronotrace.web3 import case_id_to_bytes32, format_bytes32
from chronotrace.web3.ipfs import IPFSClient, generate_simulated_ipfs_cid
from chronotrace.web3.attestation import EVMAttestationClient


def test_bytes32_formatting():
    b32 = case_id_to_bytes32("CASE-2026-LIVE")
    assert b32.startswith("0x")
    assert len(b32) == 66  # "0x" + 64 hex chars

    fmt = format_bytes32("abc")
    assert fmt.startswith("0x")
    assert len(fmt) == 66


def test_ipfs_client_pinning():
    with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as tmp:
        tmp.write(b"SAMPLE FORENSIC EVIDENCE DISK IMAGE CONTENT")
        tmp_path = Path(tmp.name)

    try:
        client = IPFSClient()
        pin_res = client.pin_evidence_bundle(tmp_path)
        assert pin_res["pinned"] is True
        assert pin_res["cid"].startswith("bafybeib")
        assert len(pin_res["sha256"]) == 64
        assert "ipfs.io" in pin_res["gateway_url"]
    finally:
        if tmp_path.exists():
            tmp_path.unlink()


def test_evm_attestation_and_tamper_detection():
    client = EVMAttestationClient(network_name="Base Sepolia (L2)")
    case_id = "CASE-2026-LIVE"
    merkle_root = "11" * 32
    evidence_sha = "22" * 32
    ipfs_cid = "bafybeibmock123"

    attestation = client.anchor_case(
        case_id=case_id,
        merkle_root=merkle_root,
        evidence_sha256=evidence_sha,
        ipfs_cid=ipfs_cid,
        event_count=500,
    )

    assert attestation.case_id == case_id
    assert attestation.status == "CONFIRMED_ON_CHAIN"
    assert attestation.network == "Base Sepolia (L2)"
    assert attestation.transaction_hash.startswith("0x")
    assert attestation.block_number > 0

    # 1. Verification with untampered state -> Passes
    verification = client.verify_on_chain(
        attestation=attestation,
        current_merkle_root=merkle_root,
        current_evidence_sha256=evidence_sha,
    )
    assert verification["is_valid"] is True
    assert verification["tamper_detected"] is False

    # 2. Tamper Test: Modify 1 byte of the local evidence hash -> Fails
    tampered_evidence_sha = ("22" * 31) + "99"
    tampered_verification = client.verify_on_chain(
        attestation=attestation,
        current_merkle_root=merkle_root,
        current_evidence_sha256=tampered_evidence_sha,
    )
    assert tampered_verification["is_valid"] is False
    assert tampered_verification["tamper_detected"] is True
    assert tampered_verification["evidence_sha256_match"] is False
