"""High-level tests for WASP Web3, EAS schemas, and FastAPI Web3 endpoints."""

from pathlib import Path
import json
from fastapi.testclient import TestClient

from chronotrace.web3.eas import EASAttestationBuilder, FORENSIC_EAS_SCHEMA_UID
from api.main import app

client = TestClient(app)


def test_eas_attestation_builder():
    builder = EASAttestationBuilder()
    attestation = builder.build_offchain_attestation(
        case_id="CASE-2026-LIVE",
        merkle_root="33" * 32,
        evidence_sha256="44" * 32,
        ipfs_cid="bafybeibtestcid123",
        event_count=1200,
        examiner="Special Agent Fox",
    )
    assert attestation.schema_uid == FORENSIC_EAS_SCHEMA_UID
    assert attestation.uid.startswith("0x")
    assert len(attestation.uid) == 66
    assert attestation.data["caseId"] == "CASE-2026-LIVE"
    assert attestation.data["examiner"] == "Special Agent Fox"
    assert attestation.expiration_time > attestation.time


def test_api_web3_endpoints_unanchored():
    # If case has not been anchored yet
    resp = client.get("/api/v1/cases/NONEXISTENT-CASE/web3/attestation")
    assert resp.status_code == 200
    assert resp.json()["anchored"] is False


def test_api_web3_anchor_and_verify_e2e():
    # Test against CASE-2026-LIVE in run_artifacts
    resp = client.post("/api/v1/cases/CASE-2026-LIVE/web3/anchor", json={
        "network": "Base Sepolia (L2)",
        "examiner": "Lead Forensic Examiner"
    })
    if resp.status_code != 200:
        print("ERROR BODY:", resp.json())
    assert resp.status_code == 200
    data = resp.json()
    assert data["anchored"] is True
    assert data["case_id"] == "CASE-2026-LIVE"
    assert data["attestation"]["transaction_hash"].startswith("0x")
    assert data["ipfs"]["cid"].startswith("bafybeib")
    assert data["eas"]["uid"].startswith("0x")

    # Now verify tamper check
    verify_resp = client.post("/api/v1/cases/CASE-2026-LIVE/web3/verify")
    assert verify_resp.status_code == 200
    vdata = verify_resp.json()
    assert vdata["is_valid"] is True
    assert vdata["tamper_detected"] is False
    assert vdata["merkle_root_match"] is True
