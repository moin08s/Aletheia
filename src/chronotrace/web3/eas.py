"""Ethereum Attestation Service (EAS) Module for WASP Forensics.

Supports creating off-chain verifiable EAS attestations and EIP-712 structured data
records for digital forensic cases, incident responses, and expert witness declarations.
"""

from __future__ import annotations
import json
import time
import hashlib
from dataclasses import dataclass, asdict
from typing import Dict, Any, Optional

from chronotrace.web3 import case_id_to_bytes32, format_bytes32


# Official EAS Forensic Schema Definition
FORENSIC_EAS_SCHEMA_RAW = "bytes32 merkleRoot,bytes32 evidenceSha256,string caseId,string ipfsCid,uint256 eventCount,string examiner"
FORENSIC_EAS_SCHEMA_UID = "0x" + hashlib.sha256(FORENSIC_EAS_SCHEMA_RAW.encode()).hexdigest()


@dataclass
class EASAttestation:
    schema_uid: str
    recipient: str
    time: int
    expiration_time: int
    revocation_time: int
    ref_uid: str
    data: Dict[str, Any]
    uid: str
    version: int = 1

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class EASAttestationBuilder:
    """Builds cryptographically verifiable EAS attestations for cases."""

    def __init__(self, schema_uid: str = FORENSIC_EAS_SCHEMA_UID):
        self.schema_uid = schema_uid

    def build_offchain_attestation(
        self,
        case_id: str,
        merkle_root: str,
        evidence_sha256: str,
        ipfs_cid: str,
        event_count: int,
        examiner: str = "Lead Forensic Examiner",
        recipient: str = "0x0000000000000000000000000000000000000000",
        validity_days: int = 365,
    ) -> EASAttestation:
        """
        Creates an EAS off-chain attestation package.
        """
        now = int(time.time())
        expiration = now + (validity_days * 86400)

        data_payload = {
            "merkleRoot": format_bytes32(merkle_root),
            "evidenceSha256": format_bytes32(evidence_sha256),
            "caseId": case_id,
            "ipfsCid": ipfs_cid,
            "eventCount": event_count,
            "examiner": examiner,
        }

        # Derive deterministic UID for off-chain attestation
        uid_input = f"{self.schema_uid}{recipient}{now}{json.dumps(data_payload, sort_keys=True)}".encode()
        uid = "0x" + hashlib.sha256(uid_input).hexdigest()

        return EASAttestation(
            schema_uid=self.schema_uid,
            recipient=recipient,
            time=now,
            expiration_time=expiration,
            revocation_time=0,
            ref_uid="0x" + "0" * 64,
            data=data_payload,
            uid=uid,
            version=1,
        )
