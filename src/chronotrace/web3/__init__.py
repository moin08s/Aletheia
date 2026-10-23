"""WASP Web3 Integration Module.

Provides Ethereum / EVM anchoring, decentralized storage (IPFS/Filecoin/Arweave),
and on-chain Chain-of-Custody attestation for digital forensic cases.
"""

from __future__ import annotations
import json
import hashlib
from dataclasses import dataclass, asdict
from typing import Optional, List, Dict, Any


@dataclass
class OnChainAttestation:
    case_id: str
    case_id_bytes32: str
    merkle_root: str
    evidence_sha256: str
    ipfs_cid: str
    network: str
    contract_address: str
    transaction_hash: str
    block_number: int
    investigator_address: str
    timestamp_utc: str
    status: str
    co_signer_address: Optional[str] = None
    dual_signed: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def case_id_to_bytes32(case_id: str) -> str:
    """Computes deterministic bytes32 hex for a case identifier string."""
    digest = hashlib.sha256(case_id.encode("utf-8")).hexdigest()
    return "0x" + digest


def format_bytes32(hex_string: str) -> str:
    """Ensures hex string is 0x-prefixed 64-char bytes32 string."""
    clean = hex_string.lower().replace("0x", "")
    if len(clean) > 64:
        clean = clean[:64]
    elif len(clean) < 64:
        clean = clean.zfill(64)
    return "0x" + clean
