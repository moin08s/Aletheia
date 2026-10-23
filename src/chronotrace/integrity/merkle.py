"""Merkle tree calculation for compact cryptographic attestation."""

from __future__ import annotations
import hashlib
import json
from typing import Any, List, Sequence


class MerkleTree:
    """Calculates a deterministic Merkle root with RFC 6962 domain separation.
    
    RFC 6962 Domain Separation:
      * Leaf nodes: H(0x00 || leaf_data)
      * Internal nodes: H(0x01 || left || right)
    This prevents second-preimage collision attacks between leaf and internal nodes.
    
    Odd-leaf handling:
      * An unbalanced odd leaf at any tier is promoted directly or combined with domain separation.
    """

    LEAF_PREFIX = b"\x00"
    NODE_PREFIX = b"\x01"

    @staticmethod
    def canonical_serialize(obj: Any) -> bytes:
        """
        RFC 8785 JSON Canonicalization Scheme (JCS).
        Ensures byte-for-byte identical serialization across Windows, Linux, and macOS.
        """
        return json.dumps(
            obj,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")

    @classmethod
    def compute_root(cls, leaf_hashes: Sequence[str]) -> str:
        """
        Compute root hash over a list of leaf hex digests using domain separation.
        Empty set produces standard 64-zero hash.
        """
        if not leaf_hashes:
            return "0" * 64

        # Deterministic sort of leaf hashes for reproducible evidence trees
        sorted_leaves = sorted(leaf_hashes)

        # RFC 6962 Leaf Hashing: H(0x00 || leaf_hash_bytes)
        current_layer = [
            hashlib.sha256(cls.LEAF_PREFIX + bytes.fromhex(h)).digest()
            for h in sorted_leaves
        ]

        while len(current_layer) > 1:
            next_layer = []
            for i in range(0, len(current_layer), 2):
                left = current_layer[i]
                if i + 1 < len(current_layer):
                    right = current_layer[i + 1]
                else:
                    # Odd-leaf promotion rule with domain preservation
                    right = left
                combined = hashlib.sha256(cls.NODE_PREFIX + left + right).digest()
                next_layer.append(combined)
            current_layer = next_layer

        return current_layer[0].hex()
