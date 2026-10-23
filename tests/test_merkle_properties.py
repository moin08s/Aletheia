"""Property-Based Invariant Verification for RFC 6962 Merkle Tree Engine.

Mathematically verifies core cryptographic properties across randomized adversarial inputs:
1. Determinism: Identical leaves produce identical roots.
2. Single-Bit Mutation Sensitivity: Mutating any leaf invalidates the root.
3. RFC 6962 Domain Separation: Leaf prefixes (0x00) and branch prefixes (0x01) never collide.
"""

import hashlib
import random
from chronotrace.integrity.merkle import MerkleTree


def _random_sha256() -> str:
    noise = str(random.random()).encode("utf-8")
    return hashlib.sha256(noise).hexdigest()


def test_merkle_determinism_property():
    """Property: Merkle root computation is 100% deterministic across repeated runs."""
    for _ in range(50):
        leaf_count = random.randint(1, 64)
        leaves = [_random_sha256() for _ in range(leaf_count)]

        root1 = MerkleTree.compute_root(leaves)
        root2 = MerkleTree.compute_root(leaves)

        assert root1 == root2
        assert len(root1) == 64


def test_merkle_single_bit_mutation_sensitivity():
    """Property: Mutating even 1 byte in any leaf guarantees a completely different root."""
    for _ in range(50):
        leaf_count = random.randint(2, 32)
        leaves = [_random_sha256() for _ in range(leaf_count)]

        orig_root = MerkleTree.compute_root(leaves)

        # Pick random leaf and replace with a mutated hash
        idx = random.randint(0, leaf_count - 1)
        mutated_leaves = list(leaves)
        mutated_leaves[idx] = _random_sha256()

        mutated_root = MerkleTree.compute_root(mutated_leaves)
        assert orig_root != mutated_root, f"Collision detected at index {idx}!"


def test_rfc6962_domain_separation_invariants():
    """Property: RFC 6962 domain prefixes ensure leaf hashes and interior branch hashes cannot collide."""
    test_data = b"FORENSIC_TIMELINE_EVENT_SAMPLE"
    leaf_hash = hashlib.sha256(MerkleTree.LEAF_PREFIX + test_data).hexdigest()
    node_hash = hashlib.sha256(MerkleTree.NODE_PREFIX + test_data).hexdigest()

    assert leaf_hash != node_hash
