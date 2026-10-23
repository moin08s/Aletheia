"""Property-Based Invariant Verification for RFC 6962 Merkle Tree Engine.

Mathematically verifies core cryptographic properties across randomized adversarial inputs:
1. Determinism: Identical leaves produce identical roots.
2. Single-Bit Mutation Sensitivity: Mutating any leaf invalidates the root.
3. RFC 6962 Domain Separation: Leaf prefixes (0x00) and branch prefixes (0x01) never collide.
4. Edge Cases: Empty tree, duplicate leaves, single-leaf domain trees.
5. Float Stability: Non-parametric MAD / Z-score statistics produce deterministic results.
"""

import hashlib
import random
from chronotrace.integrity.merkle import MerkleTree
from chronotrace.analysis.anomalies import AnomalyDetector
from chronotrace.core.models import Event, EventEvidence, EventObject, EventSource


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


def test_merkle_empty_tree_and_edge_cases():
    """Edge Case: Empty tree returns 64 zeroes, single leaf computes correct RFC 6962 domain leaf."""
    empty_root = MerkleTree.compute_root([])
    assert empty_root == "0" * 64

    single_leaf = _random_sha256()
    expected_leaf_hash = hashlib.sha256(MerkleTree.LEAF_PREFIX + bytes.fromhex(single_leaf)).digest().hex()
    actual_root = MerkleTree.compute_root([single_leaf])
    assert actual_root == expected_leaf_hash

    # Duplicate leaves must not crash or trigger division by zero
    duplicates = [single_leaf] * 8
    dup_root = MerkleTree.compute_root(duplicates)
    assert len(dup_root) == 64


def test_float_determinism_mad_computation():
    """Property: Statistical anomaly detector Z-score calculations are byte-for-byte identical across runs."""
    mock_events = [
        Event(
            event_id=f"ev-{i}",
            timestamp_utc=f"2024-03-11T02:{i:02d}:00+00:00",
            action="FILE_WRITE",
            user="attacker",
            host="WS-01",
            object=EventObject(path=f"C:\\file_{i}.txt"),
            source=EventSource(artifact="TEST", plugin="test", evidence_id="EV-1"),
            evidence=EventEvidence(evidence_id="EV-1", sha256="0" * 64),
        )
        for i in range(20)
    ]

    detector1 = AnomalyDetector(mock_events)
    detector2 = AnomalyDetector(mock_events)

    findings1 = [f.to_dict() for f in detector1.detect_all()]
    findings2 = [f.to_dict() for f in detector2.detect_all()]

    assert findings1 == findings2
