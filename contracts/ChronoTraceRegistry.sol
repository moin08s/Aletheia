// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title ChronoTraceRegistry
 * @dev Decentralized Forensic Evidence & Chain-of-Custody Attestation Registry for WASP.
 * Built for EVM environments (Ethereum, Base, Arbitrum, Optimism) for ETHGlobal hackathons.
 *
 * Implements:
 * 1. Cryptographic Case Anchoring: Merkle Root + IPFS CID + SHA256 Bundle digest.
 * 2. Immutable Chain of Custody: Track transfers of investigative responsibility between addresses.
 * 3. On-chain RFC 6962 Domain-Separated Merkle Verification: Verify evidence inclusion trustlessly.
 * 4. Tamper Evident Event Emission: Auditable provenance timeline for courts and forensic reviewers.
 */
contract ChronoTraceRegistry {

    struct CustodyRecord {
        address from;
        address to;
        uint256 timestamp;
        string reason;
        bytes signature; // EIP-712 or ECDSA signature payload
    }

    struct CaseEvidence {
        bytes32 caseId;              // Unique identifier (e.g. keccak256("CASE-2026-LIVE"))
        bytes32 merkleRoot;          // RFC 6962 Domain-Separated Merkle Root
        bytes32 evidenceSha256;      // SHA-256 digest of sealed raw evidence archive
        string ipfsCid;              // Content identifier on IPFS / Filecoin / Arweave
        address leadInvestigator;    // Original registering investigator
        uint256 registeredAt;        // Unix timestamp on-chain
        uint256 eventCount;          // Total number of normalized timeline events
        bool isSealed;               // State seal flag
    }

    // Mapping from caseId to CaseEvidence
    mapping(bytes32 => CaseEvidence) public cases;

    // Mapping from caseId to Chain of Custody history
    mapping(bytes32 => CustodyRecord[]) public custodyLedger;

    // Mapping from caseId => (leafHash => bool) for fast pre-verified evidence lookups
    mapping(bytes32 => mapping(bytes32 => bool)) public verifiedLeaves;

    // Events
    event CaseRegistered(
        bytes32 indexed caseId,
        bytes32 indexed merkleRoot,
        address indexed investigator,
        bytes32 evidenceSha256,
        string ipfsCid,
        uint256 eventCount,
        uint256 timestamp
    );

    event CustodyTransferred(
        bytes32 indexed caseId,
        address indexed from,
        address indexed to,
        string reason,
        uint256 timestamp
    );

    event EvidenceLeafVerified(
        bytes32 indexed caseId,
        bytes32 indexed leafHash,
        bool isValid,
        uint256 timestamp
    );

    // Errors
    error CaseAlreadyExists(bytes32 caseId);
    error CaseNotFound(bytes32 caseId);
    error UnauthorizedInvestigator(address caller);
    error InvalidMerkleProof();
    error InvalidParameters();

    modifier onlyLeadInvestigator(bytes32 _caseId) {
        CaseEvidence memory c = cases[_caseId];
        if (c.registeredAt == 0) revert CaseNotFound(_caseId);
        if (c.leadInvestigator != msg.sender) revert UnauthorizedInvestigator(msg.sender);
        _;
    }

    /**
     * @notice Register a newly sealed forensic case with its cryptographic roots.
     * @param _caseId Unique identifier hash of the case
     * @param _merkleRoot RFC 6962 Merkle tree root of all ingested timeline events
     * @param _evidenceSha256 SHA-256 digest of the raw acquisition bundle
     * @param _ipfsCid IPFS CID where the encrypted forensic bundle is archived
     * @param _eventCount Total count of normalized events
     */
    function registerCase(
        bytes32 _caseId,
        bytes32 _merkleRoot,
        bytes32 _evidenceSha256,
        string calldata _ipfsCid,
        uint256 _eventCount
    ) external {
        if (_caseId == bytes32(0) || _merkleRoot == bytes32(0)) revert InvalidParameters();
        if (cases[_caseId].registeredAt != 0) revert CaseAlreadyExists(_caseId);

        cases[_caseId] = CaseEvidence({
            caseId: _caseId,
            merkleRoot: _merkleRoot,
            evidenceSha256: _evidenceSha256,
            ipfsCid: _ipfsCid,
            leadInvestigator: msg.sender,
            registeredAt: block.timestamp,
            eventCount: _eventCount,
            isSealed: true
        });

        // Initialize chain of custody with creator
        custodyLedger[_caseId].push(CustodyRecord({
            from: address(0),
            to: msg.sender,
            timestamp: block.timestamp,
            reason: "Initial Case Acquisition & Cryptographic Anchoring",
            signature: ""
        }));

        emit CaseRegistered(
            _caseId,
            _merkleRoot,
            msg.sender,
            _evidenceSha256,
            _ipfsCid,
            _eventCount,
            block.timestamp
        );
    }

    /**
     * @notice Formal transfer of forensic custody to another investigator, judge, or authority.
     */
    function transferCustody(
        bytes32 _caseId,
        address _newCustodian,
        string calldata _reason,
        bytes calldata _signature
    ) external onlyLeadInvestigator(_caseId) {
        if (_newCustodian == address(0)) revert InvalidParameters();

        address previousCustodian = cases[_caseId].leadInvestigator;
        cases[_caseId].leadInvestigator = _newCustodian;

        custodyLedger[_caseId].push(CustodyRecord({
            from: previousCustodian,
            to: _newCustodian,
            timestamp: block.timestamp,
            reason: _reason,
            signature: _signature
        }));

        emit CustodyTransferred(_caseId, previousCustodian, _newCustodian, _reason, block.timestamp);
    }

    /**
     * @notice Verify inclusion of a specific evidence leaf hash against on-chain Merkle Root.
     * Implements RFC 6962 Domain Separation:
     * - Leaf: H(0x00 || leaf_data)
     * - Node: H(0x01 || left || right)
     */
    function verifyEvidenceInclusion(
        bytes32 _caseId,
        bytes32 _leafHash,
        bytes32[] calldata _proof,
        bool[] calldata _isRightSide
    ) external returns (bool) {
        CaseEvidence memory c = cases[_caseId];
        if (c.registeredAt == 0) revert CaseNotFound(_caseId);
        if (_proof.length != _isRightSide.length) revert InvalidParameters();

        // Calculate RFC 6962 domain-separated leaf digest
        bytes32 computedHash = sha256(abi.encodePacked(uint8(0x00), _leafHash));

        for (uint256 i = 0; i < _proof.length; i++) {
            bytes32 proofElement = _proof[i];
            if (_isRightSide[i]) {
                computedHash = sha256(abi.encodePacked(uint8(0x01), computedHash, proofElement));
            } else {
                computedHash = sha256(abi.encodePacked(uint8(0x01), proofElement, computedHash));
            }
        }

        bool isValid = (computedHash == c.merkleRoot);
        if (isValid) {
            verifiedLeaves[_caseId][_leafHash] = true;
        }

        emit EvidenceLeafVerified(_caseId, _leafHash, isValid, block.timestamp);
        return isValid;
    }

    /**
     * @notice Read case information
     */
    function getCase(bytes32 _caseId) external view returns (CaseEvidence memory) {
        if (cases[_caseId].registeredAt == 0) revert CaseNotFound(_caseId);
        return cases[_caseId];
    }

    /**
     * @notice Read complete Chain-of-Custody history
     */
    function getCustodyHistory(bytes32 _caseId) external view returns (CustodyRecord[] memory) {
        if (cases[_caseId].registeredAt == 0) revert CaseNotFound(_caseId);
        return custodyLedger[_caseId];
    }
}
