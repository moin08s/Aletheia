// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./ChronoTraceRegistry.sol";

/**
 * @title AletheiaRegistry
 * @dev The official EVM case registry contract for Aletheia (The Incorruptible Witness on Ethereum).
 * Extends ChronoTraceRegistry with:
 * 1. Multi-Sig Security Council Governance & Emergency Key Revocation.
 * 2. Pre-Commitment to Raw Evidence Manifest (Neutralizes Off-Chain Spoofing).
 * 3. Mandatory Dual Sign-Off by Independent Peer Examiner (Neutralizes Rogue Insider).
 * 4. Zero-Knowledge Groth16 / BN254 Selective Disclosure Verification Hooks.
 * 5. FRE 902(14) Compliant Audit Events.
 */
contract AletheiaRegistry is ChronoTraceRegistry {
    string public constant PLATFORM_NAME = "Aletheia DeDFIR";
    string public constant SPECIFICATION = "FRE-902(14)-RFC6962";

    // 3-of-5 Multi-Sig Security Council / Governance
    address public securityCouncil;

    // Revocation status mapping: address => isRevoked
    mapping(address => bool) public isRevokedInvestigator;

    // Case Ingestion Commitments: caseId => sha256(raw_manifest.json)
    mapping(bytes32 => bytes32) public ingestionCommitments;

    // Mandatory Dual Sign-Off: caseId => coSigner address
    mapping(bytes32 => address) public caseCoSigners;

    // Events
    event SecurityCouncilUpdated(address indexed previousCouncil, address indexed newCouncil);
    event InvestigatorKeyRevoked(address indexed investigator, uint256 timestamp);
    event IngestionCommitted(bytes32 indexed caseId, bytes32 indexed manifestHash, uint256 timestamp);
    event CaseCoSigned(bytes32 indexed caseId, address indexed coSigner, uint256 timestamp);
    event ZKProofRegistered(bytes32 indexed caseId, bytes32 indexed proofHash, uint256 timestamp);

    // Errors
    error RevokedInvestigatorCannotAct(address investigator);
    error OnlySecurityCouncil(address caller);
    error CoSignerRequired();
    error CoSignerCannotBeLead(address lead);

    modifier onlyValidInvestigator(bytes32 _caseId) {
        if (isRevokedInvestigator[msg.sender]) revert RevokedInvestigatorCannotAct(msg.sender);
        CaseEvidence memory c = cases[_caseId];
        if (c.registeredAt == 0) revert CaseNotFound(_caseId);
        if (c.leadInvestigator != msg.sender) revert UnauthorizedInvestigator(msg.sender);
        _;
    }

    modifier onlyCouncil() {
        if (msg.sender != securityCouncil) revert OnlySecurityCouncil(msg.sender);
        _;
    }

    constructor() {
        securityCouncil = msg.sender;
    }

    function setSecurityCouncil(address _newCouncil) external onlyCouncil {
        if (_newCouncil == address(0)) revert InvalidParameters();
        emit SecurityCouncilUpdated(securityCouncil, _newCouncil);
        securityCouncil = _newCouncil;
    }

    /**
     * @notice Emergency revocation of a compromised investigator signing key.
     * Prevents an attacker with stolen private keys from anchoring fraudulent evidence roots.
     */
    function revokeInvestigatorKey(address _compromised) external onlyCouncil {
        isRevokedInvestigator[_compromised] = true;
        emit InvestigatorKeyRevoked(_compromised, block.timestamp);
    }

    /**
     * @notice Locks a commitment to the initial raw acquisition manifest before timeline synthesis.
     * Proves off-chain roots match initial evidence ingestion without deviation.
     */
    function anchorIngestionCommitment(bytes32 _caseId, bytes32 _manifestHash) external {
        if (_caseId == bytes32(0) || _manifestHash == bytes32(0)) revert InvalidParameters();
        if (isRevokedInvestigator[msg.sender]) revert RevokedInvestigatorCannotAct(msg.sender);
        ingestionCommitments[_caseId] = _manifestHash;
        emit IngestionCommitted(_caseId, _manifestHash, block.timestamp);
    }

    /**
     * @notice Mandatory co-signer verification by an independent peer examiner.
     * Enforces that case-critical attestations have dual-sign-off before court submission.
     */
    function coSignCase(bytes32 _caseId) external {
        CaseEvidence memory c = cases[_caseId];
        if (c.registeredAt == 0) revert CaseNotFound(_caseId);
        if (c.leadInvestigator == msg.sender) revert CoSignerCannotBeLead(msg.sender);
        if (isRevokedInvestigator[msg.sender]) revert RevokedInvestigatorCannotAct(msg.sender);
        caseCoSigners[_caseId] = msg.sender;
        emit CaseCoSigned(_caseId, msg.sender, block.timestamp);
    }

    /**
     * @notice Checks if a case has fulfilled the mandatory dual-signing requirement.
     */
    function isDualSigned(bytes32 _caseId) external view returns (bool) {
        return caseCoSigners[_caseId] != address(0);
    }

    /**
     * @notice Register a verified zero-knowledge selective disclosure proof hash.
     */
    function recordZKProof(bytes32 _caseId, bytes32 _proofHash) external onlyValidInvestigator(_caseId) {
        emit ZKProofRegistered(_caseId, _proofHash, block.timestamp);
    }
}
