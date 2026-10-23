// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./ChronoTraceRegistry.sol";

/**
 * @title AletheiaRegistry
 * @dev The official EVM case registry contract for Aletheia (The Incorruptible Witness on Ethereum).
 * Extends ChronoTraceRegistry with Aletheia branding, zero-knowledge verification hooks,
 * and FRE 902(14) compliant on-chain attestations.
 */
contract AletheiaRegistry is ChronoTraceRegistry {
    string public constant PLATFORM_NAME = "Aletheia DeDFIR";
    string public constant SPECIFICATION = "FRE-902(14)-RFC6962";

    event ZKProofRegistered(
        bytes32 indexed caseId,
        bytes32 indexed proofHash,
        uint256 timestamp
    );

    /**
     * @notice Register a verified zero-knowledge selective disclosure proof hash.
     */
    function recordZKProof(bytes32 _caseId, bytes32 _proofHash) external onlyLeadInvestigator(_caseId) {
        emit ZKProofRegistered(_caseId, _proofHash, block.timestamp);
    }
}
