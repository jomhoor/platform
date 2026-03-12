// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import {IEvidenceRegistry} from "@rarimo/evidence-registry/interfaces/IEvidenceRegistry.sol";

/**
 * @title MockEvidenceRegistry
 * @dev A minimal mock of the EvidenceRegistry for local testing.
 * The PoseidonSMT contracts call evidenceRegistry.addStatement() when updating Merkle roots.
 * On Rarimo mainnet/testnet, a real EvidenceRegistry exists. Locally, we deploy this mock.
 */
contract MockEvidenceRegistry is IEvidenceRegistry {
    // Mapping to store statements
    mapping(bytes32 => bytes32) public statements;
    
    // Mapping for root timestamps
    mapping(bytes32 => uint256) public rootTimestamps;
    
    // Current root
    bytes32 public currentRoot;

    /// @notice Add a statement to the registry
    function addStatement(bytes32 key, bytes32 value) external override {
        statements[key] = value;
        bytes32 prevRoot = currentRoot;
        currentRoot = keccak256(abi.encodePacked(prevRoot, key, value));
        rootTimestamps[currentRoot] = block.timestamp;
        emit RootUpdated(prevRoot, currentRoot);
    }

    /// @notice Remove a statement from the registry
    function removeStatement(bytes32 key) external override {
        delete statements[key];
        bytes32 prevRoot = currentRoot;
        currentRoot = keccak256(abi.encodePacked(prevRoot, key));
        rootTimestamps[currentRoot] = block.timestamp;
        emit RootUpdated(prevRoot, currentRoot);
    }

    /// @notice Update a statement in the registry
    function updateStatement(bytes32 key, bytes32 newValue) external override {
        statements[key] = newValue;
        bytes32 prevRoot = currentRoot;
        currentRoot = keccak256(abi.encodePacked(prevRoot, key, newValue));
        rootTimestamps[currentRoot] = block.timestamp;
        emit RootUpdated(prevRoot, currentRoot);
    }

    /// @notice Get timestamp for a root (current returns block.timestamp, non-existent returns 0)
    function getRootTimestamp(bytes32 root) external view override returns (uint256) {
        if (root == currentRoot) {
            return block.timestamp;
        }
        return rootTimestamps[root];
    }
}
