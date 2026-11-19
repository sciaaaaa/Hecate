// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

interface IReceiverParameters {
    function paramsId() external view returns (bytes32);
}

/// One deployment records one immutable Hecate configuration version.
/// Cryptographic point validation is performed by clients, not by this contract.
contract HecateSystemRegistry {
    // Order: setup_id, alliance key_id, receiver_params_id, srs_sha256.
    bytes32[4] private identifiers;
    uint32 public immutable maxAuthorizationSize;
    address public immutable owner;
    address public immutable receiverRegistry;
    bytes private pairingPublicKey;
    bytes private schnorrPublicKey;

    event SystemRegistered(
        bytes32 indexed setupId,
        bytes32 indexed allianceKeyId,
        address indexed owner,
        uint32 maxAuthorizationSize,
        address receiverRegistry
    );

    constructor(
        bytes32[4] memory ids,
        uint32 capacity,
        address registry,
        bytes memory pairingKey,
        bytes memory schnorrKey
    ) {
        for (uint256 i; i < 4; ++i) require(ids[i] != bytes32(0), "empty identifier");
        require(capacity > 0, "empty capacity");
        require(registry.code.length > 0, "missing receiver registry");
        require(IReceiverParameters(registry).paramsId() == ids[2], "receiver parameters mismatch");
        require(pairingKey.length == 96, "pairing key length");
        require(schnorrKey.length == 33, "schnorr key length");
        require(schnorrKey[0] == 0x02 || schnorrKey[0] == 0x03, "schnorr key encoding");
        identifiers = ids;
        maxAuthorizationSize = capacity;
        owner = msg.sender;
        receiverRegistry = registry;
        pairingPublicKey = pairingKey;
        schnorrPublicKey = schnorrKey;
        emit SystemRegistered(ids[0], ids[1], msg.sender, capacity, registry);
    }

    function getConfig() external view returns (
        bytes32[4] memory ids,
        uint32 capacity,
        address controller,
        address registry,
        bytes memory pairingKey,
        bytes memory schnorrKey
    ) {
        return (identifiers, maxAuthorizationSize, owner, receiverRegistry,
                pairingPublicKey, schnorrPublicKey);
    }
}
