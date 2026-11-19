// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

interface IHecateSystem {
    function getConfig() external view returns
        (bytes32[4] memory, uint32, address, address, bytes memory, bytes memory);
}

/// Full public parameters, immutable after successful finalization.
contract HecatePPKStore {
    address public immutable systemRegistry;
    address public immutable owner;
    bytes32 public immutable setupId;
    bytes32 public immutable expectedSrsHash;
    bytes32 public immutable manifestHash;
    uint32 public immutable capacity;
    uint32 public constant POINTS_PER_CHUNK = 64;
    uint32 public immutable chunkCount;
    uint32 public uploadedChunks;
    bool public finalized;
    bytes private manifestData;
    bytes private tau2Data;
    mapping(uint256 => bytes) private chunks;

    event ChunkUploaded(uint256 indexed index, bytes32 sha256Hash);
    event ParametersFinalized(bytes32 indexed setupId, bytes32 srsHash);

    modifier onlyOwner() { require(msg.sender == owner, "not owner"); _; }
    modifier ready() { require(finalized, "not finalized"); _; }

    constructor(address registry, bytes memory manifest, bytes memory tau2) {
        (bytes32[4] memory ids, uint32 B, address controller,,,) = IHecateSystem(registry).getConfig();
        require(msg.sender == controller, "not registered owner");
        // Bound the maximum finalization workload for this implementation.
        require(B > 0 && B <= 4096, "unsupported capacity");
        require(manifest.length > 0 && manifest.length <= 32768, "manifest length");
        require(tau2.length == 96, "tau2 length");
        systemRegistry = registry;
        owner = controller;
        setupId = ids[0];
        expectedSrsHash = ids[3];
        capacity = B;
        chunkCount = (B + POINTS_PER_CHUNK - 1) / POINTS_PER_CHUNK;
        manifestData = manifest;
        manifestHash = sha256(manifest);
        tau2Data = tau2;
    }

    function uploadChunk(uint256 index, bytes calldata data) external onlyOwner {
        require(!finalized, "already finalized");
        require(index < chunkCount, "chunk index");
        uint256 first = index * POINTS_PER_CHUNK;
        uint256 count = capacity - first;
        if (count > POINTS_PER_CHUNK) count = POINTS_PER_CHUNK;
        require(data.length == count * 48, "chunk length");
        if (chunks[index].length != 0) {
            require(keccak256(chunks[index]) == keccak256(data), "conflicting chunk");
            return; // Same-content retry never increments uploadedChunks.
        }
        chunks[index] = data;
        ++uploadedChunks;
        emit ChunkUploaded(index, sha256(data));
    }

    function chunkHash(uint256 index) external view returns (bytes32) {
        require(index < chunkCount, "chunk index");
        if (chunks[index].length == 0) return bytes32(0);
        return sha256(chunks[index]);
    }

    function copyBytes(bytes memory dest, uint256 offset, bytes memory source) private pure {
        require(offset + source.length <= dest.length, "copy bounds");
        // Word copies, including padding in the last word. Subsequent payload
        // overwrites any overlapping padding; final padding is not hashed.
        assembly {
            let target := add(add(dest, 32), offset)
            let start := add(source, 32)
            for { let i := 0 } lt(i, mload(source)) { i := add(i, 32) } {
                mstore(add(target, i), mload(add(start, i)))
            }
        }
    }

    function finalize() external onlyOwner {
        require(!finalized, "already finalized");
        require(uploadedChunks == chunkCount, "incomplete upload");
        bytes memory all = new bytes(uint256(capacity) * 48 + 96);
        for (uint256 i; i < chunkCount; ++i) {
            bytes memory part = chunks[i];
            copyBytes(all, i * POINTS_PER_CHUNK * 48, part);
        }
        bytes memory tau2 = tau2Data;
        copyBytes(all, uint256(capacity) * 48, tau2);
        require(sha256(all) == expectedSrsHash, "SRS hash mismatch");
        finalized = true;
        emit ParametersFinalized(setupId, expectedSrsHash);
    }

    function getManifest() external view ready returns (bytes memory) { return manifestData; }
    function getTauG2() external view ready returns (bytes memory) { return tau2Data; }
    function getG1Chunk(uint256 index) external view ready returns (bytes memory) {
        require(index < chunkCount, "chunk index");
        return chunks[index];
    }
    /// 1-based j: return [tau^j]_1. P0=G1 is in the public manifest.
    function getG1Power(uint256 j) external view ready returns (bytes memory) {
        require(j >= 1 && j <= capacity, "power index");
        bytes memory part = chunks[(j - 1) / POINTS_PER_CHUNK];
        uint256 offset = ((j - 1) % POINTS_PER_CHUNK) * 48;
        bytes memory result = new bytes(48);
        for (uint256 i; i < 48; ++i) result[i] = part[offset + i];
        return result;
    }
}
