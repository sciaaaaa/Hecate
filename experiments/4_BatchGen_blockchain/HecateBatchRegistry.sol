// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;
interface ISystem {
    function getConfig() external view returns (bytes32[4] memory,uint32,address,address,bytes memory,bytes memory);
}
interface IPPK {
    function systemRegistry() external view returns(address);
    function setupId() external view returns(bytes32);
    function expectedSrsHash() external view returns(bytes32);
    function finalized() external view returns(bool);
}
/// Authenticated storage. Clients MUST verify the full-point Schnorr signature.
contract HecateBatchRegistry {
    address public immutable systemRegistry;
    address public immutable ppkStore;
    address public immutable owner;
    bytes32 public immutable setupId;
    bytes32 public immutable keyId;
    uint256 constant Q=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
    struct Batch { bytes U; bytes R; bytes32 s; bytes info; uint256 publishedBlock; }
    mapping(bytes32=>Batch) private batches;
    event BatchPublished(bytes32 indexed t, bytes32 infoHash);
    constructor(address system,address ppk) {
        (bytes32[4] memory ids,,address controller,,,)=ISystem(system).getConfig();
        require(msg.sender==controller,"not registered owner");
        require(IPPK(ppk).systemRegistry()==system && IPPK(ppk).finalized(),"PPK not ready");
        require(IPPK(ppk).setupId()==ids[0] && IPPK(ppk).expectedSrsHash()==ids[3],"PPK mismatch");
        systemRegistry=system;ppkStore=ppk;owner=controller;setupId=ids[0];keyId=ids[1];
    }
    function exists(bytes32 t) external view returns(bool) { return batches[t].publishedBlock!=0; }
    function publishBatch(bytes32 t,bytes calldata U,bytes calldata R,bytes32 s,bytes calldata info) external {
        require(msg.sender==owner,"not owner");
        require(t!=bytes32(0) && batches[t].publishedBlock==0,"batch exists or empty");
        require(U.length==96 && R.length==33,"point length");
        require(R[0]==0x02 || R[0]==0x03,"R encoding");
        require(uint256(s)<Q,"s out of range");
        require(info.length>0 && info.length<=8192,"info length");
        batches[t]=Batch(U,R,s,info,block.number);
        emit BatchPublished(t,sha256(info));
    }
    function getBatch(bytes32 t) external view returns(bytes memory U,bytes memory R,bytes32 s,bytes memory info,uint256 publishedBlock) {
        Batch storage b=batches[t];require(b.publishedBlock!=0,"unknown batch");
        return(b.U,b.R,b.s,b.info,b.publishedBlock);
    }
}
