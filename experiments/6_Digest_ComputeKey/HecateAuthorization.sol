// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;
interface ICapacity { function maxAuthorizationSize() external view returns(uint32); }
interface ICipher {
 struct Record {address sender;bytes32 batch;bytes32 id;bytes32 receiver;bytes publicKey;uint256 size;uint256 uploaded;bytes32 expected;bytes32 rolling;bool finalized;}
 function owner() external view returns(address);
 function systemRegistry() external view returns(address);
 function get(bytes32 key) external view returns(Record memory);
}
// Authenticated immutable set per batch. Clients recompute the polynomial digest.
// No capability key or capability ciphertext is accepted by this contract.
contract HecateAuthorization {
 address public immutable owner;
 address public immutable cipherStore;
 uint32 public immutable capacity;
 uint256 constant P=52435875175126190479447740508185965837690552500527637822603658699938581184513;
 struct Grant {bool exists;address[] senders;bytes32[] ids;bytes digest;bytes32[] receivers;}
 mapping(bytes32=>Grant) private grants;
 event Authorized(bytes32 indexed batch,bytes32 commitment);
 constructor(address store) {
   require(store.code.length>0,"store");
   require(msg.sender==ICipher(store).owner(),"owner");
   owner=msg.sender;cipherStore=store;
   capacity=ICapacity(ICipher(store).systemRegistry()).maxAuthorizationSize();
 }
 function publish(bytes32 batch,address[] calldata senders,bytes32[] calldata ids,bytes calldata digest) external {
   require(msg.sender==owner,"owner");require(!grants[batch].exists,"batch already authorized");
   require(ids.length>0 && ids.length<=capacity && senders.length==ids.length,"count");
   require(digest.length==48,"G1 encoding length");
   bytes32[] memory receivers=new bytes32[](ids.length);
   for(uint256 i=0;i<ids.length;i++) {
     require(uint256(ids[i])<P && (i==0 || uint256(ids[i-1])<uint256(ids[i])),"sorted distinct IDs");
     ICipher.Record memory r=ICipher(cipherStore).get(keccak256(abi.encodePacked(senders[i],batch,ids[i])));
     require(r.finalized && r.sender==senders[i] && r.batch==batch && r.id==ids[i],"record binding");
     receivers[i]=r.receiver;
   }
   Grant storage g=grants[batch];g.exists=true;g.senders=senders;g.ids=ids;g.digest=digest;g.receivers=receivers;
   emit Authorized(batch,keccak256(abi.encode(batch,senders,ids,digest,receivers)));
 }
 function get(bytes32 batch) external view returns(Grant memory){return grants[batch];}
}
