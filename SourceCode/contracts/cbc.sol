// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;
import "/home/oracle/contracts/EllipticCurve.sol";

contract CBC{
    //mapping(bytes32 => bytes32) public VerifyResult;
    //mapping(bytes32 => bytes32) public Req;
    //mapping(bytes32 => bytes32) public Res;
    bool[] VerifyResult;
    uint256 public constant GX =
        0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798;
    uint256 public constant GY =
        0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8;
    uint256 public constant AA = 0;
    uint256 public constant BB = 7;
    uint256 public constant PP =
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;
    uint256 public constant NN = 
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;


    struct request_data{
        string ct;
        bytes32 uuid;
    }
    request_data[] Req;

    struct response_data{
        string ct;
        bytes32 uuid;
    }
    response_data[] Res;

    event requested(string,bytes32);
    event responded(string,bytes32);

    function collect(uint256 pkx,uint256 pky,uint256 Rx, uint256 Ry,uint256 z,string memory message, bytes32 tx_hash, bytes memory signature, address signer) public returns(bool){
        require(verify(signer,tx_hash,signature));//P sig
        require(verify_sch(message,Rx,Ry,pkx,pky,z));
        VerifyResult.push(true);
        return true;
    }

    function trace(uint256 pkx,uint256 pky,uint256 Rx, uint256 Ry,uint256 z,string memory message, bytes32 tx_hash, bytes memory signature, address signer) public returns(bool){
        require(verify(signer,tx_hash,signature));//P sig
        require(verify_sch(message,Rx,Ry,pkx,pky,z));
        VerifyResult.push(true);
        return true;
    }

    function request(string memory ct,bytes32 hash,bytes memory signature,address signer) public{
        require(verify(signer,hash,signature));//U sig
        bytes32 uuid=generateUUID();
        request_data memory r=request_data(ct,uuid);
        Req.push(r);
        emit requested(ct,uuid);
    }

    function respond(uint256 pkx,uint256 pky,uint256 Rx, uint256 Ry,uint256 z,string memory ct,bytes32 uuid, bytes32 tx_hash, bytes memory signature, address signer) public{
        require(verify(signer,tx_hash,signature));//P sig message=ct
        require(verify_sch(ct,Rx,Ry,pkx,pky,z));
        response_data memory r=response_data(ct,uuid);
        Res.push(r);
        emit requested(ct,uuid);
    }

    function generateUUID() public view returns (bytes32) {
        // Combining block number, timestamp, and sender address
        return keccak256(abi.encodePacked(block.number, block.timestamp, msg.sender));
    }

    function verify_sch(string memory message,uint256 Rx,uint256 Ry,uint256 pkx, uint256 pky,uint256 z) public pure returns  (bool) {
        uint256 c = computec(message,Rx,Ry,pkx,pky);
        uint256 p1x;
        uint256 p1y;
        uint256 p2x;
        uint256 p2y;
        uint256 pkcx;
        uint256 pkcy;
        (p1x,p1y) = EllipticCurve.ecMul(z, GX, GY, AA, PP);
        (pkcx,pkcy) = EllipticCurve.ecMul(c, pkx, pky, AA, PP);
        (p2x,p2y) = EllipticCurve.ecAdd(pkcx, pkcy, Rx,Ry , AA, PP);
        return p1x==p2x && p1y==p2y;
    }

    function computec(string memory message,uint256 Rx,uint256 Ry,uint256 pkx, uint256 pky) public pure returns (uint256) {
        bytes memory concatenatedPks;

        concatenatedPks = abi.encodePacked(concatenatedPks, pkx, pky);

        concatenatedPks=abi.encodePacked(concatenatedPks,Rx,Ry);
        concatenatedPks=abi.encodePacked(concatenatedPks,message);
        bytes32 hash = keccak256(concatenatedPks);
        
        // 将哈希值转换为整数
        uint256 hashInt = uint256(hash);
        
        // 对整数取模
        uint256 c = hashInt % NN;
        return c;
    }

    function verify(
        address signer,
        bytes32 messageHash,
        bytes memory signature
    ) public pure returns (bool) {
        bytes32 ethSignedMessageHash = getEthSignedMessageHash(messageHash);

        (bytes32 r, bytes32 s, uint8 v) = splitSignature(signature);

        address recoveredAddress = ecrecover(ethSignedMessageHash, v, r, s);
        return recoveredAddress == signer;
    }

    function getEthSignedMessageHash(bytes32 _messageHash) public pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", _messageHash));
    }

    function splitSignature(bytes memory sig)
        public
        pure
        returns (
            bytes32 r,
            bytes32 s,
            uint8 v
        )
    {
        require(sig.length == 65, "Invalid signature length");

        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }
    }
}