pragma solidity ^0.8.0;

import "/home/oracle/contracts/EllipticCurve.sol";

contract ATS{
    uint256 n=10;
    uint256 t=4;
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
    uint256 constant MAX_UINT256 = type(uint256).max;

    bool public z_combined=false;

    point public R;
    uint256 public z;

    struct SigATS {
        uint256 Rix;
        uint256 Riy;
        uint256 zi;
    }

    struct point{
        uint256 x;
        uint256 y;
    }
    
    mapping(bytes32 => point) public pks;
    mapping(bytes32 => point) public Ris;
    mapping(bytes32 => uint256) public zis;
    mapping(bytes32 => bool) public incommittee;
    string[] public committee;//Committee
    string[] public all_signer_list;//All oracles
    string[] public R_submit_list;
    string[] public z_submit_list;

    function addsigner(string memory name,uint256 x,uint256 y) public{
        pks[stringToBytes32(name)]=point(x,y);
        all_signer_list.push(name);
    }

    function register_committee(string memory name) public{
        committee.push(name);
        incommittee[stringToBytes32(name)]=true;
    }

    function addRi(string memory name,uint256 x,uint256 y) public{
        require(incommittee[stringToBytes32(name)],name);
        R_submit_list.push(name);
        Ris[stringToBytes32(name)]=point(x,y);
        if (R_submit_list.length>=t){
            combineR();
        }
    }

    function addzi(string memory name,uint256 zi) public{
        require(incommittee[stringToBytes32(name)],name);
        zis[stringToBytes32(name)]=zi;
        z_submit_list.push(name);
        if (z_submit_list.length>=t){
            combinez();
        }
    }

    function combineR() private{
        point memory tempR=Ris[stringToBytes32(committee[0])];
        uint256 tempRx=tempR.x;
        uint256 tempRy=tempR.y;
        for(uint i=1;i<committee.length;i++){
            (tempRx,tempRy)=EllipticCurve.ecAdd(tempRx, tempRy,Ris[stringToBytes32(committee[i])].x,Ris[stringToBytes32(committee[i])].y, AA, PP);
            
        }
        R.x=tempRx;
        R.y=tempRy;
    }


    function combinez() public {
            uint256 sum=0;
            for (uint i = 0; i < committee.length; i++) {
                sum = addmod(sum, zis[stringToBytes32(committee[i])], NN);
            }
            z = sum;
    }

    function combinepk() public view returns(uint256,uint256){
        point memory temppk=pks[stringToBytes32(committee[0])];
        uint256 temppkx=temppk.x;
        uint256 temppky=temppk.y;
        for(uint i=1;i<committee.length;i++){
            (temppkx,temppky)=EllipticCurve.ecAdd(temppkx, temppky,pks[stringToBytes32(committee[i])].x,pks[stringToBytes32(committee[i])].y, AA, PP);
            
        }
        return (temppkx,temppky);
    }

    function iszcombined() public returns(bool){
        return z_combined;
    }

    function getCombinedSig() public view returns (uint256,uint256,uint256) {
        return (R.x,R.y,z);
    }

    function getR() public view returns (uint256,uint256){
        return (R.x,R.y);
    }

    function getz() public view returns (uint256){
        return z;
    }

    function verify(string memory message) public view returns  (bool) {
        uint256 c = computec(message);
        uint256 p1x;
        uint256 p1y;
        uint256 p2x;
        uint256 p2y;
        uint256 pkcx;
        uint256 pkcy;
        uint256 pkcmcx;
        uint256 pkcmcy;
        (p1x,p1y) = EllipticCurve.ecMul(z, GX, GY, AA, PP);
        (pkcx,pkcy) = combinepk();
        (pkcmcx,pkcmcy) = EllipticCurve.ecMul(c, pkcx, pkcy, AA, PP);
        (p2x,p2y) = EllipticCurve.ecAdd(pkcmcx, pkcmcy, R.x,R.y , AA, PP);
        return p1x==p2x && p1y==p2y;
        //return(p1x,p1y,p2x,p2y);
    }


    function computec(string memory message) public view returns (uint256) {
        bytes memory concatenatedPks;
        concatenatedPks=abi.encodePacked(t);
        for (uint256 i = 0; i < all_signer_list.length; i++) {
            concatenatedPks = abi.encodePacked(concatenatedPks, pks[stringToBytes32(all_signer_list[i])].x, pks[stringToBytes32(all_signer_list[i])].y);
        }
        concatenatedPks=abi.encodePacked(concatenatedPks,R.x,R.y);
        concatenatedPks=abi.encodePacked(concatenatedPks,message);
        bytes32 hash = keccak256(concatenatedPks);
        
        // 将哈希值转换为整数
        uint256 hashInt = uint256(hash);
        
        // 对整数取模
        uint256 c = hashInt % NN;
        return c;
    }

    function stringToBytes32(string memory source) public pure returns (bytes32 result) {
        bytes memory tempEmptyStringTest = bytes(source);
        if (tempEmptyStringTest.length == 0) {
            return 0x0;
        }

        assembly {
            result := mload(add(source, 32))
        }
    }

    function point_to_bytes_uint(uint256 a, uint256 b) public pure returns (bytes memory) {
        return abi.encodePacked(a, b);
    }
}