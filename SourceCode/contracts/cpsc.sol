// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import "/home/oracle/contracts/EllipticCurve.sol";

contract CPSC {

    struct SigATS {
        uint256 Rix;
        uint256 Riy;
        uint256 zi;
    }

    struct point{
        uint256 x;
        uint256 y;
    }

    struct m2{
        bytes data;
        string ct;
        bytes sigvc;
        string a1a2;
        uint256 ts;
        uint256 Rx;
        uint256 Ry;
        uint256 z;
        string dp;
    }

    string[] public committee;//Committee
    string[] public all_signer_list;//All oracles

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

    bytes ssk_psc;
    bytes vk_psc;

    mapping(bytes32 => point) public pks;//pks of ats scheme
    mapping(bytes32 => SigATS[]) private Index;
    mapping(bytes32 => m2[]) private Index_m2data;
    mapping(bytes32 => bool) private Index_ats;
    
    function addsigner(string memory name,uint256 x,uint256 y) public{
        pks[stringToBytes32(name)]=point(x,y);
        all_signer_list.push(name);
    }

    function register_committee(string memory name) public{
        committee.push(name);
    }

    function generateIKey(string memory _a1a2, string memory _data) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(_a1a2, _data));
    }

    function addATS(string memory _a1a2, string memory _data, uint256 Rix, uint256 Riy, uint256 zi) public {
        bytes32 key = generateIKey(_a1a2,_data);
        Index[key].push(SigATS(Rix, Riy, zi));
    }


    event ats_success(bytes32 key);
        function collect(bytes memory meta_and_name,bytes memory data,string memory ct,bytes memory sigvc,string memory a1a2, uint256 ts,uint256 Rix,uint256 Riy,uint256 zi) public{
        //if sigvc=b'0', b=0
        (string memory meta, string memory dp) = abi.decode(meta_and_name, (string, string));
        //bytes32 key = generateIKey(a1a2, meta);//For storage
        //bytes32 ats_key = generateIKey(a1, a2, ct);//For ATS
        //update Index
        addATS(a1a2, ct, Rix, Riy, zi);
        SigATS[] memory sigs = Index[generateIKey(a1a2, ct)]; //Ats的存储使用ct，因为针对同一批次数据的ct是相同的

        if (sigs.length>=committee.length){
            //Combine R
            
            (uint256 Rx, uint256 Ry, uint256 z) = combineSignatures(sigs);

            if (verify(ct, Rx, Ry, z)){
                //return(data,sigvc,a1,a2,ts,Rx,Ry,z);
                storeM2Data(generateIKey(a1a2, meta), data, ct, sigvc, a1a2, ts, Rx,Ry, z,dp);
                emit ats_success(generateIKey(a1a2, meta));
            }
            else {
                revert("OPS");
            }
        }
    }

    function storeM2Data(bytes32 key, bytes memory data, string memory ct, bytes memory sigvc, string memory a1a2, uint256 ts, uint256 Rx, uint256 Ry, uint256 z,string memory dp) private {
        m2 memory newM2 = m2({
            data: data,
            ct: ct,
            sigvc: sigvc,
            a1a2: a1a2,
            ts: ts,
            Rx: Rx,
            Ry: Ry,
            z: z,
            dp:dp
        });
        Index_m2data[key].push(newM2);
    }


    function combineSignatures(SigATS[] memory sigs) private pure returns (uint256 Rx, uint256 Ry, uint256 z) {
        Rx = sigs[0].Rix;
        Ry = sigs[0].Riy;
        for (uint i = 1; i < sigs.length; i++) {
            (Rx, Ry) = EllipticCurve.ecAdd(Rx, Ry, sigs[i].Rix, sigs[i].Riy, AA, PP);
        }

        for (uint i = 0; i < sigs.length; i++) {
            z = addmod(z, sigs[i].zi, NN);
        }
}

    function getm2(bytes32 key) public view returns(m2 memory){
        uint256 length=Index_m2data[key].length;
        return Index_m2data[key][length-1];
    }


    function verify(string memory message,uint256 Rx,uint256 Ry,uint256 z) public view returns  (bool) {
        uint256 c = computec(message,Rx,Ry);
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
        (p2x,p2y) = EllipticCurve.ecAdd(pkcmcx, pkcmcy, Rx,Ry , AA, PP);
        return p1x==p2x && p1y==p2y;
    }


    function getAllSignerList() public view returns (string[] memory) {
        return all_signer_list;
    }


    function computec(string memory message,uint256 Rx,uint256 Ry) public view returns (uint256) {
        bytes memory concatenatedPks;
        concatenatedPks=abi.encodePacked(committee.length);

        for (uint256 i = 0; i < all_signer_list.length; i++) {
            concatenatedPks = abi.encodePacked(concatenatedPks, pks[stringToBytes32(all_signer_list[i])].x,pks[stringToBytes32(all_signer_list[i])].y);
        }

        concatenatedPks=abi.encodePacked(concatenatedPks,Rx,Ry);
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
    

    function combinepk() public view returns(uint256,uint256){
        point memory temppk=pks[stringToBytes32(committee[0])];

        uint256 temppkx=temppk.x;
        uint256 temppky=temppk.y;
        for(uint i=1;i<committee.length;i++){
            (temppkx,temppky)=EllipticCurve.ecAdd(temppkx, temppky,pks[stringToBytes32(committee[i])].x,pks[stringToBytes32(committee[i])].y, AA, PP);
            
        }
        return (temppkx,temppky);
    }

    // function respond0(string memory meta, string memory a1a2) public view returns(bytes[] memory, string[] memory,uint128[][] memory) {
        
    //     bytes32 key = generateIKey(a1a2, meta);
    //     m2[] memory m2searched = Index_m2data[key];
        
    //     // 初始化二维数组
    //     uint128[][] memory rvalue = new uint128[][](m2searched.length);
    //     string[] memory dps=new string[](m2searched.length);
    //     bytes[] memory sigvc=new bytes[](m2searched.length);
    //     for(uint i = 0; i < m2searched.length; i++) {
    //         // 解码每个 m2 数据
    //         uint128[] memory numbers = abi.decode(m2searched[i].data, (uint128[]));
            
    //         // 为 rvalue[i] 分配内存并复制数据
    //         rvalue[i] = new uint128[](numbers.length);
    //         for(uint j = 0; j < numbers.length; j++) {
    //             rvalue[i][j] = numbers[j];
    //         }
    //         dps[i]=m2searched[i].dp;
    //         sigvc[i]=m2searched[i].sigvc;
    //     }
        
    //     return (sigvc,dps,rvalue);
    // }
    function respond0(string memory meta, string memory a1a2, uint256 index) public view returns(bytes memory, string memory, uint128[] memory) {
        bytes32 key = generateIKey(a1a2, meta);
        m2[] memory m2searched = Index_m2data[key];

        require(index < m2searched.length, "Index out of bounds");

        // 获取指定索引的数据
        uint128[] memory numbers = abi.decode(m2searched[index].data, (uint128[]));
        
        // 返回单个数据
        return (m2searched[index].sigvc, m2searched[index].dp, numbers);
    }

    function respond1(string memory uuid, string memory meta, string memory a1a2) public view returns(bytes memory){
        bytes32 key = generateIKey(a1a2, meta);
        m2[] memory m2searched = Index_m2data[key];
        require(m2searched.length > 0, "No data found for the given key");
        return m2searched[0].data;
    }

    function callSign(
        uint128[] memory xArray,
        uint128[] memory labsArray,
        bytes memory sk,
        bytes memory pk
    ) public view returns (bytes memory sigs) {
        // ABI encode the input parameters
        bytes memory input = abi.encode(xArray, labsArray, sk, pk);

        bytes memory output;

        assembly {
            let inputPtr := add(input, 0x20)
            let inputSize := mload(input)

            let success := staticcall(
                gas(),                // Pass the remaining gas
                0x11,   // Address of the precompiled contract
                inputPtr,             // Input data location
                inputSize,            // Input data size
                0,                    // Output data location (temporarily set to 0)
                0                     // Output data size (temporarily set to 0)
            )

            let size := returndatasize()
            output := mload(0x40)   // Allocate output buffer
            mstore(0x40, add(output, add(size, 0x20))) // Update free memory pointer
            mstore(output, size)    // Store the size of the output

            returndatacopy(add(output, 0x20), 0, size) // Copy the returned data

            // Check if the call was successful
            if iszero(success) {
                revert(0, 0)
            }
        }
        sigs=abi.decode(output, (bytes));
        return sigs;
    }

    function callEval(
        uint128[] memory xArray,
        uint128[] memory labsArray,
        bytes memory pk,
        bytes memory sigs,
        int func
    ) public view returns (bytes memory vk_r, bytes memory proof, int computedValue) {
        // ABI encode the input parameters
        bytes memory input = abi.encode(xArray, labsArray, pk, sigs, func);
        bytes memory output;
        bool success;

        assembly {
            let inputPtr := add(input, 0x20)
            let inputSize := mload(input)

            success := staticcall(
                gas(),                // Forward all available gas
                0x12,   // Address of the precompiled contract
                inputPtr,             // Input data location
                inputSize,            // Input data size
                0,                    // Output data location (temporarily set to 0)
                0                     // Output data size (temporarily set to 0)
            )

            let size := returndatasize()
            output := mload(0x40)  // Allocate memory for output
            mstore(0x40, add(output, add(size, 0x20))) // Update free memory pointer
            mstore(output, size)   // Store size of the output

            returndatacopy(add(output, 0x20), 0, size) // Copy the returned data
        }

        require(success, "Precompiled call failed");

        // Decode the output
        (vk_r, proof, computedValue) = abi.decode(output, (bytes, bytes, int));
    }

    function callGenWk() public view returns (bytes memory wk){
        bytes memory output;
        bool success;

        assembly {
            // 由于没有输入参数，我们不需要准备输入数据

            success := staticcall(
                gas(),                // 转发所有可用的 gas
                0x15, // 预编译合约的地址
                0,                    // 输入数据位置（无输入，所以为0）
                0,                    // 输入数据大小（无输入，所以为0）
                0,                    // 输出数据位置（暂时设为0）
                0                     // 输出数据大小（暂时设为0）
            )

            let size := returndatasize()
            output := mload(0x40)  // 为输出分配内存
            mstore(0x40, add(output, add(size, 0x20))) // 更新空闲内存指针
            mstore(output, size)   // 存储输出的大小

            returndatacopy(add(output, 0x20), 0, size) // 复制返回的数据
        }

        require(success, "Precompiled call failed");

        wk = abi.decode(output, (bytes));
    }
    
    function callEmb(
        bytes memory content,
        bytes memory input_image,
        bytes memory output_image,
        bytes memory wk
    ) public view returns (int result) {
        // ABI encode the input parameters
        bytes memory input = abi.encode(content, input_image, output_image, wk);
        bytes memory output;
        bool success;

        assembly {
            let inputPtr := add(input, 0x20)
            let inputSize := mload(input)

            success := staticcall(
                gas(),                // Forward all available gas
                0x13,   // Address of the precompiled contract
                inputPtr,             // Input data location
                inputSize,            // Input data size
                0,                    // Output data location (temporarily set to 0)
                0                     // Output data size (temporarily set to 0)
            )

            let size := returndatasize()
            output := mload(0x40)  // Allocate memory for output
            mstore(0x40, add(output, add(size, 0x20))) // Update free memory pointer
            mstore(output, size)   // Store size of the output

            returndatacopy(add(output, 0x20), 0, size) // Copy the returned data
        }

        require(success, "Precompiled call failed");

        // Decode the output
        result = abi.decode(output, (int));
    }

    function callExt(
        bytes memory output_image,
        bytes memory wk
    ) public view returns (bytes memory result) {
        // ABI encode the input parameters
        bytes memory input = abi.encode(output_image, wk);
        bytes memory output;
        bool success;

        assembly {
            let inputPtr := add(input, 0x20)
            let inputSize := mload(input)

            success := staticcall(
                gas(),                // Forward all available gas
                0x14,   // Address of the precompiled contract
                inputPtr,             // Input data location
                inputSize,            // Input data size
                0,                    // Output data location (temporarily set to 0)
                0                     // Output data size (temporarily set to 0)
            )

            let size := returndatasize()
            output := mload(0x40)  // Allocate memory for output
            mstore(0x40, add(output, add(size, 0x20))) // Update free memory pointer
            mstore(output, size)   // Store size of the output

            returndatacopy(add(output, 0x20), 0, size) // Copy the returned data
        }

        require(success, "Precompiled call failed");

        // Decode the output
        result = abi.decode(output, (bytes));
    }
}