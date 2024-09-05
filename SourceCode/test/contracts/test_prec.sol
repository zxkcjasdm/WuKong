// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract PrecompiledVC {
    // 预编译合约的地址
    
    // 调用预编译合约计算两个字节数组的哈希值
    function callSign(
        uint128[] memory xArray,
        uint128[] memory labsArray,
        bytes memory sk,
        bytes memory pk
    ) public view returns (bytes memory) {
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
        return output;
    }



}