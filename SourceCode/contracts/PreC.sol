// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

/**
 ** @title Elliptic Curve Library
 ** @dev Library providing arithmetic operations over elliptic curves.
 ** This library does not check whether the inserted points belong to the curve
 ** `isOnCurve` function should be used by the library user to check the aforementioned statement.
 ** @author Witnet Foundation
 */
library PreC {
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

