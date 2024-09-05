// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract PrecompiledVC {
    
    function callSign(
        uint128[] calldata xArray,
        uint128[] calldata labsArray,
        bytes calldata sk,
        bytes calldata pk
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
        uint128[] calldata xArray,
        uint128[] calldata labsArray,
        bytes calldata pk,
        bytes calldata sigs,
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


}