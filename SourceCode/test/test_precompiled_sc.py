# """
# 测试给EVM增加预编译合约
# """
# from typing import (
#     Type,
# )
# from eth_tester import EthereumTester, PyEVMBackend
# from eth.vm.forks.london import LondonVM
# from web3 import Web3, EthereumTesterProvider
# from eth.abc import (
#     ComputationAPI,
# )
# from eth_utils.toolz import (
#     merge,
# )
# from eth._utils.address import (
#     force_bytes_to_address,
# )
# from eth.vm.forks.london.computation import (
#     LondonComputation
# )
# from eth.vm.forks.london.state import(
#     LondonState
# )
# from eth.vm.forks.berlin.computation import(
#     BERLIN_PRECOMPILES
# )
# from eth.vm.forks import (
#     LondonVM,
# )
# from eth.vm.state import BaseState
# from web3 import Web3, EthereumTesterProvider
# from eth_utils import keccak
# from eth_abi import decode,encode
# import solcx
# from solcx import compile_source


# def custom_precompile(computation: ComputationAPI) -> ComputationAPI:
#     # Get the input data from the computation
#     input_data = computation.msg.data_as_bytes
#     # Decode the input data
#     param1, param2 = decode(['bytes', 'bytes'], input_data)

#     print(f"Received param1: {param1.decode()}, param2: {param2.decode()}")

#     # Compute the hash
#     result = keccak(param1 + param2)
#     # Encode the result
#     output = encode(['bytes32'], [result])
#     # Set the output and return
#     computation.output = output

# CUSTOM_PRECOMPILES = merge(
#     BERLIN_PRECOMPILES,
#     {
#         force_bytes_to_address(b"\x10"): custom_precompile,
#     },
# )

# class CustomComputation(LondonComputation):
#     _precompiles = CUSTOM_PRECOMPILES

# class CustomState(LondonState):
#     computation_class = CustomComputation

# class CustomVM(LondonVM):
#     _state_class: Type[BaseState] = CustomState


# if __name__=="__main__":
#     custom_backend = PyEVMBackend(vm_configuration=[(0, CustomVM)])
#     eth_tester = EthereumTester(backend=custom_backend)
#     w3 = Web3(EthereumTesterProvider(eth_tester))

#     solcx.install_solc('0.8.0')
#     solcx.set_solc_version('0.8.0')
#     with open('./contracts/test_prec.sol', 'r') as file:
#         source_code = file.read()
#     compiled_sol = compile_source(source_code)
#     contract_interface = compiled_sol['<stdin>:PrecompiledHasher']

    
#     # Deploy contract
#     TestPreC = w3.eth.contract(abi=contract_interface['abi'], bytecode=contract_interface['bin'])
#     tx_hash = TestPreC.constructor().transact()
#     tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
#     contract_address = tx_receipt.contractAddress

#     # Create contract instance
#     contract_instance = w3.eth.contract(address=contract_address, abi=contract_interface['abi'])

#     #Call
#     result = contract_instance.functions.calculateHash(b'hello',b'world').call()
#     #tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
#     print("Call from sol",type(result),result.hex())


#     address = force_bytes_to_address(b"\x10")
#     param1 = b'hello'
#     param2 = b'world'
#     encoded_params = encode(['bytes', 'bytes'], [param1, param2])

#     output = w3.eth.call({
#     'to': address,
#     'data': encoded_params
#     })
#     print("Call from local",type(output),output.hex()) 