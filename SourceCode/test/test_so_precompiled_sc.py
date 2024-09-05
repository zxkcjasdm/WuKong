from eth_tester import EthereumTester, PyEVMBackend

from web3 import Web3, EthereumTesterProvider

from web3 import Web3, EthereumTesterProvider
from eth_abi import decode,encode
import solcx
from solcx import compile_source
from eth._utils.address import (
    force_bytes_to_address,
)
from wk_evm.WK_EVM import WK_EVM
"""
用于测试rust实现的函数编译为so格式lib，通过python提供接口实现evm预编译合约
"""

# 测试函数
if __name__=="__main__":
    custom_backend = PyEVMBackend(vm_configuration=[(0, WK_EVM)])
    eth_tester = EthereumTester(backend=custom_backend)
    w3 = Web3(EthereumTesterProvider(eth_tester))

    solcx.install_solc('0.8.0')
    solcx.set_solc_version('0.8.0')
    with open('./contracts/test_prec.sol', 'r') as file:
        source_code = file.read()
    compiled_sol = compile_source(source_code)
    contract_interface = compiled_sol['<stdin>:PrecompiledHasher']

    
    # Deploy contract
    TestPreC = w3.eth.contract(abi=contract_interface['abi'], bytecode=contract_interface['bin'])
    tx_hash = TestPreC.constructor().transact()
    tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    contract_address = tx_receipt.contractAddress

    # Create contract instance
    contract_instance = w3.eth.contract(address=contract_address, abi=contract_interface['abi'])




    param1 = b'Hefllo'*100*1024
    param2 = b'Worsdfld'
    #Call
    result = contract_instance.functions.calculateHash(param1,param2).call()
    #tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    print("Call from sol",type(result),result.hex())


    address = force_bytes_to_address(b"\x10")

    encoded_params = encode(['bytes', 'bytes'], [param1, param2])

    output = w3.eth.call({
    'to': address,
    'data': encoded_params
    })
    print("Call from local",type(output.hex()),output.hex()) 