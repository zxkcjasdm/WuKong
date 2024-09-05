from web3 import Web3
from solcx import compile_source
import solcx
from eth_tester import EthereumTester, PyEVMBackend
from web3.providers.eth_tester import EthereumTesterProvider
from ecdsa import SECP256k1, ellipticcurve
import secrets


curve = SECP256k1.curve
generator = SECP256k1.generator
order = generator.order()


# Install specific version of solc
solcx.install_solc('0.8.0')

# Set the installed version of solc
solcx.set_solc_version('0.8.0')

# Compile Solidity source code
with open('../contracts/cpsc.sol', 'r') as file:
    source_code = file.read()

compiled_sol = compile_source(source_code)
contract_interface = compiled_sol['<stdin>:Secp256k1']

# Setup web3 with eth-tester
eth_tester = EthereumTester(backend=PyEVMBackend())
w3 = Web3(EthereumTesterProvider(eth_tester))

# Set pre-funded account as sender
w3.eth.default_account = w3.eth.accounts[0]

# Deploy contract
Secp256k1 = w3.eth.contract(abi=contract_interface['abi'], bytecode=contract_interface['bin'])
tx_hash = Secp256k1.constructor().transact()
tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
contract_address = tx_receipt.contractAddress

# Create contract instance
contract_instance = w3.eth.contract(address=contract_address, abi=contract_interface['abi'])

# Test the contract

curve = SECP256k1.curve
generator = SECP256k1.generator
order = generator.order()
sk = secrets.randbelow(order)
pk = sk*generator

result = contract_instance.functions.derivePubKey(sk).call()
x_c, y_c = result

print(f"Public key computed by sc: X = {x_c}, Y = {y_c}")
print(f"Public key computed locally = {pk.x()}, Y = {pk.y()}")
# 获取结果
# Call addGAndPoint function
# tx_hash = contract_instance.functions.derivePubKey(sk).transact({'from': w3.eth.default_account, 'gas': 3000000})
# tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)

