from web3 import Web3
from solcx import compile_source
import solcx
import sha3
from eth_abi import decode,encode
from wkutils.utils import *

with open('/home/oracle/contracts/cbc.sol', 'r', encoding='utf-8') as file:
             contract_source_code = file.read()
# 编译合约
solcx.install_solc('0.8.0')
solcx.set_solc_version('0.8.0')
compiled_sol = compile_source(contract_source_code)
contract_interface = compiled_sol['<stdin>:CBC']

# 连接到本地 Geth 节点
w3 = Web3(Web3.HTTPProvider('http://127.0.0.1:8545'))

# 确保连接成功
if not w3.is_connected():
    raise Exception("Failed to connect to Ethereum node")

# 获取默认账户
default_account = w3.eth.accounts[0]

# 部署合约
SignatureVerifier = w3.eth.contract(abi=contract_interface['abi'], bytecode=contract_interface['bin'])
tx_hash = SignatureVerifier.constructor().transact({'from': default_account})
tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
contract_address = tx_receipt.contractAddress

# 创建合约实例
contract = w3.eth.contract(address=contract_address, abi=contract_interface['abi'])

# 验证签名




sk_sige = secrets.randbelow(order) #sk^sig_e
pk_sige = generator * sk_sige #pk^sig_e

h = sha3.keccak_256()
h.update("Hello".encode("utf-8"))
success_message = h.digest().hex() #m
            

h = sha3.keccak_256()
r=secrets.randbelow(order)
R= generator * r
h.update(point_to_bytes(pk_sige)) #H(pk,R,m)
h.update(point_to_bytes(R))
h.update(success_message.encode("utf-8"))


c = int.from_bytes(h.digest(), byteorder='big') % order
z = (r+ c * sk_sige) % order

proxy_hash=w3.keccak(text=success_message)

# 使用默认账户签名消息
signature = w3.eth.sign(default_account, proxy_hash)
# 调整签名格式
v = w3.to_int(signature[-1])
if v < 27:
    v += 27
r = signature[:32]
s = signature[32:64]
adjusted_signature = r + s + bytes([v])

transaction = contract.functions.collect(pk_sige.x(),pk_sige.y(),R.x(),R.y(),z,success_message, proxy_hash, adjusted_signature, default_account).transact({
    'from': default_account,
    'gas': 3000000,  # 指定 Gas 限额
    'gasPrice': w3.to_wei('20', 'gwei')  # 指定 Gas 价格
})

receipt = w3.eth.wait_for_transaction_receipt(transaction)
print(receipt)