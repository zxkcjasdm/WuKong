import requests
import json
import hashlib
import secrets
import random
from flask import Flask, request, jsonify
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from ecdsa import SECP256k1, ellipticcurve
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from wkutils.utils import *
from web3 import Web3
from solcx import compile_source
import solcx


import base64
import config
import argparse
import time
import sha3


app = Flask(__name__)

curve = SECP256k1.curve
generator = SECP256k1.generator
order = generator.order()

#Proxy分别验证多个Oi的签名，转发给Encalve，最终合约做聚合操作
class Proxy:
    def __init__(self, t, combiner_url, enclave_url):
        self.t=t
        self.combiner_url=combiner_url
        self.enclave_url=enclave_url
        self.pk_dict=None
        self.R=None
        self.get_pkdict()
        self.init_bc()

    def get_pkdict(self):
        if not self.pk_dict:
            while True:
                response=requests.post(f"{self.combiner_url}/get_pkdict")
                code = response.status_code
                if code==200:
                    break
                elif code==204:
                    print(code,"Waitting for pk_dict")
                time.sleep(1) 
            pk_dict_serialized = response.json()
            pk_dict = {name: bytes_to_point(bytes.fromhex(pk_hex)) for name, pk_hex in pk_dict_serialized.items()}
            self.pk_dict=pk_dict

    def get_R(self):
        if not self.R:
            while True:
                response=requests.post(f"{self.combiner_url}/get_R")
                code = response.status_code
                if code==200:
                    break
                elif code==204:
                    print(code,"Waitting for R")
                time.sleep(1) 
            R=bytes_to_point(bytes.fromhex(response.json()["R"]))
            self.R=R
        return self.R

    def init_bc(self):
        with open('/home/oracle/contracts/cbc.sol', 'r') as file:
            contract_source_code = file.read()
        solcx.install_solc('0.8.0')
        solcx.set_solc_version('0.8.0')
        compiled_sol = compile_source(contract_source_code)
        contract_interface = compiled_sol['<stdin>:CBC']

        # 连接到本地 Geth 节点
        self.w3 = Web3(Web3.HTTPProvider('http://127.0.0.1:8545'))

        # 确保连接成功
        if not self.w3.is_connected():
            raise Exception("Failed to connect to Ethereum node")

        # 获取默认账户
        self.default_account = self.w3.eth.accounts[0]

        # 部署合约
        CBC = self.w3.eth.contract(abi=contract_interface['abi'], bytecode=contract_interface['bin'])
        tx_hash = CBC.constructor().transact({'from': self.default_account})
        tx_receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
        self.contract_address = tx_receipt.contractAddress


        # 创建合约实例
        self.contract = self.w3.eth.contract(address=self.contract_address, abi=contract_interface['abi'])

@app.route("/get_cbc_address", methods=["POST"])
def get_cbc_address():
    return jsonify({"status":"succeed","address": proxy.contract_address}),200



@app.route('/data_collect', methods=['POST']) #
def data_collect():
    start_time = time.perf_counter()
    data = request.json
    oraclename = data["oraclename"]
    message =data["ciphertext"]

    h = sha3.keccak_256()
    h.update(oraclename.encode("utf-8"))
    h.update(data["Ri"].encode("utf-8"))
    h.update(data['zi'].encode("utf-8"))
    h.update(message.encode("utf-8"))

    b64pk = data["public_key"]
    pem_pk = base64.b64decode(b64pk).decode("utf-8")
    public_key=serialization.load_pem_public_key(pem_pk.encode("utf-8"))# oracle的公钥


    assert verify_signature_with_hash(public_key, h.digest(), data["signature_i"])

    end_time = time.perf_counter()
    execution_time = end_time - start_time
    print(f"Proxy Data Collect part 1 executed in {execution_time:.4f} seconds")
    json_data={"Ri":data["Ri"],"zi":data["zi"],"oraclename":oraclename,"ciphertext":message}


    json_str = json.dumps(json_data)

    # 计算JSON字符串的字节长度
    byte_length = len(json_str.encode('utf-8'))

    # 将字节数转换为KB
    kb_size = byte_length / 1024

    print(f"Proxy Data Collect Communication size: {kb_size:.2f} KB")


    response=requests.post(f"{proxy.enclave_url}/preprocess",json=json_data)
    resdata=response.json()
    print(response.text)
    if resdata['status']=='ATS succeed': #transact with BC Collection"
        start_time = time.perf_counter()
        message = resdata["m"]
        R = bytes_to_point(bytes.fromhex(resdata['R']))
        z = int(resdata['z'])
        pk = bytes_to_point(bytes.fromhex(resdata['pk']))
        proxy_hash=proxy.w3.keccak(text=message)

        signature = proxy.w3.eth.sign(proxy.default_account, proxy_hash)
        v = proxy.w3.to_int(signature[-1])
        if v < 27:
            v += 27
        r = signature[:32]
        s = signature[32:64]
        adjusted_signature = r + s + bytes([v])


        end_time = time.perf_counter()
        execution_time = end_time - start_time
        print(f"Proxy Data Collect part 2 executed in {execution_time:.4f} seconds")


        start_time = time.perf_counter()
        transaction = proxy.contract.functions.collect(pk.x(),pk.y(),R.x(),R.y(),z,message, proxy_hash, adjusted_signature, proxy.default_account).transact({
            'from': proxy.default_account,
            'gas': 3000000,  # 指定 Gas 限额
            'gasPrice': proxy.w3.to_wei('20', 'gwei')  # 指定 Gas 价格
        })
        receipt = proxy.w3.eth.wait_for_transaction_receipt(transaction)

        print(f"Txcol used {receipt.gasUsed} gas.")

        end_time = time.perf_counter()
        execution_time = end_time - start_time
        print(f"Blockchain Collect executed in {execution_time:.4f} seconds")


        transaction_details = proxy.w3.eth.get_transaction(transaction)

        # 获取交易数据的大小（以字节计数）
        transaction_data_size = len(transaction_details['input'])/1024 

        print(f"Blockchain Data Collect Transaction size: {transaction_data_size:.2f} KB")

        #print(receipt)

    return jsonify({"status":"Verification succeed"}),200


@app.route('/data_trace', methods=['POST']) #
def data_trace():
    start_time=time.perf_counter()
    data = request.json
    json_str = json.dumps(data)
    # 计算JSON字符串的字节长度
    byte_length = len(json_str.encode('utf-8'))
    # 将字节数转换为KB
    kb_size = byte_length / 1024
    print(f"Proxy Data Trace Communication size(input): {kb_size:.2f} KB")


    oraclename = data["oraclename"]
    message =data["ciphertext"]

    h = sha3.keccak_256()
    h.update(oraclename.encode("utf-8"))
    h.update(data["Ri"].encode("utf-8"))
    h.update(data['zi'].encode("utf-8"))
    h.update(message.encode("utf-8"))

    b64pk = data["public_key"]
    pem_pk = base64.b64decode(b64pk).decode("utf-8")
    public_key=serialization.load_pem_public_key(pem_pk.encode("utf-8"))# oracle的公钥
    end_time=time.perf_counter()
    execution_time = end_time - start_time
    print(f"Proxy Data Trace part 1 executed in {execution_time:.4f} seconds")
    assert verify_signature_with_hash(public_key, h.digest(), data["signature_i"])


    response=requests.post(f"{proxy.enclave_url}/preprocess",json={"Ri":data["Ri"],"zi":data["zi"],
                                                                   "oraclename":oraclename,"ciphertext":message})
    resdata=response.json()
    json_str = json.dumps(resdata)
    # 计算JSON字符串的字节长度
    byte_length = len(json_str.encode('utf-8'))
    # 将字节数转换为KB
    kb_size = byte_length / 1024
    print(f"Proxy Data Trace Communication size(From E): {kb_size:.2f} KB")


    if resdata['status']=='Trace succeed': #transact with BC Collection"
        start_time=time.perf_counter()
        message = resdata["m"]
        R = bytes_to_point(bytes.fromhex(resdata['R']))
        z = int(resdata['z'])
        pk = bytes_to_point(bytes.fromhex(resdata['pk']))
        proxy_hash=proxy.w3.keccak(text=message)

        signature = proxy.w3.eth.sign(proxy.default_account, proxy_hash)
        v = proxy.w3.to_int(signature[-1])
        if v < 27:
            v += 27
        r = signature[:32]
        s = signature[32:64]
        adjusted_signature = r + s + bytes([v])
        end_time = time.perf_counter()
        execution_time = end_time - start_time
        print(f"Proxy Data Trace part 2 executed in {execution_time:.4f} seconds")

        start_time=time.perf_counter()
        transaction = proxy.contract.functions.trace(pk.x(),pk.y(),R.x(),R.y(),z,message, proxy_hash, adjusted_signature, proxy.default_account).transact({
            'from': proxy.default_account,
            'gas': 3000000,  # 指定 Gas 限额
            'gasPrice': proxy.w3.to_wei('20', 'gwei')  # 指定 Gas 价格
        })

        receipt = proxy.w3.eth.wait_for_transaction_receipt(transaction)
        print(f"Txtra used {receipt.gasUsed} gas.")

        #print(receipt)
        end_time = time.perf_counter()
        execution_time = end_time - start_time
        print(f"Blockchain Trace executed in {execution_time:.4f} seconds")


        transaction_details = proxy.w3.eth.get_transaction(transaction)

        # 获取交易数据的大小（以字节计数）
        transaction_data_size = len(transaction_details['input'])/1024 

        print(f"Blockchain Data Trace Transaction size: {transaction_data_size:.2f} KB")


    return jsonify({"status":"Verification succeed"}),200


@app.route('/data_request', methods=['POST']) #
def data_request():
    start_time=time.perf_counter()
    data = request.json
    json_str = json.dumps(data)
    # 计算JSON字符串的字节长度
    byte_length = len(json_str.encode('utf-8'))
    # 将字节数转换为KB
    kb_size = byte_length / 1024
    print(f"Proxy Data Request Communication size(input): {kb_size:.2f} KB")

    response=requests.post(f"{proxy.enclave_url}/respond",json=data)
    resdata=response.json()

    json_str = json.dumps(resdata)
    # 计算JSON字符串的字节长度
    byte_length = len(json_str.encode('utf-8'))
    # 将字节数转换为KB
    kb_size = byte_length / 1024
    print(f"Proxy Data Request Communication size(From E): {kb_size:.2f} KB")
    
    
    if resdata['status']=="Computation succeed":
        start_time=time.perf_counter()

        cth = resdata["m"]
        R = bytes_to_point(bytes.fromhex(resdata['R']))
        z = int(resdata['z'])
        pk = bytes_to_point(bytes.fromhex(resdata['pk']))
        proxy_hash=proxy.w3.keccak(text=cth)

        signature = proxy.w3.eth.sign(proxy.default_account, proxy_hash)
        v = proxy.w3.to_int(signature[-1])
        if v < 27:
            v += 27
        r = signature[:32]
        s = signature[32:64]
        adjusted_signature = r + s + bytes([v])
        end_time=time.perf_counter()
        execution_time=end_time-start_time
        print(f"Proxy Data Request part executed in {execution_time:.4f} seconds")

        start_time=time.perf_counter()
        transaction = proxy.contract.functions.respond(pk.x(),pk.y(),R.x(),R.y(),z,cth,proxy.w3.keccak(text=resdata["uuid"]), proxy_hash, adjusted_signature, proxy.default_account).transact({
            'from': proxy.default_account,
            'gas': 3000000,  # 指定 Gas 限额
            'gasPrice': proxy.w3.to_wei('20', 'gwei')  # 指定 Gas 价格
        })

        receipt = proxy.w3.eth.wait_for_transaction_receipt(transaction)

        print(f"Txres used {receipt.gasUsed} gas.")
        #print(receipt)
        end_time=time.perf_counter()
        execution_time=end_time-start_time
        print(f"BC Data Request executed in {execution_time:.4f} seconds")

        transaction_details = proxy.w3.eth.get_transaction(transaction)

        # 获取交易数据的大小（以字节计数）
        transaction_data_size = len(transaction_details['input'])/1024 

        print(f"Blockchain Data Request Transaction size: {transaction_data_size:.2f} KB")

    return jsonify({"status":"request succeed","ct":resdata["ct"]}),200

@app.route("/dp_setupvc",methods=['POST'])
def dp_setupvc():
    data = request.json
    response=requests.post(f"{proxy.enclave_url}/dp_setupvc",json=data)

    return jsonify({"status":"DP setup vc succeed"}),200

if __name__=="__main__":
    global proxy
    t = config.ORACLE_SETTINGS['t']
    combiner_url = config.ORACLE_SETTINGS['combiner_url']
    proxy_host=config.PROXY_SETTINGS["proxy_host"]
    proxy_port=config.PROXY_SETTINGS["proxy_port"]
    enclave_url=config.ENCLAVE_SETTINGS["enclave_url"]
    proxy = Proxy(t,combiner_url,enclave_url)
    app.run(host=proxy_host,port=proxy_port, debug=False,threaded=True)
