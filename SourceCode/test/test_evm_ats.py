import requests
import json
import hashlib
import secrets
import random
import os
import sys
import sha3

wkutils_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '../wkutils'))
if wkutils_path not in sys.path:
    sys.path.append(wkutils_path)
from utils import *

from flask import Flask, request, jsonify
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from ecdsa import SECP256k1, ellipticcurve
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from web3 import Web3
from solcx import compile_source
import solcx
from eth_tester import EthereumTester, PyEVMBackend
from web3.providers.eth_tester import EthereumTesterProvider
from dataclasses import dataclass
import base64
import argparse
import time


curve = SECP256k1.curve
generator = SECP256k1.generator
order = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
infinity = ellipticcurve.INFINITY

if __name__=="__main__":
    solcx.install_solc('0.8.0')
    solcx.set_solc_version('0.8.0')
    with open('../contracts/ats.sol', 'r') as file:
        source_code = file.read()
    compiled_sol = compile_source(source_code)
    contract_interface = compiled_sol['<stdin>:ATS']
    eth_tester = EthereumTester(backend=PyEVMBackend())
    w3 = Web3(EthereumTesterProvider(eth_tester))

    w3.eth.default_account = w3.eth.accounts[0]
    # Deploy contract
    Secp256k1 = w3.eth.contract(abi=contract_interface['abi'], bytecode=contract_interface['bin'])
    tx_hash = Secp256k1.constructor().transact()
    tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    contract_address = tx_receipt.contractAddress
    # Create contract instance
    contract_instance = w3.eth.contract(address=contract_address, abi=contract_interface['abi'])

    t=4
    n=10
    #创建oracle
    class Oracle:
        def __init__(self, name, sk, pk):
            self.name = name
            self.sk = sk
            self.pk = pk

        def __str__(self):
            return f"{self.name}"
        
        def __repr__(self):
            return self.__str__()
    oracles=[]
    for i in range(0,n):
        name=f"oracle{i}"
        sk = secrets.randbelow(order)
        pk = generator * sk
        oracle=Oracle(name=name,sk=sk,pk=pk)
        oracles.append(oracle)
        tx_hash = contract_instance.functions.addsigner(oracle.name,oracle.pk.x(),oracle.pk.y()).transact()
        tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    
    committee = random.sample(oracles, t)

    for com in committee: #注册committee
        tx_hash = contract_instance.functions.register_committee(com.name).transact()
        tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)

    message="test"
    for com in committee: #计算R
        r = secrets.randbelow(order)
        R = r*generator
        com.r=r
        com.R=R
        tx_hash = contract_instance.functions.addRi(com.name,com.R.x(),com.R.y()).transact()
        tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)

    #获取合约聚合的R
    Rx,Ry = contract_instance.functions.getR().call()

    #本地计算的R，用于对比合约计算的R是否正确
    localR = sum((c.R for c in committee), infinity)
    assert(Rx==localR.x() and Ry==localR.y()),"WRONG R"


    #本地计算point_to_bytes和合约的point_to_bytes进行对比
    localb=point_to_bytes_uint(Rx,Ry)
    cb= contract_instance.functions.point_to_bytes_uint(Rx,Ry).call()
    assert(localb.hex()==cb.hex()),"WRONG point_to_bytes method"


    #每个committee中的oracle计算z
    for com in committee:
        h = sha3.keccak_256()
        h.update(uint256_to_bytes(t))
        for o in oracles:
            h.update(point_to_bytes(o.pk))
        h.update(point_to_bytes_uint(Rx,Ry))
        h.update(message.encode("utf-8"))
        c = int.from_bytes(h.digest(), byteorder='big') % order
        com.z=(com.r  + com.sk * c ) % order
        print(f"{com.name} computed z:{com.z}")
        tx_hash = contract_instance.functions.addzi(com.name,com.z).transact({'from': w3.eth.default_account, 'gas': 30000000})
        tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)

    #本地计算z和合约的z进行对比
    sumz=0
    for c in committee:
        sumz =(sumz +c.z)%order
    localz=sumz

    #如果是0，说明z没有被计算，排查发现是uint256溢出，用addmod就可以了
    z= contract_instance.functions.getz().call()
    assert(localz==z),f"WRONG z {localz} while {z}"

    #测试合约verify
    h = sha3.keccak_256()
    h.update(uint256_to_bytes(t))
    for o in oracles:
        h.update(point_to_bytes(o.pk))
    h.update(point_to_bytes_uint(Rx,Ry))
    h.update(message.encode("utf-8"))
    hash_local=h.digest()
    c_sc=contract_instance.functions.computec(message).call()
    c_local = int.from_bytes(h.digest(), byteorder='big') % order
    print("*"*12)
    print(c_sc,c_local)


    pk_C = sum((com.pk for com in committee), ellipticcurve.INFINITY)
    print(f"pk_C*c: {showpoint(pk_C*c_local)}")
    
    result=contract_instance.functions.combinepk().call()
    print(result)
    
    p1 = localz * generator
    p2 = pk_C * c_sc + localR
    print(p1.x(),p1.y(),p2.x(),p2.y())
    result=contract_instance.functions.verify(message).call()
    print(result)
