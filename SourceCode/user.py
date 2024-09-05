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
from wk_evm.custom_precompiled.custom_vc import Setup,Sign,int_list_to_u128_array,VerSig
from requests.exceptions import JSONDecodeError

import solcx
import sha3
import base64
import config
import argparse
import time
import uuid

def gen_RSA_keypair():
        private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend())
        public_key = private_key.public_key()

        private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
        public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
        
        return private_key,public_key,private_pem,public_pem

def check_attest():
    return True

if __name__=="__main__":
    SAVING_PATH="./LocalStorage/user_storage/"
    """
    Setup to oracle1
    """
    sk_du,pk_du,sk_pem,pk_pem=gen_RSA_keypair()
    user_name="du1"
    oracle_name="oracle1"
    test_host = config.ORACLE_SETTINGS['oracle_hosts'][oracle_name]
    test_port = config.ORACLE_SETTINGS['oracle_ports'][oracle_name]
    test_url = f"http://{test_host}:{test_port}"
    proxy_url=config.PROXY_SETTINGS["proxy_url"]

    ENCLAVE_KEY_PATH=config.ENCLAVE_SETTINGS["publicKey"]
    enclave_pk=read_rsapk_from_pem(ENCLAVE_KEY_PATH)

    response=requests.post(f"{test_url}/du_register")
    response=response.json()
    cred=response["cred"]
    pid=response["pid"]
    print(pid)
    sig_pid=response["sig_pid"]

    #print(cred,pid,sig_pid)
    timestamp=int(time.time())
    
    assert check_attest(),"Attestation Failed"

    w3 = Web3(Web3.HTTPProvider('http://127.0.0.1:8545'))
    default_account = w3.eth.accounts[0]
    with open('/home/oracle/contracts/cbc.sol', 'r') as file:
            contract_source_code = file.read()
    solcx.install_solc('0.8.0')
    solcx.set_solc_version('0.8.0')
    compiled_sol = compile_source(contract_source_code)
    contract_interface = compiled_sol['<stdin>:CBC']
    
    response=requests.post(f"{proxy_url}/get_cbc_address")
    resdata=response.json()
    contract_address=resdata["address"]
    print(contract_address)
    contract = w3.eth.contract(address=contract_address, abi=contract_interface['abi'])
    


    #Data to send
    m3_0={"a1a2": "com,pub","f":2,"pk_du":base64.b64encode(pk_pem).decode('utf-8'),"cred":cred,"timestamp": timestamp,"metadata": "404HospitalData"} #请求可计算数据

    m3_1={"a1a2": "com,pub","pid":pid,"sig_pid":sig_pid,"pk_du":base64.b64encode(pk_pem).decode('utf-8'),"cred":cred,"timestamp": timestamp,"metadata": "PhotoofHFUT"} #请求图片数据

    m3b=m3_0

    du_uuid=str(uuid.uuid4())
    json_message = json.dumps(m3b)
    ct = encrypt_message(enclave_pk, json_message,0)
    #{'b': 1, 'data':data,'sigvc':"","a1a2":"com,pub","timestamp":timestamp,"metadata":"PhotoofHFUT","dp":dp_name}
    """
    Send TxReq to Cbc
    这里应该依靠proxy对Cbc的监听触发proxy的request，目前没接入cbc所以该条消息由du直接发给proxy进行触发，uuid也是本地产生
    """
    

    user_hash=w3.keccak(text=ct)
    # 使用默认账户签名消息
    signature = w3.eth.sign(default_account, user_hash)
    # 调整签名格式
    v = w3.to_int(signature[-1])
    if v < 27:
        v += 27
    r = signature[:32]
    s = signature[32:64]
    adjusted_signature = r + s + bytes([v])

    transaction = contract.functions.request(ct,user_hash,adjusted_signature,default_account).transact({
        'from': default_account,
        'gas': 3000000,  # 指定 Gas 限额
        'gasPrice': w3.to_wei('20', 'gwei')  # 指定 Gas 价格
    })
    receipt = w3.eth.wait_for_transaction_receipt(transaction)
    #print(receipt)

    response=requests.post(f"{proxy_url}/data_request",json={"uuid":du_uuid,"ct":ct}) #simulation
    
    try:
        resdata = response.json()  # 尝试解析 JSON 响应
        print("JSON data:", resdata)
    except JSONDecodeError:
        print()
        print("No data searched")
        exit(0)
    
    if "f" in m3b: #可计算数据
        comresult_str=decrypt_message(sk_du,resdata["ct"])
        comresult=json.loads(comresult_str)
        #print(comresult)
        value=int(comresult["value"])
        proof=comresult["proof"].encode("utf-8")
        vk_r=comresult["vk_r"].encode("utf-8")
        labs=comresult["labs"]
        print(value,proof,vk_r,labs)
        
        assert VerSig(vk_r,int_list_to_u128_array(labs),value,proof)

    else: #图片数据
        image_b64=decrypt_message(sk_du,resdata["ct"])
        h = sha3.keccak_256()
        h.update(image_b64.encode("utf-8"))
        store_key=h.hexdigest() #也就是图片的hash
        input_data=store_key.encode("utf-8")#本地存储
        #先存，如果失败了再删
        base64_to_image(image_b64, f"{SAVING_PATH}/{store_key}.jpg")
