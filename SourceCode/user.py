from wkutils.utils import *
from web3 import Web3
from solcx import compile_source
from wk_evm.custom_precompiled.custom_vc import Setup,Sign,int_list_to_u128_array,VerSig
from requests.exceptions import JSONDecodeError


import asyncio
import aiohttp
import solcx
import sha3
import base64
import config
import argparse
import time
import uuid

import requests
import json
import hashlib
import base64
import uuid
import time
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.backends import default_backend
from web3 import Web3
from solcx import compile_source


def gen_RSA_keypair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
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
    return private_key, public_key, private_pem, public_pem


def check_attest():
    return True


async def data_request(w3, contract, pk_pem, cred, pid, sig_pid, proxy_url, enclave_pk, sk_du, saving_path, default_account,time_costs):
    total_start_time=time.perf_counter()

    start_time = time.perf_counter()

    timestamp = int(time.time())
    m3_0 = {
        "a1a2": "com,pub",
        "f": 1,
        "pk_du": base64.b64encode(pk_pem).decode('utf-8'),
        "cred": cred,
        "timestamp": timestamp,
        "metadata": "404HospitalData"
    }

    m3_1 = {
        "a1a2": "com,pub",
        "pid": pid,
        "sig_pid": sig_pid,
        "pk_du": base64.b64encode(pk_pem).decode('utf-8'),
        "cred": cred,
        "timestamp": timestamp,
        "metadata": "PhotoofHFUT"
    }

    m3b = m3_0

    du_uuid = str(uuid.uuid4())
    json_message = json.dumps(m3b)
    ct = encrypt_message(enclave_pk, json_message, 0)

    user_hash = w3.keccak(text=ct)
    signature = w3.eth.sign(default_account, user_hash)

    v = w3.to_int(signature[-1])
    if v < 27:
        v += 27
    r = signature[:32]
    s = signature[32:64]
    adjusted_signature = r + s + bytes([v])

    end_time = time.perf_counter()
    execution_time_1 = end_time - start_time
    print(f"User Data Request part 1 executed in {execution_time_1:.4f} seconds")

    start_time = time.perf_counter()

    try:
        transaction = contract.functions.request(
            ct, user_hash, adjusted_signature, default_account
        ).transact({
            'from': default_account,
            'gas': 3000000,
            'gasPrice': w3.to_wei('20', 'gwei')
        })
        receipt = w3.eth.wait_for_transaction_receipt(transaction)

# 打印消耗的 gas
        print(f"Txreq used {receipt.gasUsed} gas.")

        transaction_details = w3.eth.get_transaction(transaction)
        transaction_data_size = len(transaction_details['input']) / 1024
        print(f"Blockchain Data Request Transaction size: {transaction_data_size:.2f} KB")
    except Exception as e:
        print(f"Error during blockchain transaction: {e}")
        return

    end_time = time.perf_counter()
    execution_time = end_time - start_time
    print(f"Blockchain Request executed in {execution_time:.4f} seconds")

    json_data = {"uuid": du_uuid, "ct": ct}

    async with aiohttp.ClientSession() as session:
        try:
            async with session.post(f"{proxy_url}/data_request", json=json_data,timeout=800) as response:
                resdata = await response.json()
                print("Response data: size", len(await response.read()) / 1024, "KB")
        except aiohttp.ClientError as e:
            print(f"Request failed: {e}")
            return
    start_time = time.perf_counter()
    if "f" in m3b:
        comresult_str = decrypt_message(sk_du, resdata["ct"])
        comresult = json.loads(comresult_str)
        value = int(comresult["value"])
        proof = comresult["proof"].encode("utf-8")
        vk_r = comresult["vk_r"].encode("utf-8")
        labs = comresult["labs"]
        print(value, proof, vk_r, labs)
        assert VerSig(vk_r, int_list_to_u128_array(labs), value, proof)

    else:
        image_b64 = decrypt_message(sk_du, resdata["ct"])
        h = hashlib.sha3_256()
        h.update(image_b64.encode("utf-8"))
        store_key = h.hexdigest()
        base64_to_image(image_b64, f"{saving_path}/{store_key}.jpg")

    end_time = time.perf_counter()
    execution_time_2 = end_time - start_time
    print(f"User Data Request part 2 executed in {execution_time_2:.4f} seconds")
    total_end_time=time.perf_counter()
    print(f"User Data Request total time {total_end_time-total_start_time:.4f} seconds")
    time_costs.append(round(total_end_time-total_start_time,4))

async def main():
    SAVING_PATH = "./LocalStorage/user_storage/"
    sk_du, pk_du, sk_pem, pk_pem = gen_RSA_keypair()
    user_name = "du1"
    oracle_name = "oracle1"
    test_host = config.ORACLE_SETTINGS['oracle_hosts'][oracle_name]
    test_port = config.ORACLE_SETTINGS['oracle_ports'][oracle_name]
    test_url = f"http://{test_host}:{test_port}"
    proxy_url = config.PROXY_SETTINGS["proxy_url"]

    ENCLAVE_KEY_PATH = config.ENCLAVE_SETTINGS["publicKey"]
    enclave_pk = read_rsapk_from_pem(ENCLAVE_KEY_PATH)

    response = requests.post(f"{test_url}/du_register")
    response = response.json()
    cred = response["cred"]
    pid = response["pid"]
    sig_pid = response["sig_pid"]

    assert check_attest(), "Attestation Failed"

    w3 = Web3(Web3.HTTPProvider('http://8.149.134.123:8545'))
    default_account = w3.eth.accounts[0]
    with open('/home/oracle/contracts/cbc.sol', 'r') as file:
        contract_source_code = file.read()
    solcx.install_solc('0.8.0')
    solcx.set_solc_version('0.8.0')
    compiled_sol = compile_source(contract_source_code)
    contract_interface = compiled_sol['<stdin>:CBC']

    response = requests.post(f"{proxy_url}/get_cbc_address")
    resdata = response.json()
    contract_address = resdata["address"]
    contract = w3.eth.contract(address=contract_address, abi=contract_interface['abi'])

    time_costs=[]
    # 并发执行多个 data_request 调用
    tasks = [
        asyncio.create_task(data_request(w3, contract, pk_pem, cred, pid, sig_pid, proxy_url, enclave_pk, sk_du, SAVING_PATH, default_account,time_costs))
        for _ in range(4)  # 假设我们想并发执行 5 次 data_request
    ]
    await asyncio.gather(*tasks)

    print("***",time_costs)

if __name__ == "__main__":
    asyncio.run(main())
