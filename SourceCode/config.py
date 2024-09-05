# config.py

NUM_ORACLES = 8
ORACLE_BASE_PORT = "400"

ORACLE_SETTINGS = {
    "n": NUM_ORACLES,
    "t": 3,
    "signers": [f"oracle{i}" for i in range(NUM_ORACLES)],
    #"committee": ["oracle0", "oracle4", "oracle9"],  # 可以根据需要动态生成或手动指定
    "combiner_url": "http://0.0.0.0:5000",
    "oracle_hosts": {f"oracle{i}": "127.0.0.1" for i in range(NUM_ORACLES)},
    "oracle_ports": {f"oracle{i}": f"{ORACLE_BASE_PORT}{i}" for i in range(NUM_ORACLES)}
}

proxy_host = "0.0.0.0"
proxy_port = 5200
PROXY_SETTINGS = {
    "proxy_port": proxy_port,
    "proxy_host": proxy_host,
    "proxy_url": f"http://{proxy_host}:{proxy_port}"
}


SERVER_SETTINGS={
    
}
enclave_host = "127.0.0.1"
enclave_port = 8888
E_KEY_PATH="keys/Enclave"
ENCLAVE_SETTINGS={
    "publicKey":f'{E_KEY_PATH}/public/E_public_key.pem',
    "privateKey":f'{E_KEY_PATH}/private/E_private_key.pem',
    "enclave_url": f"http://{enclave_host}:{enclave_port}"
}
