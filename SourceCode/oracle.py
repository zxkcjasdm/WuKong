# oracle_client.py
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

import sha3
import base64
import config
import argparse
import time
import uuid
import ctypes
from ctypes import c_char_p, c_size_t, c_bool, POINTER, c_void_p, cast

# 加载共享库
lib = ctypes.CDLL('./lib/liblsh_lib.so')  # 或 .dylib 在 macOS 上

# 定义函数签名
lib.create_lsh.argtypes = [c_size_t, c_size_t, c_size_t, c_size_t, c_size_t]
lib.create_lsh.restype = ctypes.c_void_p

lib.insert_image.argtypes = [ctypes.c_void_p, c_char_p]
lib.insert_image.restype = c_bool

lib.query_image.argtypes = [ctypes.c_void_p, c_char_p, c_size_t]
lib.query_image.restype = c_void_p

lib.free_string.argtypes = [c_void_p]
lib.free_lsh.argtypes = [c_void_p]

app = Flask(__name__)

curve = SECP256k1.curve
generator = SECP256k1.generator
order = generator.order()
ATS_KEY_PATH="keys/ATS"
ASY_KEY_PATH="keys/ASY"

class LSH:
    def __init__(self, num_hash_tables, hash_size, dimension, image_width, image_height):
        self.obj = lib.create_lsh(num_hash_tables, hash_size, dimension, image_width, image_height)

    def insert(self, image_path):
        return lib.insert_image(self.obj, image_path.encode('utf-8'))

    def query(self, image_path, k):
        result_ptr = lib.query_image(self.obj, image_path.encode('utf-8'), k)
        if not result_ptr:
            raise ValueError("Query failed")
        try:
            result = cast(result_ptr, c_char_p).value.decode('utf-8')
            #print(result)
        finally:
            lib.free_string(result_ptr)
        return result.split(',')

    def cleanup(self):
        if self.obj:
            lib.free_lsh(self.obj)
            self.obj = None

    def __del__(self):
        self.cleanup()

class Oracle:
    def __init__(self, name, t, combiner_url,proxy_url,is_in_committee,lsh):
        self.name = name
        self.is_in_committee=is_in_committee
        self.ski, self.pki = self.key_gen()
        print(name,f"pk is {showpoint(self.pki)}")
        self.private_key,self.public_key,self.private_key_pem,self.public_key_pem=self.gen_RSA_keypair()
        self.R={} #on key 聚合后的R
        self.z={} #on key 聚合后的z
        self.zi={} #on key 聚合前的share
        self.Ri={} #on key 聚合前的share
        self.ri={} #on key
        self.pk_dict=None
        self.t = t
        self.combiner_url = combiner_url
        self.proxy_url=proxy_url
        #print(f"{self.name}, sk: {self.ski}, pk: {showpoint(self.pki)}")
        self.addsigner()
        self.lsh=lsh

    def gen_RSA_keypair(self):
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
        
        with open(f'{ASY_KEY_PATH}/private/{self.name}_private_key.pem', 'wb') as f:
            f.write(private_pem)

        with open(f'{ASY_KEY_PATH}/public/{self.name}_public_key.pem', 'wb') as f:
            f.write(public_pem)

        return private_key,public_key,private_pem,public_pem
    
    def addsigner(self):
        data = {
        'name': self.name,
        'pki': point_to_bytes(self.pki).hex()
        }
        requests.post(f"{self.combiner_url}/add_signer", json=data)

    def register_committee(self):
        data = {'name': self.name}
        requests.post(f"{self.combiner_url}/register_committee", json=data)

    def generate_ri(self,key):
        self.ri[key] = secrets.randbelow(order)
        self.Ri[key] = generator * self.ri[key]
        print(f"{self.name} generated ri: {self.ri[key]}, Ri: {showpoint(self.Ri[key])}")
        data = {
            'name': self.name,
            'Ri': point_to_bytes(self.Ri[key]).hex(),
            'key':key
        }
        requests.post(f"{self.combiner_url}/add_Ri", json=data)

    def get_R(self,key):
        #if not self.R[key]:
        if key not in self.R:
            while True:
                response=requests.post(f"{self.combiner_url}/get_R", json={'key':key}) 

                code = response.status_code
                if code==200:
                    break
                elif code==204:
                    print(code,f"Waitting for R on key:{key}")
                time.sleep(1) 
            tempR=bytes_to_point(bytes.fromhex(response.json()["R"]))
            self.R[key]=tempR
        #return self.R

    def get_rsa_pk_pem(self):
        return self.public_key_pem

    def key_gen(self):
        ski = secrets.randbelow(order)
        pki = generator * ski
        return ski, pki

    def sign(self, message, key):
        h = sha3.keccak_256()
        h.update(uint256_to_bytes(t))
        print(t,h.digest())
        for name in sorted(self.pk_dict.keys()):
            print(name,showpoint(self.pk_dict[name]))
            h.update(point_to_bytes(self.pk_dict[name]))
        h.update(point_to_bytes(self.R[key]))
        h.update(message.encode("utf-8"))
        c = int.from_bytes(h.digest(), byteorder='big') % order
        self.zi[key] = (self.ri[key] + c * self.ski) % order
        data = {
            'name': self.name,
            'zi': self.zi[key],
            'key':key
        }
        #print(f"t={self.t},R={self.R},message={message},c={c},pk_dict={self.pk_dict}")
        requests.post(f"{self.combiner_url}/add_zi", json=data)

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

    def judge_data(self,data):
        return random.random() < 1.1

    def add_enclave_pk(self,path):
        self.enclave_pk=read_rsapk_from_pem(path)



@app.route('/data_collect', methods=['POST'])
def data_collect():
    if not oracle.is_in_committee: #committee中的成员才接收消息
        return jsonify({"status":"你找错人了"}),200
    edata = request.json
    ciphertext=edata["ciphertext"]
    message=decrypt_message(oracle.private_key,ciphertext)


    data_is_faithful=oracle.judge_data(message) #由oracle判断数据是否正确，目前这一功能为概率实现，即以概率返回True

    if not data_is_faithful: #数据不正确，返回
        return jsonify({"status":"unfaithful data"}),200
    print(repr(message))

    m0b=json.loads(message)
    ct=encrypt_message(oracle.enclave_pk,message,m0b["timestamp"]) 
    #计算这次提交的key，用于存储zi和Ri
    
    h = sha3.keccak_256()
    h.update(m0b["a1a2"].encode("utf-8"))
    h.update(ct.encode("utf-8"))
    key=h.digest().hex()

    oracle.generate_ri(key)
    oracle.get_R(key)

    if m0b["b"]==1:
        h = sha3.keccak_256()
        h.update(m0b["data"].encode("utf-8"))
        h.update(str(m0b["timestamp"]).encode("utf-8")) #增加时间进行hash，进行batch控制，防止同一图片多次上传后无法ats
        store_key=h.hexdigest() #也就是图片的hash
        base64_to_image(m0b["data"], f"./LocalStorage/oracle_storage/{store_key}.jpg")
        oracle.lsh.insert(f"./LocalStorage/oracle_storage/{store_key}.jpg")
        #图片，使用hash进行ats
        oracle.sign(store_key,key)
    else:
    #非图片，使用原始数据密文进行ats签名
        oracle.sign(ct,key)
    
    #签名后发送给proxy进行验证
    #If the data is faithful, $\mathcal{O}_i$ encrypts $m_{1,b}$, 
    # signs the ciphertext $c$, sends a collection message $\textsf{Msg}^{\textrm{col}}_2 = (\mathcal{O}_i, \Sigma.\mathsf{Enc}(pk^{\textrm{enc}}_{\mathcal{E}}, m_{1,b}), \sigma_i)$ to the $\mathcal{P}$ of an $\mathcal{S}$
    h = sha3.keccak_256()
    h.update(oracle.name.encode("utf-8"))
    h.update(point_to_bytes(oracle.Ri[key]).hex().encode("utf-8"))
    h.update(str(oracle.zi[key]).encode("utf-8"))
    h.update(ct.encode("utf-8"))
    signature_i=sign_hash(oracle.private_key,h.digest())
    response = requests.post(
        f"{oracle.proxy_url}/data_collect",
        json={
            "oraclename": oracle.name,
            "Ri": point_to_bytes(oracle.Ri[key]).hex(),
            "zi": str(oracle.zi[key]),
            "ciphertext": ct,
            "signature_i":signature_i,
            "public_key":base64.b64encode(oracle.get_rsa_pk_pem()).decode('utf-8')
        }
    )

    return jsonify({"status":"succeed"}),200

@app.route('/get_rsa_pk', methods=['POST'])
def get_rsa_pk():
    return jsonify({"pk":base64.b64encode(oracle.get_rsa_pk_pem()).decode('utf-8')}),200


@app.route("/du_register", methods=['POST'])
def du_register():
    #create a cred
    h = sha3.keccak_256()
    h.update(uint256_to_bytes(secrets.randbelow(order)))
    cred = sign_hash(oracle.private_key, h.digest())
    pid = str(uuid.uuid4())
    pid = str(pid).split('-')[0] #切短

    h = sha3.keccak_256()
    h.update(pid.encode("utf-8"))
    sig_pid=sign_hash(oracle.private_key,h.digest())
    return jsonify({"cred":cred,"pid":pid,"sig_pid":sig_pid}),200


@app.route("/data_trace", methods=['POST'])
def data_trace():
    if not oracle.is_in_committee: #committee中的成员才接收消息
        return jsonify({"status":"你找错人了"}),200
    edata = request.json
    ciphertext=edata["ciphertext"]
    message=decrypt_message(oracle.private_key,ciphertext)
    m02=json.loads(message)
    #LSH here
    h = sha3.keccak_256()
    h.update(m02["data"].encode("utf-8"))
    h.update(str(m02["timestamp"]).encode("utf-8")) #增加时间进行hash，进行batch控制，防止多次请求Tracing后ats无法进行
    store_key=h.hexdigest()
    base64_to_image(m02["data"], f"./LocalStorage/oracle_storage/{store_key}.jpg")
    results = oracle.lsh.query(f"./LocalStorage/oracle_storage/{store_key}.jpg", 5)
    print(f"LSH查询结果:{results}")

    if not results == [""]: #查询到了结果
        ct=encrypt_message(oracle.enclave_pk,message,m02["timestamp"]) 
        h = sha3.keccak_256()
        h.update(m02["a1a2"].encode("utf-8"))
        h.update(ct.encode("utf-8"))
        key=h.digest().hex()

        oracle.generate_ri(key)
        oracle.get_R(key)
        oracle.sign(store_key,key)

        h = sha3.keccak_256()
        h.update(oracle.name.encode("utf-8"))
        h.update(point_to_bytes(oracle.Ri[key]).hex().encode("utf-8"))
        h.update(str(oracle.zi[key]).encode("utf-8"))
        h.update(ct.encode("utf-8"))
        signature_i=sign_hash(oracle.private_key,h.digest())

        response = requests.post(
        f"{oracle.proxy_url}/data_trace",
        json={
            "oraclename": oracle.name,
            "Ri": point_to_bytes(oracle.Ri[key]).hex(),
            "zi": str(oracle.zi[key]),
            "ciphertext": ct,
            "signature_i":signature_i,
            "public_key":base64.b64encode(oracle.get_rsa_pk_pem()).decode('utf-8')
        }
        
    )
        return jsonify({"status":"Watermarked"}),200

    return jsonify({"status":"Not Watermarked"}),200


if __name__=="__main__":
    global oracle
    parser = argparse.ArgumentParser(description="Oracle Configuration Script")
    parser.add_argument('--id', type=int, default=0, help='oracle id')
    parser.add_argument('--in-committee', dest='in_committee', action='store_true', help='Set to mark in committee')
    args = parser.parse_args()
    id = args.id
    in_committee=args.in_committee

    name=f"oracle{id}"
    t = config.ORACLE_SETTINGS['t']
    combiner_url = config.ORACLE_SETTINGS['combiner_url']
    proxy_url=config.PROXY_SETTINGS["proxy_url"]
    ENCLAVE_KEY_PATH=config.ENCLAVE_SETTINGS["publicKey"]


    IMAGE_WIDTH=224
    IMAGE_HEIGHT=224
    IMAGE_CHANNEL=3
    dimension=IMAGE_WIDTH*IMAGE_HEIGHT*IMAGE_CHANNEL
    num_hash_tables=8
    hash_size=128
    lsh = LSH(num_hash_tables, hash_size, dimension, IMAGE_WIDTH, IMAGE_HEIGHT)


    oracle = Oracle(name,t,combiner_url,proxy_url,in_committee,lsh)
    if oracle.is_in_committee:
        oracle.register_committee()
        oracle.add_enclave_pk(ENCLAVE_KEY_PATH)

    oracle.get_pkdict()
    oracle_host=config.ORACLE_SETTINGS["oracle_hosts"][name]
    oracle_port=config.ORACLE_SETTINGS["oracle_ports"][name]

    #Setup Finished

    app.run(port=oracle_port, debug=False)
    #不要开调试，否则启动一个oracle后，另一个oracle启动时会重启一次，导致数据不一致问题（因为当前在一个目录下运行的）





    # message="HOW DO YOU TURN THIS ON"

    # if in_committee: 
    #     oracle.generate_ri()
    #     oracle.get_R()
    #     oracle.sign(message)












    # t=3
    # n=10
    # message="HOW DO YOU TURN THIS ON"
    # signers = [Oracle(f"oracle{i}", t,combiner_url) for i in range(n)]
    # committee = random.sample(signers, t)


    # for oracle in committee:
    #     oracle.register_committee()
    #     oracle.get_pkdict()
    
    # for oracle in committee:
    #     oracle.generate_ri()

    # for oracle in committee:
    #     oracle.get_R()

    # #sign here
    # for oracle in committee:
    #     oracle.sign(message) #这一步之后每个Oracle都有了sig_i=(R_i,z_i)了
    # response=requests.post(f"{combiner_url}/get_signature") #这一步其实是让combiner进行签名聚合，在WK方案中，是Proxy收集多个签名share来做聚合
    # agg_signature_serialized = response.json()
    # agg_signature={"R":bytes_to_point(bytes.fromhex(agg_signature_serialized["R"])),"z":int(agg_signature_serialized['z']),'C':agg_signature_serialized["C"]}
    # #print(agg_signature)

    # #Verify 验证签名，WK方案中是Proxy来验证
    # #由于需要计算pk_C，验证者也需要请求pk列表
    # response=requests.post(f"{combiner_url}/get_pkdict")
    # pk_dict_serialized = response.json()
    # pk_dict = {name: bytes_to_point(bytes.fromhex(pk_hex)) for name, pk_hex in pk_dict_serialized.items()}
    # pk_C = sum((pk_dict[name] for name in agg_signature["C"]), ellipticcurve.INFINITY)

    # h = hashlib.sha256()
    # h.update(str(t).encode("utf-8"))
    # for pki in pk_dict.values():
    #     h.update(point_to_bytes(pki))
    # h.update(point_to_bytes(agg_signature["R"]))
    # h.update(message.encode("utf-8"))
    # c = int.from_bytes(h.digest(), byteorder='big') % order

    # print(f"Computed c for verification: {c}")
    # p1 = agg_signature["z"] * generator
    # p2 = pk_C * c + agg_signature["R"]

    # print(f"p1: {showpoint(p1)}")
    # print(f"p2: {showpoint(p2)}")
    # assert p1 == p2, "Signature verification failed"