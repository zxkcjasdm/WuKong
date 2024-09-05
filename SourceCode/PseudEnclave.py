import requests
import json
import hashlib
import secrets
import random
import config
import shelve
from flask import Flask, request, jsonify
from wkutils.utils import *
from web3 import Web3
from solcx import compile_source
import uuid
import solcx
from eth_tester import EthereumTester, PyEVMBackend
from web3.providers.eth_tester import EthereumTesterProvider
from threading import Lock
import sha3
from eth_abi import decode,encode
from wk_evm.custom_precompiled.custom_vc import Setup,Sign,int_list_to_u128_array,VerSig
from wk_evm.WK_EVM import WK_EVM
from web3.exceptions import ContractLogicError
from eth_tester.exceptions import TransactionFailed

transaction_lock = Lock()
app = Flask(__name__)
skpath=config.ENCLAVE_SETTINGS["privateKey"]
app.config['CONTRACT_INITIALIZED'] = False

class LocalKV:
    def __init__(self, filename):
        self.filename = filename

    def set(self, key, value):
        with shelve.open(self.filename) as db:
            db[key] = value

    def get(self, key, default=None):
        with shelve.open(self.filename) as db:
            return db.get(key, default)

    def delete(self, key):
        with shelve.open(self.filename) as db:
            if key in db:
                del db[key]

    def list_keys(self):
        with shelve.open(self.filename) as db:
            return list(db.keys())



def init_contract():
    if not app.config['CONTRACT_INITIALIZED']:
        app.config['CONTRACT_INITIALIZED'] = True
        # 这里放置所有初始化合约的代码
        #solcx.install_solc('0.8.0')
        # solcx.set_solc_version('0.8.0')
        with open("contracts/compiled_contract_new.json", "r") as f:
            compiled_sol = json.load(f)

        #合约较大，如果不优化就会超出EIP-170的24,576字节限制
        contract_interface = compiled_sol['<stdin>:CPSC']
        
        custom_backend = PyEVMBackend(vm_configuration=[(0, WK_EVM)])
        eth_tester = EthereumTester(backend=custom_backend)
        w3 = Web3(EthereumTesterProvider(eth_tester))

        w3.eth.default_account = w3.eth.accounts[0]
        # Deploy contract
        Cpsc = w3.eth.contract(abi=contract_interface['abi'], bytecode=contract_interface['bin'])
        tx_hash = Cpsc.constructor().transact()
        tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
        contract_address = tx_receipt.contractAddress
        # Create contract instance
        contract_instance = w3.eth.contract(address=contract_address, abi=contract_interface['abi'])
        
        # 存储在应用上下文中
        app.contract_instance = contract_instance
        app.w3 = w3
        
        pk_dict=None
        while not pk_dict:
            response=requests.post(f"{combiner_url}/get_pkdict")
            code = response.status_code
            if code==200:
                break
            elif code==204:
                print(code,"Waitting for pk_dict")
            time.sleep(1) 
        pk_dict_serialized = response.json()
        pk_dict = {name: bytes_to_point(bytes.fromhex(pk_hex)) for name, pk_hex in pk_dict_serialized.items()}

        comittees=None
        while not comittees:
            response=requests.post(f"{combiner_url}/get_com")
            code = response.status_code
            if code==200:
                break
            elif code==204:
                print(code,"Waitting for comittees")
            time.sleep(1) 
        comittees = response.json()

        #注册所有的oracle
        for name in pk_dict:
            print(name)
            pk=pk_dict[name]
            tx_hash = contract_instance.functions.addsigner(name,pk.x(),pk.y()).transact()
            tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)

        #注册committee
        for comname in comittees:
            tx_hash = contract_instance.functions.register_committee(comname).transact()
            tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
        print("合约已经初始化了",contract_address)
        #这里pk太长了，无法在合约存储
        app.pk_psc,app.ssk_psc=Setup(200,200,200)
        # tx_hash = contract_instance.functions.setvckeys(pk_psc,ssk_psc).transact({'gas': int(500000*8)})
        # tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
        # print(tx_receipt)
        app.dppks={}
        app.image_saving_path="LocalStorage/enclave_storage/input"
        app.image_output_path="LocalStorage/enclave_storage/output"
        app.wk = app.contract_instance.functions.callGenWk().call()

        app.sk_sige = secrets.randbelow(order) #sk^sig_e
        app.pk_sige = generator * app.sk_sige #pk^sig_e

@app.route("/dp_setupvc",methods=['POST'])
def dp_setupvc():
    data = request.json
    dp = data["dp"]
    pk = data["pk"].encode("utf-8") #from str to bytes
    #这里pk太长了，无法在合约存储
    print(dp,len(pk),pk[0:100])
    app.dppks[dp]=pk

    return jsonify({'status': 'VC PK Updated'}), 200


@app.route('/preprocess', methods=['POST'])
def preprocess():
    start_time = time.perf_counter()

    data = request.json
    name = data['oraclename']
    ct = data["ciphertext"]
    Ri = bytes_to_point(bytes.fromhex(data['Ri']))
    zi = int(data['zi'])
    enclave_sk = read_rsask_from_pem(skpath)
    message = decrypt_message(enclave_sk, ct)
    m1 = json.loads(message)

    sigvc = b'0'

    a1a2=m1["a1a2"]
    ts = m1["timestamp"]
    meta_and_name=encode(['string', 'string'], [m1["metadata"], m1["dp"]])
    


    if m1["b"] == 0: #else b'0' 可计算数据
        sigvc = m1["sigvc"].encode("utf-8")
        numbers = json.loads(m1["data"])
        encoded = encode(['uint128[]'], [numbers])
        input_data=encoded
        #输入的uint128列表
        ats_base=ct

    else: #b==1 or 2，对于图片类型，生成hash作为data进入Cpsc
        h = sha3.keccak_256()
        h.update(m1["data"].encode("utf-8"))
        h.update(str(m1["timestamp"]).encode("utf-8")) #增加时间进行hash，进行batch控制，防止同一图片多次上传后无法ats
        store_key=h.hexdigest() #也就是图片的hash
        input_data=store_key.encode("utf-8")#本地存储
        #先存，如果失败了再删
        base64_to_image(m1["data"], f"{app.image_saving_path}/{store_key}.jpg")
        ats_base=store_key

    with transaction_lock:
        #use metadata to create key, user could get the metadata to retrieve
        tx_hash = app.contract_instance.functions.collect(meta_and_name,input_data,ats_base, sigvc, a1a2, ts, Ri.x(), Ri.y(), zi).transact({'gas': int(4672284*2)})
        #ats_base指的是基于哪个数据进行ats签名的，对于图片是hash，对于可计算数据是ct
        #对于图片，存储ct可能太长
        tx_receipt = app.w3.eth.wait_for_transaction_receipt(tx_hash)
        #print(tx_receipt)
        ats_success_event = app.contract_instance.events.ats_success()
        ats_events = ats_success_event.get_logs(fromBlock=tx_receipt.blockNumber, toBlock=tx_receipt.blockNumber)
        #print(ats_events)
        if m1["b"]==2: #对于Trace的数据
             for event in ats_events:
                print("Start Tracing")
                key = event['args']['key']
                m2list=app.contract_instance.functions.getm2(key).call()#获取的是最后一个m2，key的计算方式是keccak256(A1,A2,meta)
                #print(m2list)
                m2={"data":m2list[0],"sigvc":m2list[2],"a1a2":m2list[3],"timestamp":m2list[4],"Rx":m2list[5],"Ry":m2list[6],"z":m2list[7]}

                wd_path=f"{app.image_saving_path}/{m2['data'].decode('utf-8')}.jpg"#接收图像保存的位置
                #提取水印
                #print(wd_path)
                inf="UBIPLAB"
                inf=app.contract_instance.functions.callExt(wd_path.encode("utf-8"),app.wk).call()
                if inf == "":
                    inf = "UBIPLAB" #simulation
                #使用pk_tar加密，这里用enclave的pk模拟
                pk_tar=read_rsapk_from_pem(config.ENCLAVE_SETTINGS["publicKey"])
                encrypt_message(pk_tar,inf.decode("utf-8"),0)
                #
                h = sha3.keccak_256()
                h.update(inf)
                hinf=h.digest().hex()

                h = sha3.keccak_256()
                r=secrets.randbelow(order)
                R= generator * r
                h.update(point_to_bytes(app.pk_sige)) #H(pk,R,m)
                h.update(point_to_bytes(R))
                h.update(hinf.encode("utf-8"))

                c = int.from_bytes(h.digest(), byteorder='big') % order
                z = (r+ c * app.sk_sige) % order
                end_time = time.perf_counter()

                execution_time=end_time-start_time
                print(f"Enclave Data Trace executed in {execution_time:.4f} seconds",flush=True)
                return jsonify({'status': 'Trace succeed',"pk":point_to_bytes(app.pk_sige).hex() ,"R":point_to_bytes(R).hex(), "m": hinf, "z":z}), 200
             
        for event in ats_events:
            key = event['args']['key']
            m2list=app.contract_instance.functions.getm2(key).call()#获取的是最后一个m2，key的计算方式是keccak256(A1,A2,meta)
            #print(m2list)
            if m1["b"]==0:
                u128data = decode(['uint128[]'], m2list[0])
                m2={"data":u128data,"sigvc":m2list[2].decode('utf-8'),"a1a2":m2list[3],"timestamp":m2list[4],"Rx":m2list[5],"Ry":m2list[6],"z":m2list[7]}
            else:
                m2={"data":m2list[0].decode('utf-8'),"sigvc":m2list[2].decode('utf-8'),"a1a2":m2list[3],"timestamp":m2list[4],"Rx":m2list[5],"Ry":m2list[6],"z":m2list[7]}
            """
            已经通过mapping存储过了
            """

            recived_message = json.dumps(m2) #真实保存的数据，不能泄露
            h = sha3.keccak_256()
            h.update(recived_message.encode("utf-8"))
            success_message = h.digest().hex() #m


            with open(f'LocalStorage/enclave_storage/input/{success_message}.json', 'w') as file:
                json.dump(m2, file)

            
            h = sha3.keccak_256()
            r=secrets.randbelow(order)
            R= generator * r
            h.update(point_to_bytes(app.pk_sige)) #H(pk,R,m)
            h.update(point_to_bytes(R))
            h.update(success_message.encode("utf-8"))

            c = int.from_bytes(h.digest(), byteorder='big') % order
            z = (r+ c * app.sk_sige) % order
            #sigE = sign_hash(enclave_sk, hashvalue)
            end_time = time.perf_counter()
            execution_time=end_time-start_time
            print(f"Enclave Data Collect executed in {execution_time:.4f} seconds",flush=True)

            return jsonify({'status': 'ATS succeed', "pk":point_to_bytes(app.pk_sige).hex() ,"R":point_to_bytes(R).hex(), "m": success_message, "z":z}), 200

    return jsonify({'status': 'Data Collected'}), 200

@app.route('/respond', methods=['POST'])
def respond():
    start_time=time.perf_counter()
    data = request.json
    json_str=json.dumps(data)
    byte_length = len(json_str.encode('utf-8'))
    # 将字节数转换为KB
    kb_size = byte_length / 1024
    print(f"Enclave Data Request Communication size(input): {kb_size:.2f} KB",flush=True)



    enclave_sk = read_rsask_from_pem(skpath)
    uuid = data['uuid']
    ct = data["ct"]
    message = decrypt_message(enclave_sk, ct)
    m3b = json.loads(message)
    b64pkdu=m3b["pk_du"]
    pem_pk_du = base64.b64decode(b64pkdu).decode("utf-8")
    pk_du=serialization.load_pem_public_key(pem_pk_du.encode("utf-8"))

    
    #m30
    if "f" in m3b:
        
        f=m3b["f"]
        values=[]
        print("EVAL***")
        #for i in range(len(dps)):
        index = 0
        while True:
            try:
                sigvc,dp,data = app.contract_instance.functions.respond0(m3b["metadata"],m3b["a1a2"],index).call()
                #print(sigvc,dp,data)
                pk=app.dppks[dp]
                #是否需要增加缓存机制，即一段data,sigvc,f之前已经计算过结果，可以把结果缓存，此处跳过eval以及versig
                vk_r,proof,computed_value=app.contract_instance.functions.callEval(data,data,pk,sigvc,f).call() #用dp的pk来eval
                assert VerSig(vk_r,int_list_to_u128_array(data),computed_value,proof),"Verification Failed"
                values.append(computed_value)
                index += 1  # 增加索引，继续读取下一个
            
            except (TransactionFailed) as e:
                # 假设异常的原因是因为索引超出范围，或者 Out of Gas
                print(f"Stopped at index {index}: {str(e)}",flush=True)
                break
            

            
            #vk_r,proof,computed_value=contract_instance.functions.callEval(x_array,labs_array,pk,sigs,func).call({'gas': GAS_PROVIDED})
            #print(vk_r,proof,computed_value)

        final_sigs = app.contract_instance.functions.callSign(values,values,app.ssk_psc,app.pk_psc).call()
        final_vk_r,final_proof,final_value=app.contract_instance.functions.callEval(values,values,app.pk_psc,final_sigs,f).call() #用psc的pk来eval
        result_data={"vk_r":final_vk_r.decode("utf-8"),"proof":final_proof.decode("utf-8"),"value":str(final_value),"labs":values}
        #print(final_value,len(final_proof))
        ct=encrypt_message(pk_du,json.dumps(result_data),0)

        h = sha3.keccak_256()
        h.update(ct.encode("utf-8"))
        cth = h.digest().hex() #m
        

        h = sha3.keccak_256()
        r=secrets.randbelow(order)
        R= generator * r
        h.update(point_to_bytes(app.pk_sige)) #H(pk,R,m)
        h.update(point_to_bytes(R))
        h.update(cth.encode("utf-8"))

        c = int.from_bytes(h.digest(), byteorder='big') % order
        z = (r+ c * app.sk_sige) % order

        end_time=time.perf_counter()
        execution_time=end_time-start_time
        print(f"Enclave Data Request executed in {execution_time:.4f} seconds",flush=True)

        data_tosend={"status":"Computation succeed","ct":ct,"pk":point_to_bytes(app.pk_sige).hex() ,"R":point_to_bytes(R).hex(), "m": cth, "z":z,"uuid":uuid}

        json_str=json.dumps(data_tosend)
        byte_length = len(json_str.encode('utf-8'))
        # 将字节数转换为KB
        kb_size = byte_length / 1024
        print(f"Enclave Data Request Communication size(output): {kb_size:.2f} KB",flush=True)
        return jsonify(data_tosend), 200
    #m31
        
    else:
        pid=m3b["pid"]
        store_key=app.contract_instance.functions.respond1(uuid,m3b["metadata"],m3b["a1a2"]).call()
        
        saving_path=f"{app.image_saving_path}/{store_key.decode('utf-8')}.jpg"
        output_path=f"{app.image_output_path}/{store_key.decode('utf-8')}.jpg"

        result=app.contract_instance.functions.callEmb(pid.encode("utf-8"),saving_path.encode("utf-8"),output_path.encode("utf-8"),app.wk).call()
        if result==1:
            #Succeed
            image_data=image_to_base64(output_path)
            #print(f"uuid:{uuid}, pid:{pid}, saving path:{output_path}")  #返回嵌入后的图像
            ct=encrypt_message(pk_du,image_data,0)

        end_time=time.perf_counter()
        execution_time=end_time-start_time
        print(f"Enclave Data Request executed in {execution_time:.4f} seconds",flush=True)


        data_tosend={'status': 'Respond succeed',"ct":ct}
        json_str=json.dumps(data_tosend)
        byte_length = len(json_str.encode('utf-8'))
        # 将字节数转换为KB
        kb_size = byte_length / 1024
        print(f"Enclave Data Request Communication size(output): {kb_size:.2f} KB",flush=True)

        return jsonify(data_tosend), 200

if __name__=="__main__":
    combiner_url=config.ORACLE_SETTINGS["combiner_url"]

    enclave_host=config.enclave_host
    enclave_port=config.enclave_port

    #初始化EVM
    init_contract()
    app.run(host=enclave_host,port=enclave_port, debug=False,threaded=True)
