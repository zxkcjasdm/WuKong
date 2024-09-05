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
from wk_evm.custom_precompiled.custom_vc import Setup,Sign,VerSig,generate_random_x_array,int_list_to_u128_array
from wkutils.utils import *

import random
import json

"""
用于测试rust实现的Verifiable Computation相关函数编译为so格式lib，通过python提供接口实现evm预编译合约
"""

# 测试函数
if __name__=="__main__":
    custom_backend = PyEVMBackend(vm_configuration=[(0, WK_EVM)])
    eth_tester = EthereumTester(backend=custom_backend)
    w3 = Web3(EthereumTesterProvider(eth_tester))

    with open("contracts/compiled_contract.json", "r") as f:
            compiled_sol = json.load(f)

        #合约较大，如果不优化就会超出EIP-170的24,576字节限制
    contract_interface = compiled_sol['<stdin>:CPSC']

    # Deploy contract
    TestPreC = w3.eth.contract(abi=contract_interface['abi'], bytecode=contract_interface['bin'])
    tx_hash = TestPreC.constructor().transact()
    tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    contract_address = tx_receipt.contractAddress

    # Create contract instance
    contract_instance = w3.eth.contract(address=contract_address, abi=contract_interface['abi'])

    #生成测试数据，x和labs长为10，使用avg
    """
    @todo:setup中的三个参数设多少合适，x的长度是多少比较合适
    """
    GAS_PROVIDED=int(4672284*1.5)
    # t=20
    # x_array=[random.randint(0, 100000) for _ in range(t)]
    # labs_array=[random.randint(0, 100000) for _ in range(t)]
    # func=0
    # pk,sk=Setup(100,100,100)

    # #.sol文件中的callSign函数能够调用预编译合约
    # sigs = contract_instance.functions.callSign(x_array,labs_array,sk,pk).call()
    # #tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    # print("Sigs:",sigs)


    # vk_r,proof,computed_value=contract_instance.functions.callEval(x_array,labs_array,pk,sigs,func).call()
    # print(vk_r,proof,computed_value)





    print("Simulation","*"*12)
    #Simulation of Respond
    class DataProvider:
        def __init__(self,pk,sk,t) -> None:
            self.pk=pk
            self.sk=sk
            self.data=[random.randint(0, 100000) for _ in range(t)]
            self.labs=[random.randint(0, 100) for _ in range(t)]
            self.sigs=contract_instance.functions.callSign(self.data,self.labs,self.sk,self.pk).call()
    n=5
    func=0 #Avg函数
    DPs=[]
    #每个DP初始化，并对数据进行签名，每个DP持有5-10个数据
    # for i in range(5):
    #     pk,sk=Setup()
    #     print("Length of keys:",len(pk)/1024,len(sk)/1024)
    #     dp=DataProvider(pk,sk,random.randint(5,10))
    #     DPs.append(dp)
       
    
    print("VC Signatures Generated")
    #PSC的VC PK与SK
    pk_psc,sk_psc=Setup(200,200,200)
    decoded_pk = base64.b64decode(pk_psc)
    decoded_sk = base64.b64decode(sk_psc)

    print(len(decoded_pk)*8,len(decoded_sk)*8)
    print("PSC VC pk,sk Generated")
    #PSC获取了来自多个DP的data，首先对单个DP做Eval并获得结果
    vk_rs=[]
    proofs=[]
    computed_values=[random.randint(1, 10000) for _ in range(500)]
    count=0
    # for dp in DPs:
    #     vk_r,proof,computed_value=contract_instance.functions.callEval(dp.data,dp.labs,dp.pk,dp.sigs,func).call()
    #     #使用call方式调用，不改变区块链状态，所以gas并不会真正消耗
    #     vk_rs.append(vk_r)
    #     proofs.append(proof)
    #     computed_values.append(computed_value)
    #     print(f"Avg of DP{count} is {computed_value}")
    #     count+=1

    # for i in range(len(DPs)):
    #     dp=DPs[i]
    #     is_success=VerSig(vk_rs[i],int_list_to_u128_array(dp.labs),computed_values[i],proofs[i])
    #     assert is_success
    #     print(f"Proof of DP{i} Verified")
    #针对最后结果，PSC做SIGN与EVAL

    labs_psc=[random.randint(0, 100) for _ in range(len(computed_values))]
    sigs_psc = contract_instance.functions.callSign(computed_values,labs_psc,sk_psc,pk_psc).call()
    vk_r_psc,proof_psc,result=contract_instance.functions.callEval(computed_values,labs_psc,pk_psc,sigs_psc,func).call()

    print("Proof Verification")



    is_success=VerSig(vk_r_psc,int_list_to_u128_array(labs_psc),result,proof_psc)
    assert is_success
    print(f"Proof of PSC Verified, Result value {result}")





    # # ##直接调用预编译合约测试签名过程
    # address = force_bytes_to_address(b"\x11")

    # encoded_params = encode(['uint128[]', 'uint128[]', 'bytes', 'bytes'],[x_array,labs_array,sk,pk])

    # result = w3.eth.call({
    # 'to': address,
    # 'data': encoded_params
    # })
    # sigs = decode(['bytes'], result)[0]
    # print("Call from local Sigs:",sigs) 


    # ##直接调用预编译合约测试Eval过程
    # address = force_bytes_to_address(b"\x12")
    # encoded_params = encode(['uint128[]', 'uint128[]', 'bytes', 'bytes', 'int'],[x_array,labs_array,pk,sigs,0])
    # result = w3.eth.call({
    # 'to': address,
    # 'data': encoded_params
    # })
    # vk_r,proof,computed_value=decode(['bytes','bytes','int'],result)
    # print(vk_r,proof,computed_value)