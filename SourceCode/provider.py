import requests
import time
from wkutils.utils import *
import config
import asyncio
import aiohttp
import random
import pandas as pd
import ast
from wk_evm.custom_precompiled.custom_vc import Setup,Sign,int_list_to_u128_array


async def send_request(session, url, ct):
    
    print(f"Sending to {url}, Size:{len(ct.encode('utf-8'))/1024}KB")
    async with session.post(url, json={"ciphertext": ct},timeout=1200) as response:
        print(await response.text())

async def get_public_key(session, url):
    async with session.post(f"{url}/get_rsa_pk") as response:
        data = await response.json()
        b64pk = data["pk"]
        pem_pk = base64.b64decode(b64pk).decode("utf-8")
        return serialization.load_pem_public_key(pem_pk.encode("utf-8"))

async def process_oracle(raw_data, session, oracle_name,dp_name,sk,pk,timestamp):
    
    test_host = config.ORACLE_SETTINGS['oracle_hosts'][oracle_name]
    test_port = config.ORACLE_SETTINGS['oracle_ports'][oracle_name]
    test_url = f"http://{test_host}:{test_port}"
    public_key = await get_public_key(session, test_url)

    start_time = time.perf_counter()
    sigvc=Sign(int_list_to_u128_array(raw_data),int_list_to_u128_array(raw_data),sk,pk).decode("utf-8")

    path="./data/04.jpg"
    data=image_to_base64(path)
    m={'b': 0, 'data': f'{raw_data}', 'sigvc': sigvc, "a1a2": "com,pub", "timestamp": timestamp, "metadata": "404HospitalData","dp":dp_name} #为了确保每一轮提交的ct不一样，我们的方法是引入timestamp作为padding以加密，
        #也就是同一批次提交的数据timestamp相同，这样在ats签名时不会出错
    #m = {'b': 1, 'data':data,'sigvc':"","a1a2":"com,pub","timestamp":timestamp,"metadata":"PhotoofHFUT","dp":dp_name} #Image data
    
    json_message = json.dumps(m)
    ct = encrypt_message(public_key, json_message,0)
    end_time = time.perf_counter()
    execution_time = end_time - start_time
    print(f"Provider computation executed in {execution_time:.4f} seconds")
    await send_request(session, f"{test_url}/data_collect", ct)

    # 结束时间
    
    # 计算执行时间
async def read_data(path):
    df = pd.read_csv(path)
    df['Doctor Communication Scores'] = df['Doctor Communication Scores'].apply(ast.literal_eval)
    random_list = df['Doctor Communication Scores'].sample(n=1).iloc[0]
    return random

async def main(proxy_url, test_oracles, dp_name, pk, sk, time_costs):
    timestamp = int(time.time())
    start_time=time.perf_counter()
    for i in range(1):  # 假设你只运行一次循环
        #raw_data = [random.randint(1, 10000) for _ in range(2)]
        raw_data=read_data("dataset/statewise_doctor_score.csv")
        async with aiohttp.ClientSession() as session:
            tasks = [
                process_oracle(raw_data, session, oracle, dp_name, sk, pk, timestamp)
                for oracle in test_oracles
            ]
            await asyncio.gather(*tasks)
        print(f"Batch {i} data Updated")
        finish_time=time.perf_counter()-start_time
        print(f"Data Provider 总共花费 {finish_time:.4f} seconds") 
        time_costs.append(round(finish_time, 4))

async def run_multiple_mains(n, proxy_url, test_oracles, dp_name, pk, sk, time_costs):
    tasks = [
        asyncio.create_task(main(proxy_url, test_oracles, dp_name, pk, sk, time_costs))
        for _ in range(n)
    ]
    await asyncio.gather(*tasks)

if __name__ == "__main__":
    # 初始化参数
    proxy_url = config.PROXY_SETTINGS["proxy_url"]
    test_oracles = ["oracle0", "oracle1", "oracle2"]
    dp_name = "dp0"
    pk, sk = Setup(max_nconstraints=100, max_nvariables=100, max_inputs=100)

    # 使用 requests 发送同步请求
    response = requests.post(f"{proxy_url}/dp_setupvc", json={"pk": pk.decode("utf-8"), "dp": dp_name})

    # 设置并行运行的 main 实例数量
    n = 1
    time_costs=[]
    # 启动异步任务
    asyncio.run(run_multiple_mains(n, proxy_url, test_oracles, dp_name, pk, sk, time_costs))
    print(time_costs)
