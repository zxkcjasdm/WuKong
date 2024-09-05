#暂且用request发就行了
import requests
import time
from wkutils.utils import *
import config
import asyncio
import aiohttp
import random
from wk_evm.custom_precompiled.custom_vc import Setup,Sign,int_list_to_u128_array


async def send_request(session, url, message, public_key):
    json_message = json.dumps(message)
    ct = encrypt_message(public_key, json_message,0)
    print(f"Sending to {url}: {ct}")
    async with session.post(url, json={"ciphertext": ct}) as response:
        print(await response.text())

async def get_public_key(session, url):
    async with session.post(f"{url}/get_rsa_pk") as response:
        data = await response.json()
        b64pk = data["pk"]
        pem_pk = base64.b64decode(b64pk).decode("utf-8")
        return serialization.load_pem_public_key(pem_pk.encode("utf-8"))

async def process_oracle(session, oracle_name,dp_name,sk,pk,timestamp):
    test_host = config.ORACLE_SETTINGS['oracle_hosts'][oracle_name]
    test_port = config.ORACLE_SETTINGS['oracle_ports'][oracle_name]
    test_url = f"http://{test_host}:{test_port}"
    
    public_key = await get_public_key(session, test_url)
    raw_data=[1,2,3,4,5,6,7,8,9,10]
    
    sigvc=Sign(int_list_to_u128_array(raw_data),int_list_to_u128_array(raw_data),sk,pk).decode("utf-8")

    path="./data/04.jpg"
    data=image_to_base64(path)
    messages = [
        {'b': 0, 'data': f'{raw_data}', 'sigvc': sigvc, "a1a2": "com,pub", "timestamp": timestamp, "metadata": "404HospitalData","dp":dp_name} #为了确保每一轮提交的ct不一样，我们的方法是引入timestamp作为padding以加密，
        #也就是同一批次提交的数据timestamp相同，这样在ats签名时不会出错
        #{'b': 1, 'data':data,'sigvc':"","a1a2":"com,pub","timestamp":timestamp,"metadata":"PhotoofHFUT","dp":dp_name} #Image data
    ]

    for m in messages:
        await send_request(session, f"{test_url}/data_collect", m, public_key)
        await asyncio.sleep(1)  # 1秒间隔

async def main():

    proxy_url=config.PROXY_SETTINGS["proxy_url"]
    test_oracles = ["oracle1", "oracle2"]
    dp_name="dp0"
    pk,sk=Setup(max_nconstraints=100,max_nvariables=100,max_inputs=100)
    print(pk)
    response=requests.post(f"{proxy_url}/dp_setupvc",json={"pk":pk.decode("utf-8"),"dp":dp_name})
    timestamp=int(time.time())
    async with aiohttp.ClientSession() as session:
        tasks = [process_oracle(session, oracle,dp_name,sk,pk,timestamp) for oracle in test_oracles]
        await asyncio.gather(*tasks)
        # for oracle in test_oracles:
        #     await process_oracle(session, oracle)


if __name__=="__main__":
   asyncio.run(main())