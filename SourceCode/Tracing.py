import requests
import time
from wkutils.utils import *
import config
import asyncio
import aiohttp
import random

async def send_request(session, url, ct):


    print(f"Trace: Sending to {url}, Size:{len(ct.encode('utf-8'))/1024}KB")
    async with session.post(url, json={"ciphertext": ct}) as response:
        print(await response.text())

async def get_public_key(session, url):
    async with session.post(f"{url}/get_rsa_pk") as response:
        data = await response.json()
        b64pk = data["pk"]
        pem_pk = base64.b64decode(b64pk).decode("utf-8")
        return serialization.load_pem_public_key(pem_pk.encode("utf-8"))

async def process_oracle(session, oracle_name,timestamp):
    test_host = config.ORACLE_SETTINGS['oracle_hosts'][oracle_name]
    test_port = config.ORACLE_SETTINGS['oracle_ports'][oracle_name]
    test_url = f"http://{test_host}:{test_port}"

    start_time = time.perf_counter()
    public_key = await get_public_key(session, test_url)
    #path="./data/wd/04.jpg" #使用嵌入过水印的图片
    path="./LocalStorage/user_storage/e91d31827170e69f1aa1e211ee8ca26556035b7b1ad4cfcb8373120fb28f11b3.jpg"
    data=image_to_base64(path)
    
    m = {'b': 2, 'data':data,'sigvc':"","a1a2":"com,pub","timestamp":timestamp,"metadata":"PhotoofHFUT","dp":"DEFAULT"} #m02  b==2表示trace 
    
    json_message = json.dumps(m)
    ct = encrypt_message(public_key, json_message,0)

    end_time = time.perf_counter()
    execution_time = end_time - start_time
    print(f"Provider computation executed in {execution_time:.4f} seconds")
    await send_request(session, f"{test_url}/data_trace", ct)
    await asyncio.sleep(1)  # 1秒间隔

async def main():

    test_oracles = ["oracle0", "oracle1", "oracle2"]
    dp_name="dp0"
    timestamp=int(time.time())
    async with aiohttp.ClientSession() as session:
        tasks = [process_oracle(session, oracle, timestamp) for oracle in test_oracles]
        await asyncio.gather(*tasks)
        # for oracle in test_oracles:
        #     await process_oracle(session, oracle)


if __name__=="__main__":
   asyncio.run(main())
