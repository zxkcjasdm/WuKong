import requests
import time
from wkutils.utils import *
import config
import asyncio
import aiohttp
import random

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

async def process_oracle(session, oracle_name,timestamp):
    test_host = config.ORACLE_SETTINGS['oracle_hosts'][oracle_name]
    test_port = config.ORACLE_SETTINGS['oracle_ports'][oracle_name]
    test_url = f"http://{test_host}:{test_port}"
    
    public_key = await get_public_key(session, test_url)
    #path="./data/wd/04.jpg" #使用嵌入过水印的图片
    path="./LocalStorage/enclave_storage/output/c9517828e4979af987c442941bb7339f5287a3c02530c4250d98e0616c056abd.jpg"
    data=image_to_base64(path)

    messages = [
         {'b': 2, 'data':data,'sigvc':"","a1a2":"com,pub","timestamp":timestamp,"metadata":"PhotoofHFUT","dp":"DEFAULT"} #m02  b==2表示trace 
         
    ]

    for m in messages:
        await send_request(session, f"{test_url}/data_trace", m, public_key)
        await asyncio.sleep(1)  # 1秒间隔

async def main():

    test_oracles = ["oracle1", "oracle2"]
    dp_name="dp0"
    timestamp=int(time.time())
    async with aiohttp.ClientSession() as session:
        tasks = [process_oracle(session, oracle, timestamp) for oracle in test_oracles]
        await asyncio.gather(*tasks)
        # for oracle in test_oracles:
        #     await process_oracle(session, oracle)


if __name__=="__main__":
   asyncio.run(main())