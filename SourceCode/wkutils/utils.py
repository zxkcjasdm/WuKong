import requests
import json
import hashlib
import secrets
import random
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from ecdsa import SECP256k1, ellipticcurve
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding as symmetric_padding
from PIL import Image
from io import BytesIO
import base64
import argparse
import time


curve = SECP256k1.curve
generator = SECP256k1.generator
order = generator.order()

def showpoint(p):
    return f"Point at Secp256k1 {p.curve()}:({p.x()},{p.y()})"

def point_to_bytes(point):
    # x_bytes = point.x().to_bytes((point.x().bit_length() + 7) // 8, 'big')
    # y_bytes = point.y().to_bytes((point.y().bit_length() + 7) // 8, 'big')
    x_bytes = point.x().to_bytes(32, 'big')
    y_bytes = point.y().to_bytes(32, 'big')
    return x_bytes + y_bytes

def point_to_bytes_uint(x, y):
    x_bytes = x.to_bytes(32, 'big')
    y_bytes = y.to_bytes(32, 'big')
    return x_bytes + y_bytes

def uint256_to_bytes(x):
    x_bytes = x.to_bytes(32, 'big')
    return x_bytes


def bytes_to_point(byte_data):
    byte_len = len(byte_data) // 2
    x_bytes = byte_data[:byte_len]
    y_bytes = byte_data[byte_len:]
    x = int.from_bytes(x_bytes, 'big')
    y = int.from_bytes(y_bytes, 'big')
    return ellipticcurve.Point(curve, x, y)

# def decrypt_message(private_key, encrypted_data):
#     chunk_size = 256  # 2048-bit key
#     encrypted_data = base64.b64decode(encrypted_data)
#     decrypted_chunks = []

#     for i in range(0, len(encrypted_data), chunk_size):
#         chunk = encrypted_data[i:i + chunk_size]
#         decrypted_chunk = private_key.decrypt(
#             chunk,
#             padding.PKCS1v15()
#         )
#         decrypted_chunks.append(decrypted_chunk)
    
#     # 将所有解密块连接起来，并解码为字符串
#     decrypted_data = b''.join(decrypted_chunks)
#     return decrypted_data.decode('utf-8')

# def encrypt_message(public_key, data):
#     chunk_size = 214  # 2048-bit key with PKCS#1 v1.5 padding
#     encrypted_chunks = []
    
#     for i in range(0, len(data), chunk_size):
#         chunk = data[i:i + chunk_size].encode('utf-8')
#         encrypted_chunk = public_key.encrypt(
#             chunk,
#             padding.PKCS1v15()
#         )
#         encrypted_chunks.append(encrypted_chunk)
#     return base64.b64encode(b''.join(encrypted_chunks)).decode('utf-8')

def encrypt_message(public_key, data, timestamp):
    chunk_size = 214  # 适用于2048位密钥
    encrypted_chunks = []
    
    for i in range(0, len(data), chunk_size):
        chunk = data[i:i + chunk_size].encode('utf-8')
        # 使用 PKCS#1 v1.5 但不添加随机填充
        padded_chunk = _add_pkcs1_padding(chunk, 256,timestamp)
        encrypted_chunk = pow(int.from_bytes(padded_chunk, 'big'), 
                              public_key.public_numbers().e, 
                              public_key.public_numbers().n)
        encrypted_chunks.append(encrypted_chunk.to_bytes(256, 'big'))
    
    return base64.b64encode(b''.join(encrypted_chunks)).decode('utf-8')

# def _add_pkcs1_padding(data, block_size):
#     padding_length = block_size - len(data) - 3
#     return b'\x00\x02' + b'\xff' * padding_length + b'\x00' + data
def _add_pkcs1_padding(data, block_size, timestamp):
    timestamp_bytes = hashlib.sha256(str(timestamp).encode('utf-8')).digest()
    padding_length = block_size - len(data) - len(timestamp_bytes) - 3

    if padding_length < 0:
        raise ValueError("数据块太大，无法填充")

    # 使用时间戳和固定填充字节 `\xff`
    padding = b'\xff' * padding_length
    return b'\x00\x02' + padding + timestamp_bytes + b'\x00' + data

# def decrypt_message(private_key, encrypted_data):
#     chunk_size = 256
#     encrypted_data = base64.b64decode(encrypted_data)
#     decrypted_chunks = []

#     for i in range(0, len(encrypted_data), chunk_size):
#         chunk = encrypted_data[i:i + chunk_size]
#         decrypted_int = pow(int.from_bytes(chunk, 'big'),
#                             private_key.private_numbers().d,
#                             private_key.private_numbers().public_numbers.n)
#         decrypted_padded = decrypted_int.to_bytes(chunk_size, 'big')
#         # 移除 PKCS#1 v1.5 填充
#         decrypted_chunk = decrypted_padded[decrypted_padded.index(b'\x00', 2)+1:]
#         decrypted_chunks.append(decrypted_chunk)
    
#     return b''.join(decrypted_chunks).decode('utf-8')
def decrypt_message(private_key, encrypted_data):
    chunk_size = 256
    encrypted_data = base64.b64decode(encrypted_data)
    decrypted_chunks = []

    for i in range(0, len(encrypted_data), chunk_size):
        chunk = encrypted_data[i:i + chunk_size]
        decrypted_int = pow(int.from_bytes(chunk, 'big'),
                            private_key.private_numbers().d,
                            private_key.private_numbers().public_numbers.n)
        decrypted_padded = decrypted_int.to_bytes(chunk_size, 'big')
        # 移除 PKCS#1 v1.5 填充，包括时间戳
        start = 2
        while decrypted_padded[start] == 0xff:
            start += 1
        # 时间戳长度为32（SHA256哈希的长度）
        timestamp = decrypted_padded[start:start+32]
        decrypted_chunk = decrypted_padded[start+33:]  # +1 for the separator null byte
        decrypted_chunks.append(decrypted_chunk)
    
    try:
        return b''.join(decrypted_chunks).decode('utf-8')
    except UnicodeDecodeError:
        # 如果UTF-8解码失败，尝试其他编码或返回字节串
        return b''.join(decrypted_chunks)
    

def _add_pkcs1_padding_sign(data, block_size):
    padding_length = block_size - len(data) - 3
    return b'\x00\x01' + b'\xff' * padding_length + b'\x00' + data

def sign_hash(private_key, hash_value):
    # 确保hash_value是字节串
    if isinstance(hash_value, str):
        hash_value = bytes.fromhex(hash_value)
    
    # 添加 PKCS#1 v1.5 填充
    padded_hash = _add_pkcs1_padding_sign(hash_value, 256)
    
    # 使用私钥进行签名
    signature = pow(int.from_bytes(padded_hash, 'big'),
                    private_key.private_numbers().d,
                    private_key.private_numbers().public_numbers.n)
    
    # 将签名转换为字节串并进行 Base64 编码
    return base64.b64encode(signature.to_bytes(256, 'big')).decode('utf-8')

def verify_signature_with_hash(public_key, hash_value, signature):
    # 确保hash_value是字节串
    if isinstance(hash_value, str):
        hash_value = bytes.fromhex(hash_value)
    
    # 解码 Base64 签名
    signature = int.from_bytes(base64.b64decode(signature), 'big')
    
    # 使用公钥验证签名
    decrypted_signature = pow(signature,
                              public_key.public_numbers().e,
                              public_key.public_numbers().n)
    
    # 移除填充
    padded_hash = decrypted_signature.to_bytes(256, 'big')
    
    # 提取哈希值
    extracted_hash = _extract_hash_from_padding(padded_hash)
    
    # 比较哈希值
    return extracted_hash == hash_value

def _extract_hash_from_padding(padded_hash):
    # 查找第二个 \x00 字节的位置
    separator_index = padded_hash.index(b'\x00', 2)
    # 返回实际的哈希值
    return padded_hash[separator_index + 1:]



def image_to_base64(image_path):
    # 打开图像
    with Image.open(image_path) as image:
        # 创建一个字节流对象
        buffered = BytesIO()
        # 将图像保存到字节流中，格式为 JPEG
        image.save(buffered, format="JPEG")
        # 获取字节流内容并进行 Base64 编码
        img_str = base64.b64encode(buffered.getvalue()).decode("utf-8")
        
    return img_str

def base64_to_image(base64_string, output_path):
    # 解码 Base64 字符串
    img_data = base64.b64decode(base64_string)
    
    # 创建一个字节流对象
    buffered = BytesIO(img_data)
    
    # 打开图像
    image = Image.open(buffered)
    
    # 保存图像为 JPEG 格式
    image.save(output_path, format="JPEG" ,quality=95)



def read_rsapk_from_pem(path):
    with open(path, "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read()
    )
    return public_key

def read_rsask_from_pem(path,password=None):
    with open(path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
        key_file.read(),
        password=password,  # 如果私钥有密码，可以在这里提供
    )
    return private_key

def generate_aes_key(length=16):
    return secrets.token_bytes(length)

def generate_iv(length=16):
    return secrets.token_bytes(length)

def aes_encrypt(key, plaintext, iv=None):
    if iv is None:
        iv = generate_iv()
    
    # 创建PKCS7填充器
    padder = symmetric_padding.PKCS7(128).padder()
    
    # 填充数据
    padded_data = padder.update(plaintext) + padder.finalize()
    
    # 创建一个加密器
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    # 加密数据
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    
    # 返回初始化向量和密文
    return iv + ciphertext

def aes_decrypt(key, ciphertext):
    # 分离初始化向量和密文
    iv = ciphertext[:16]
    ciphertext = ciphertext[16:]
    
    # 创建一个解密器
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    
    # 解密数据
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    
    # 创建PKCS7填充移除器
    unpadder = symmetric_padding.PKCS7(128).unpadder()
    
    # 移除填充
    data = unpadder.update(padded_data) + unpadder.finalize()
    
    return data

