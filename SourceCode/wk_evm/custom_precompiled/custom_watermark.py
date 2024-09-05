import numpy as np
from scipy.fft import dct, idct
from PIL import Image
from bitarray import bitarray
import numba
from wkutils.utils import generate_aes_key, aes_encrypt, aes_decrypt
import base64
import uuid
from io import BytesIO


EMB_LENGTH=104
#对于UUID-4，AES128加密并用base32编码，嵌入的长度总是104


@numba.jit(forceobj=True)
def dct_2d(matrix):
    return dct(dct(matrix.T, type=2, norm='ortho').T, type=2, norm='ortho')

@numba.jit(forceobj=True)
def idct_2d(matrix):
    return idct(idct(matrix.T, type=2, norm='ortho').T, type=2, norm='ortho')

def text_to_bits(text):
    ba = bitarray()
    ba.frombytes(text.encode('utf-8'))
    return ba.to01()

def bits_to_text(bits):
    ba = bitarray(bits)
    return ba.tobytes().decode('utf-8', errors='ignore')

@numba.jit(forceobj=True)
def embed_text(y, bits, strength=1, block_size=8, coef_pos=(4, 4)):
    rows, cols = y.shape
    bit_index = 0
    for i in range(0, rows, block_size):
        for j in range(0, cols, block_size):
            if bit_index >= len(bits):
                return y
            block = y[i:i+block_size, j:j+block_size]
            dct_block = dct_2d(block)
            
            if bits[bit_index] == '1':
                dct_block[coef_pos] += strength
            else:
                dct_block[coef_pos] -= strength
            bit_index += 1
            
            y[i:i+block_size, j:j+block_size] = idct_2d(dct_block)
    return y

@numba.jit(forceobj=True)
def extract_text(y, text_length, strength=1, block_size=8, coef_pos=(4, 4)):
    rows, cols = y.shape
    bits = ''
    bit_index = 0
    for i in range(0, rows, block_size):
        for j in range(0, cols, block_size):
            if bit_index >= text_length * 8:
                return bits
            block = y[i:i+block_size, j:j+block_size]
            dct_block = dct_2d(block)
            
            if dct_block[coef_pos] > strength / 2:
                bits += '1'
            else:
                bits += '0'
            bit_index += 1
    return bits

def process_image(image_data, text, strength=10, mode='embed',is_base64=False):
    if not is_base64:
        try:
            image = Image.open(image_data)
        except IOError:
            print(f"无法打开图像文件: {image_data}")
            return None
    else:
        image=load_image_from_base64(image_data)

    ycbcr = image.convert('YCbCr')
    y, cb, cr = ycbcr.split()
    y = np.array(y, dtype=np.float32)

    if mode == 'embed':
        bits = text_to_bits(text)
        y = embed_text(y, bits, strength)
        y = np.clip(y, 0, 255).astype(np.uint8)
        watermarked_ycbcr = Image.merge('YCbCr', (Image.fromarray(y), cb, cr))
        return watermarked_ycbcr.convert('RGB')
    elif mode == 'extract':
        #bits = extract_text(y, len(text), strength)
        bits = extract_text(y, EMB_LENGTH, strength)
        return bits_to_text(bits)
    else:
        print("无效的模式")
        return None


def load_image_from_base64(base64_string):
    # 解码Base64字符串
    image_data = base64.b64decode(base64_string)
    # 使用BytesIO加载图像
    image = Image.open(BytesIO(image_data))
    return image

def image_to_base64(image_path):
    with open(image_path, "rb") as image_file:
        # 读取图像并编码为Base64
        base64_string = base64.b64encode(image_file.read()).decode('utf-8')
    return base64_string


def emb(wk,bmessage,idata,strength=10,mode=0):
    """
    0->path of image
    1->base64 of image

    bmessage:bytes
    """
    encrypted = aes_encrypt(wk, bmessage)
    b32ct=base64.b32encode(encrypted).decode("utf-8")
    if mode==0:
        watermarked_image = process_image(idata, b32ct, strength, mode='embed')
    elif mode==1:
        watermarked_image = process_image(idata, b32ct, strength, mode='embed', is_base64=True)
    
    if watermarked_image:
        rpath=f"/home/oracle/data/wd/{uuid.uuid4()}.jpg"
        watermarked_image.save(rpath,quality=95)
        return rpath

def ext(wk,idata,strength=10,mode=0):
    """
    0->path of image
    1->base64 of image
    """
    if mode==0:
        extracted_text = process_image(idata, "", strength, mode='extract')
    elif mode==1:
        extracted_text = process_image(idata, "", strength, mode='extract',is_base64=True)
    if extracted_text:
        ct=base64.b32decode(extracted_text)
        decrypted=aes_decrypt(wk,ct).decode("utf-8")
        #print("提取的内容:", decrypted)
        return decrypted



if __name__=="__main__":
    failure=0
    total=10
    for i in range(total):
        print("Round",i)
        aes_key=generate_aes_key()
        print(type(aes_key))
        image_path = '/home/oracle/data/04.jpg'
        b64image=image_to_base64(image_path)

        message = str(uuid.uuid4())
        bmessage = message.encode("utf-8")
        encrypted = aes_encrypt(aes_key, bmessage)
        text=base64.b32encode(encrypted).decode("utf-8")

        print("插入的是",message)
        strength = 20
        
        # 嵌入水印
        # watermarked_image = process_image(image_path, text, strength, mode='embed',is_base64=False)
        # if watermarked_image:
        #     watermarked_image.save('watermarked_image.png')
        try:
            rpath=emb(aes_key,bmessage,image_path,strength,mode=0)
            ext(aes_key,rpath,strength,mode=0)
        except Exception as e:
            print(e)
            failure+=1
        break
    #print(f"{100*failure/total}%")
    #提取水印
    extracted_text = process_image(rpath, text, strength, mode='extract')
    if extracted_text:
        ct=base64.b32decode(extracted_text)
        decrypted=aes_decrypt(aes_key,ct).decode("utf-8")
        print("提取的内容:", decrypted)
