import os
from ctypes import CDLL, c_char_p, string_at, cast, c_void_p, POINTER,c_int,c_float


lib_path = os.path.join("wklib","lib_watermark.so")

lib = CDLL(lib_path)
lib.generate_watermark_key.argtypes = [c_int]
lib.generate_watermark_key.restype = c_void_p
lib.free_watermark_key.argtypes = [c_void_p]

lib.wk_emb.argtypes = [c_float,c_int,c_int,c_char_p,c_char_p,c_char_p,c_char_p]
#int wk_emb(float alpha, int m_num, int p_size, const char* content, const char* input_path, const char* output_path, const char* key)
lib.wk_emb.restype = c_int

lib.wk_ext.argtypes = [c_int,c_int,c_char_p,c_char_p]
#const char* wk_ext(int m_num,int p_size, const char* path,const char* key)
lib.wk_ext.restype = c_void_p
lib.free_ext.argtypes = [c_void_p]

m_num = 38
p_size = 2
w_size = m_num * p_size
alpha=2.8

def generate_wk():
    #WK Generation
    wk_ptr = lib.generate_watermark_key(w_size)
    if not wk_ptr:
        raise ValueError("Generation failed")
    try:
        wk = cast(wk_ptr, c_char_p).value.decode('utf-8')
        #print(wk)
        #print(f"Watermark Key Generated:{wk[:100]}...")
    finally:
        lib.free_watermark_key(wk_ptr)
    return wk.encode("utf-8")

def wkemb(content,input_image,output_image,wk):
    emb_result=lib.wk_emb(alpha,m_num,p_size,content,input_image,output_image,wk)
    return emb_result

def wkext(output_image,wk):
    ext_result_ptr=lib.wk_ext(m_num,p_size,output_image,wk)
    if not ext_result_ptr:
        raise ValueError("Extraction failed")
    try:
        message = cast(ext_result_ptr, c_char_p).value.decode('utf-8')
        print(message)
    except UnicodeDecodeError as e:
        message = cast(ext_result_ptr, c_char_p).value
        print(message)
        print(f"解码错误: {e}")
        return ""
    finally:
        lib.free_ext(ext_result_ptr)
    return message