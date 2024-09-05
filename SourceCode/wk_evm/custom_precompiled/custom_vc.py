from ctypes import CDLL, c_char_p, string_at, cast, c_void_p, POINTER
import os
import ctypes
import random
import base64

"""对Setup Sign Eval以及VerSig四个过程提供封装好的python函数
    以及U128 class封装,生成c指针的随机U128数组，int转U128函数，对于U256可以后续扩展
"""

lib_path = os.path.join("wklib","libhsnp.so")

class U128(ctypes.Structure):
    _fields_ = [("low", ctypes.c_uint64),
                ("high", ctypes.c_uint64)]

def generate_random_x_array(t):
    # 创建一个函数来生成随机的 U128 值
    def random_u128():
        return U128(
            low=random.randint(0, 2**64 - 1),
            high=random.randint(0, 2**60 - 1)
        )
    
    # 创建 t 长度的 U128 数组类型
    U128Array = U128 * t
    
    # 生成包含 t 个随机 U128 值的数组
    x_array = U128Array(*(random_u128() for _ in range(t)))
    
    return x_array

def int_to_u128(value):
    if value < 0 or value >= 2**128:
        raise ValueError("Value must be between 0 and 2^128 - 1")
    
    low = value & ((1 << 64) - 1)  # 取低 64 位
    high = value >> 64             # 取高 64 位
    
    return U128(low, high)

def int_list_to_u128_array(int_list):
    # 创建 U128 数组类型
    U128Array = U128 * len(int_list)
    # 生成 U128 数组
    u128_array = U128Array(*(int_to_u128(x) for x in int_list))
    
    return u128_array



def Setup(max_nconstraints=100,max_nvariables=100,max_inputs=100):
    """
    Setup of VC

    INPUT:max_nconstraints,max_nvariables,max_inputs

    OUTPUT:pk,sk in base64 bytes
    """
    lib = CDLL(lib_path)

    lib.hsnp_setup.argtypes = [ctypes.c_size_t, ctypes.c_size_t, ctypes.c_size_t]
    lib.hsnp_setup.restype = c_void_p
    lib.free_hsnp_setup.argtypes = [c_void_p]

    result_ptr = lib.hsnp_setup(max_nconstraints, max_nvariables, max_inputs)

    if not result_ptr:
        raise ValueError("Setup failed")
    try:
        result = cast(result_ptr, c_char_p).value.decode('utf-8')
    finally:
        lib.free_hsnp_setup(result_ptr)

    pk,sk=result.split("|")
    pk=pk.encode("utf-8")
    sk=sk.encode("utf-8")
    return pk,sk


def Sign(x_array,labs_array,sk,pk):
    """
    Sign of VC

    INPUT: x_array:u128[], labs_array:u128[], sk:base64, pk:base64
    
    OUTPUT: sigs:base64 bytes
    """

    lib = CDLL(lib_path)

    lib.hsnp_sign.argtypes = (ctypes.POINTER(U128),
                          ctypes.c_size_t,
                          ctypes.POINTER(U128),
                          ctypes.c_char_p,
                          ctypes.c_char_p)
    lib.hsnp_sign.restype = c_void_p
    lib.free_hsnp_sign.argtypes = [c_void_p]

    result_ptr = lib.hsnp_sign(x_array, len(x_array), labs_array, sk, pk)

    if not result_ptr:
        raise ValueError("Sign failed")
    try:
        result = cast(result_ptr, c_char_p).value.decode('utf-8')
    finally:
        lib.free_hsnp_sign(result_ptr)
    sigs=result.encode("utf-8")
    return sigs

def Eval(x_array,labs_array,pk,sigs,func=0):
    """
    Eval of VC

    INPUT: x_array:u128[], labs_array:u128[], pk:base64 bytes, sigs:base64 bytes, func:uint(0 for avg, 1 for max, 2 for min)
    
    OUTPUT: vk_r:base64 bytes, proof:base64 bytes, computed_value:int 
    """

    lib = CDLL(lib_path)
    lib.hsnp_eval.argtypes = (ctypes.POINTER(U128),
                          ctypes.c_size_t,
                          ctypes.POINTER(U128),
                          ctypes.c_size_t,
                          ctypes.c_char_p,
                          ctypes.c_char_p)
    lib.hsnp_eval.restype = c_void_p
    lib.free_hsnp_eval.argtypes = [c_void_p]

    result_ptr = lib.hsnp_eval(x_array, len(x_array), labs_array, func , pk, sigs)
    if not result_ptr:
        raise ValueError("Eval failed")
    try:
        result = cast(result_ptr, c_char_p).value.decode('utf-8')
    finally:
        lib.free_hsnp_eval(result_ptr)
    y,vk_r,proof=result.split("|")
    vk_r=vk_r.encode("utf-8")

    proof=proof.encode("utf-8")

    computed_value = int.from_bytes(base64.b64decode(y), 'big') #使用大端序，和rust中一致
    return vk_r,proof,computed_value

def VerSig(vk_r,labs_array,computed_value,proof):
    """
    VerSig of VC

    INPUT: vk_r:base64 bytes, labs_array:U128[], computed_value:int, proof:base64 bytes

    OUTPUT: is_success:bool
    
    
    """

    lib = CDLL(lib_path)
    lib.hsnp_versig.argtypes = (ctypes.c_char_p,
                                ctypes.c_size_t,
                                ctypes.POINTER(U128),
                                U128,
                                ctypes.c_char_p)
    lib.hsnp_versig.restype = ctypes.c_bool

    is_success = lib.hsnp_versig(vk_r, len(labs_array), labs_array, int_to_u128(computed_value) , proof)
    return is_success

if __name__=="__main__":
    pk,sk=Setup()
    x_array=generate_random_x_array(10)

    labs_array=generate_random_x_array(10)

    sigs=Sign(x_array,labs_array,sk,pk)

    vk_r,proof,computed_value=Eval(x_array,labs_array,pk,sigs,func=0)

    is_success=VerSig(vk_r,labs_array,computed_value,proof)

    print(is_success)