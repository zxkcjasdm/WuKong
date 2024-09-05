from typing import (
    Type,
)
from eth.vm.forks.london import LondonVM
from eth.abc import (
    ComputationAPI,
)
from eth_utils.toolz import (
    merge,
)
from eth._utils.address import (
    force_bytes_to_address,
)
from eth.vm.forks.london.computation import (
    LondonComputation
)
from eth.vm.forks.london.state import(
    LondonState
)
from eth.vm.forks.berlin.computation import(
    BERLIN_PRECOMPILES
)
from eth.vm.forks import (
    LondonVM,
)
from eth.vm.state import BaseState
from eth_abi import decode,encode
from wk_evm.custom_precompiled.custom_vc import Sign,Eval,int_list_to_u128_array
# from wk_evm.custom_precompiled.custom_watermark import emb,ext
from wk_evm.custom_precompiled.custom_watermark_lgdr import generate_wk,wkemb,wkext

# def custom_keccak256(computation: ComputationAPI) -> ComputationAPI:
#     # Get the input data from the computation
#     input_data = computation.msg.data_as_bytes
#     # Decode the input data
#     param1, param2 = decode(['bytes', 'bytes'], input_data)

#     # Compute the hash from .so dll
#     result = custom_keccak(param1, param2)
#     # Encode the result
#     output = encode(['bytes32'], [result])
#     # Set the output and return
#     computation.output = output

def custom_vcsign(computation: ComputationAPI) -> ComputationAPI:
    input_data = computation.msg.data_as_bytes
    # Decode the input data
    x_array, labs_array, sk, pk = decode(
        ['uint128[]', 'uint128[]', 'bytes', 'bytes'], input_data
    )
    #Convert into C-like U128Array
    x_array_u128=int_list_to_u128_array(x_array)
    labs_array_u128=int_list_to_u128_array(labs_array)

    sigs=Sign(x_array_u128,labs_array_u128,sk,pk)
    # Encode the result
    output = encode(['bytes'], [sigs])
    computation.output = output


def custom_vceval(computation: ComputationAPI) -> ComputationAPI:
    input_data = computation.msg.data_as_bytes
    # Decode the input data
    x_array, labs_array, pk, sigs, func = decode(
        ['uint128[]', 'uint128[]', 'bytes', 'bytes', 'int'], input_data
    )
    x_array_u128=int_list_to_u128_array(x_array)
    labs_array_u128=int_list_to_u128_array(labs_array)

    vk_r,proof,computed_value=Eval(x_array_u128,labs_array_u128,pk,sigs,func)
    output = encode(['bytes','bytes','int'], [vk_r,proof,computed_value])
    computation.output = output

def custom_genwk(computation: ComputationAPI) -> ComputationAPI:
    wk=generate_wk()
    output = encode(['bytes'], [wk])
    computation.output = output


def custom_emb(computation: ComputationAPI) -> ComputationAPI:
    #def wkemb(content,input_image,output_image,wk):
    input_data = computation.msg.data_as_bytes
    content, input_image, output_image, wk = decode(
        ['bytes', 'bytes', 'bytes', 'bytes'], input_data
    )
    result=wkemb(content, input_image, output_image, wk)
    output = encode(['int'], [result])
    computation.output = output

def custom_ext(computation: ComputationAPI) -> ComputationAPI:
    #def wkext(output_image,wk):
    input_data = computation.msg.data_as_bytes
    output_image,wk = decode(
        ['bytes', 'bytes'], input_data
    )
    extracted=wkext(output_image,wk)
    output = encode(['bytes'], [extracted.encode("utf-8")])
    computation.output = output

CUSTOM_PRECOMPILES = merge(
    BERLIN_PRECOMPILES,
    {
        # force_bytes_to_address(b"\x10"): custom_keccak256,
        force_bytes_to_address(b"\x11"): custom_vcsign,
        force_bytes_to_address(b"\x12"): custom_vceval,
        force_bytes_to_address(b"\x13"): custom_emb,
        force_bytes_to_address(b"\x14"): custom_ext,
        force_bytes_to_address(b"\x15"): custom_genwk,
    },
)

class CustomComputation(LondonComputation):
    _precompiles = CUSTOM_PRECOMPILES

class CustomState(LondonState):
    computation_class = CustomComputation

class WK_EVM(LondonVM):
    _state_class: Type[BaseState] = CustomState