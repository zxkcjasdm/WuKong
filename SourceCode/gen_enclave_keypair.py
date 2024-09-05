import requests
import json
import hashlib
import secrets
import random
from flask import Flask, request, jsonify
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from ecdsa import SECP256k1, ellipticcurve
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from wkutils.utils import *


import base64
import config
import argparse
import time

E_KEY_PATH="keys/Enclave"


def gen_RSA_keypair():
    private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend())
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)
    public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)
    
    with open(f'{E_KEY_PATH}/private/E_private_key.pem', 'wb') as f:
        f.write(private_pem)

    with open(f'{E_KEY_PATH}/public/E_public_key.pem', 'wb') as f:
        f.write(public_pem)


if __name__=="__main__":
    gen_RSA_keypair()