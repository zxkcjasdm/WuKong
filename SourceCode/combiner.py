# combiner_server.py
from flask import Flask, request, jsonify
from ecdsa import SECP256k1, ellipticcurve
import hashlib
import config
from wkutils.utils import *

app = Flask(__name__)

curve = SECP256k1.curve
generator = SECP256k1.generator
order = generator.order()

"""
这里combiner和proxy在同一处运行，承担proxy中和oracle注册相关信息的部分
"""

class Combiner:
    def __init__(self, t, n):
        self.pk_dict = {}
        self.R_dict = {} #shares on key
        self.z_dict = {} #shares on key
        self.t = t
        self.n = n
        self.signer_list = []
        self.current_signer_list = []
        self.R={} #combined value on key
        self.z={} #combined value on key

    def add_signer(self, name, pki):
        self.signer_list.append(name)
        self.pk_dict[name] = pki
        print(f"{name} added as a signer, pk: {showpoint(pki)}")

    def register_committee(self, name):
        self.current_signer_list.append(name)

    def add_Ri(self, name, Ri, key):
        if key not in self.R_dict:
            self.R_dict[key] = {}
        self.R_dict[key][name] = Ri
        print(f"Ri collected from {name} on {key}, {len(self.R_dict[key])} shares now")
        if len(self.R_dict[key]) >= self.t:
            self.compute_R(key)
            print( f"agg R is {showpoint(self.R[key])} on {key}")

    def add_zi(self, name, zi, key):
        if key not in self.z_dict:
            self.z_dict[key] = {}
            
        self.z_dict[key][name] = zi
        if len(self.z_dict[key]) >= self.t:
            self.compute_z(key)
            print(f"{self.t} zi collected, agg z is {self.z[key]}")
    
    def get_R(self,key):
        return self.R[key]
    
    def compute_R(self,key):
        infinity = ellipticcurve.INFINITY
        self.R[key] = sum((self.R_dict[key][name] for name in self.current_signer_list), infinity)
        print(f"R computed {self.R[key]}")

    def compute_z(self,key):
        self.z[key] = sum(self.z_dict[key].values()) % order

    def get_signature(self):
        if self.R is None or self.z is None or len(self.current_signer_list)==0:
            return None
        return self.R, self.z, self.current_signer_list

@app.route('/register_committee', methods=['POST'])
def register():
    data = request.json
    name = data['name']
    combiner.register_committee(name)
    return jsonify({"message": f"{name} registered"}), 200

@app.route('/add_signer', methods=['POST'])
def add_signer():
    data = request.json
    name = data['name']
    pki = bytes_to_point(bytes.fromhex(data['pki']))
    combiner.add_signer(name, pki)
    return jsonify({"message": f"{name} added as a signer"}), 200

@app.route('/add_Ri', methods=['POST'])
def add_Ri():
    data = request.json
    name = data['name']
    key = data['key']
    Ri = bytes_to_point(bytes.fromhex(data['Ri']))
    combiner.add_Ri(name, Ri, key)
    return jsonify({"message": f"{name} added Ri"}), 200

@app.route('/add_zi', methods=['POST'])
def add_zi():
    data = request.json
    name = data['name']
    key = data['key']
    zi = int(data['zi'])
    combiner.add_zi(name, zi, key)
    return jsonify({"message": f"{name} added zi on {key}"}), 200

@app.route('/get_R',methods=['POST'])
def get_R():
    data =request.json
    key=data["key"]
    if key not in combiner.R_dict or len(combiner.R_dict[key]) < combiner.t or key not in combiner.R:
        return jsonify({'status': 'waiting_for_Ri'}), 204 #用 code204表示Ri未收集完
    return jsonify({"R":point_to_bytes(combiner.get_R(key)).hex()})

@app.route("/get_pkdict",methods=['POST'])
def get_pkdict():
    if len(combiner.pk_dict) < combiner.n:
        return jsonify({'status': 'waiting_for_pk'}), 204 #用 code204表示pk未收集完
    pk_dict_serialized = {name: point_to_bytes(pki).hex() for name, pki in combiner.pk_dict.items()}
    return jsonify(pk_dict_serialized), 200

@app.route("/get_com",methods=["POST"])
def get_com():
    if len(combiner.current_signer_list)<combiner.t:
        return jsonify({'status': 'waiting_for_committee'}), 204
    return jsonify(combiner.current_signer_list)
# @app.route("/get_signature",methods=['POST'])
# def get_signature():
#     signature = combiner.get_signature()
#     if signature is None:
#         return jsonify({"message": "Signature not ready"}), 204
#     R, z, C = signature
#     return jsonify({
#         "R": point_to_bytes(R).hex(),
#         "z": str(z),
#         "C": C
#     }), 200
# @app.route('/verify', methods=['POST'])
# def verify():
#     data = request.json
#     message = data['message']
#     R, z, C = combiner.R, combiner.z, combiner.current_signer_list

#     pk_C = sum((combiner.pk_dict[name] for name in C), ellipticcurve.INFINITY)
#     h = hashlib.sha256()
#     h.update(str(combiner.t).encode("utf-8"))
#     for pki in combiner.pk_dict.values():
#         h.update(point_to_bytes(pki))
#     h.update(point_to_bytes(R))
#     h.update(message.encode("utf-8"))
#     c = int.from_bytes(h.digest(), byteorder='big') % order

#     p1 = z * generator
#     p2 = c * pk_C + R

#     verification = p1 == p2
#     return jsonify({"message": "Verification result", "result": verification}), 200

if __name__ == '__main__':
    global combiner
    #read config
    t = config.ORACLE_SETTINGS['t']
    n = config.ORACLE_SETTINGS['n']
    proxy_host=config.PROXY_SETTINGS["proxy_host"]
    combiner = Combiner(t,n)
    app.run(host=proxy_host,port=5000, debug=False,threaded=True)