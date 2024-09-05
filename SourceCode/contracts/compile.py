import solcx
from solcx import compile_source
import json


# 需要指定使用的编译器版本
solcx.install_solc('0.8.0')
solcx.set_solc_version('0.8.0')

with open('/home/oracle/contracts/cpsc.sol', 'r') as file:
    contract_source_code = file.read()
    solcx.install_solc('0.8.0')
    solcx.set_solc_version('0.8.0')
    compiled_sol = compile_source(contract_source_code, optimize=True)

# 将编译结果保存到文件
with open("compiled_contract_new.json", "w") as f:
    json.dump(compiled_sol, f)