geth --dev --http --http.addr "0.0.0.0" --http.port "8545" --datadir .public_chain/data --http.corsdomain "*" --http.api "eth,web3,personal,net" console

python3 combiner.py

python3 oracle.py --id 0

python3 oracle.py --id 1 --in-committee

python3 oracle.py --id 2 --in-committee

python3 proxy.py 



make clean
make SGX=1
gramine-sgx ./wkenclave PseudEnclave.py 
#python3 PseudEnclave.py

python3 provider.py

python3 user.py

python3 Tracing.py