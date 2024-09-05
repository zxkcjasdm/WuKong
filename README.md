**Source Code & Full Version Manuscript of WuKong**

1. **Configuration**
  1.  Install Gramine. It's recommended to use the Gramine Docker Image for ease of setup and compatibility. 
  
  2.  Use pip to install all the necessary Python packages by running: `pip install -r requirements.txt`
  
  3.  Install all required development tools and libraries: `sudo apt install build-essential cmake git pkg-config libopencv-dev`

  4.  Install geth

2. **Setup**
  1. Compile the project with Software Guard Extensions (SGX) enabled by running: `make SGX=1`
  
  2. Open the config.py file and update the configuration parameters, such as host and port, to match the environment's requirements

  3. Generate the keypair of E by running: `python gen_enclave_keypair.py`

3. **Running**
  1. `geth --dev --http --http.addr "0.0.0.0" --http.port "8545" --datadir .public_chain/data --http.corsdomain "*" --http.api "eth,web3,personal,net" console`

  2. `python combiner.py`

  3. `python proxy.py`

  4. `gramine-sgx ./wkenclave PseudEnclave.py`

  5. `python oracle.py --id {id} --in-committee` if it is in committee. Otherwise `python oracle.py --id {id}`

  6. `python provider.py`
  
  7. `python user.py`
