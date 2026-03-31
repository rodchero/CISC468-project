# CISC 468 - P2P Secure File Sharing App

## Roman and Youssef

# How to Run:

## Rust Client
### Dependencies
- rust & cargo (see: https://rust-lang.org/tools/install/)
- protobuf compiler
    - MAC: 
    ```bash
    brew install protobuf
    ```
    - Ubuntu/Debian: 
    ```bash
    sudo apt update && sudo apt install protobuf-compiler
    ```
    - WINDOWS: 
    ```cmd
    winget install protobuf
    ```

### Run
- cd into rust-p2p/
- run `cargo test` to test
- run `cargo run` to run the app

### Use
- first time login : make password 
    - if you forget password, delete the vault directory (`rust-p2p/vault/`), this will reset the storage, including peer trust, local files, etc
- every login thereafter, use the same password
- `/help` for a list of commands


## Python Client
### Dependencies
- Python 3.8+ (see: https://www.python.org/downloads/)
- install all dependencies in Python-P2P/requirements.txt
    - recommended to use a venv:
        - MAC/Linux: 
            ```bash
            cd Python-P2P
            python3 -m venv venv
            source venv/bin/activate
            pip install -r requirements.txt
            ```
        - WINDOWS:
            ```cmd
            cd Python-P2P
            python -m venv venv
            .\venv\Scripts\activate
            pip install -r requirements.txt
            ```

### Run
- cd into Python-P2P/
- Generate the Protobuf classes (Required before first run):
    - MAC/Linux: ```./generate_proto.sh```
    - WINDOWS: ```python -m grpc_tools.protoc -I./proto --python_out=./src/generated ./proto/p2pfileshare.proto```
- run ```pytest``` to run the test suite
- run ```python src/main.py``` (or ```python3 src/main.py```) to start the app

### Use
- first time login: enter your display name, secure password, and desired port (defaults to 9468).
    - This will automatically generate your local identity and create two folders: a secure `.p2p_storage_<port>` vault and a `shared_files_<port>` directory.
    - Put any files you want to share with other peers directly into the `shared_files_<port>` folder.
    - if you forget your password, delete the `.p2p_storage_<port>` directory. This will reset your identity, trusted contacts, and third-party metadata cache.
- every login thereafter, use the exact same password to unlock your vault.
- use the interactive numbered menu (1-9) to perform actions like discovering peers via mDNS, requesting files, offering files, and rotating your cryptographic keys.

