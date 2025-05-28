import os
import hashlib
import json
from dotenv import load_dotenv
from web3 import Web3

# Load environment variables
load_dotenv()
RPC_URL = os.getenv("WEB3_PROVIDER")
PRIVATE_KEY = os.getenv("PRIVATE_KEY")
ACCOUNT_ADDRESS = os.getenv("ACCOUNT_ADDRESS")
CONTRACT_ADDRESS = os.getenv("CONTRACT_ADDRESS")
PINATA_API_KEY=os.getenv("PINATA_API_KEY")
PINATA_SECRET_API_KEY=os.getenv("PINATA_SECRET_KEY")
# Web3 connection
w3 = Web3(Web3.HTTPProvider(RPC_URL))
if not w3.is_connected():
    print("❌ Cannot connect to Web3 provider.")
    exit()

# Load contract ABI
with open('StorageContract.json') as f:
    contract_json = json.load(f)

abi = contract_json['abi']
contract = w3.eth.contract(address=Web3.to_checksum_address(CONTRACT_ADDRESS), abi=abi)

def keccakk_hash(data):
    return Web3.keccak(data).hex()  # Using Ethereum-style keccak hash

def split_chunks(data: bytes, num_chunks: int):
    chunk_size = len(data) // num_chunks
    return [data[i:i+chunk_size] for i in range(0, len(data), chunk_size)]

def greedy_allocate(share_count):
    servers, capacities = contract.functions.getServers().call()
    if not servers:
        print("❌ No servers registered.")
        return []

    available = sorted(zip(capacities, servers), reverse=True)
    allocation = []
    print("\n📈 Greedy Allocation Process:")

    for chunk_id in range(share_count):
        # Find the best available server
        available.sort(reverse=True)  # highest capacity first
        for i, (cap, server) in enumerate(available):
            if cap > 0:
                allocation.append(server)
                available[i] = (cap - 1, server)
                print(f"Chunk {chunk_id} ➝ Server {server} (Remaining Capacity: {cap - 1})")
                break
        else:
            print("❌ Not enough server capacity for all chunks.")
            return []

    return allocation
#Function for user for getting his file hash
def get_hash(file_path):
    try:
        with open(file_path, "rb") as f:
            file_data = f.read()
            keccak_hash = Web3.keccak(file_data).hex()
            return keccak_hash
    except FileNotFoundError:
        return "File not found."
    except Exception as e:
        return f"Error: {str(e)}"
#Sending Transaction to the Blockchain Provider
def build_transaction(func):
    try:
        nonce = w3.eth.get_transaction_count(ACCOUNT_ADDRESS, 'pending')  # Get fresh nonce, even pending ones
        gas_estimate = func.estimate_gas({'from': ACCOUNT_ADDRESS})
        gas_price = w3.eth.gas_price

        tx = func.build_transaction({
            'from': ACCOUNT_ADDRESS,
            'nonce': nonce,
            'gas': gas_estimate + 20000,
            'gasPrice': int(gas_price * 1.2)  # Boost gas price by 20%
        })

        signed_tx = w3.eth.account.sign_transaction(tx, PRIVATE_KEY)
        tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)
        print(f"✅ Transaction submitted: {tx_hash.hex()}")
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)  # Wait up to 5 minutes
        if receipt.status == 0:
            raise Exception("Transaction reverted.")
        return tx_hash
    except Exception as e:
        print(f"❌ Transaction error: {str(e)}")
        raise

#Function for Register a new user
def register():
    if check_registration():
        print("⚠️  Already registered.")
        return
    username = input("Enter username: ")
    password = input("Enter password: ")
    try:
        build_transaction(contract.functions.registerUser(username, password))
        print("✅ Registered successfully.")
    except Exception as e:
        print("❌ Error:", str(e))
def check_registration():
    try:
        return contract.functions.isRegistered(ACCOUNT_ADDRESS).call()
    except Exception as e:
        print("❌ Error checking registration:", str(e))
        return False

import requests
def upload_to_pinata(chunk_data, chunk_name):
    url = "https://api.pinata.cloud/pinning/pinFileToIPFS"

    files = {
        'file': (chunk_name, chunk_data),
    }
    headers = {
        "pinata_api_key": PINATA_API_KEY,
        "pinata_secret_api_key": PINATA_SECRET_API_KEY
    }

    response = requests.post(url, files=files, headers=headers)

    if response.status_code == 200:
        ipfs_hash = response.json()["IpfsHash"]
        
        return ipfs_hash
    else:
        print(f"❌ Failed to upload chunk: {response.text}")
        return None
def login():
    password = input("Enter password: ")
    try:
        authenticated = contract.functions.authenticate(password).call({'from': ACCOUNT_ADDRESS})
        print("✅ Login successful." if authenticated else "❌ Login failed.")
        return authenticated
    except Exception as e:
        print("❌ Error:", str(e))
        return False
#Uploading a file  
def upload():
    path = input("Enter file path: ")
    if not os.path.exists(path):
        print("❌ File not found.")
        return

    with open(path, 'rb') as f:
        data = f.read()
    share_count = int(input("Enter number of chunks: "))
    file_hash = keccakk_hash(data)
    content_hash = w3.to_bytes(hexstr=file_hash)

    # Check for duplicate
    try:
        existing = contract.functions.getFileInfo(content_hash).call()
        if existing[0] != "":
            print("❌ File already uploaded.")
            return
    except:
        pass  # Expected if file not found
    # Check for duplicate filename
    _, file_names = contract.functions.viewMyFiles().call({'from': ACCOUNT_ADDRESS})
    if os.path.basename(path) in file_names:
        print("❌ A file with the same name already exists.")
        return

    print("\n📄 Raw Data Preview:\n", data[:64], "...(truncated)")
    print("🔐 Keccak hash", file_hash)
    print("🔢 Total Chunks:", share_count)

    try:
        build_transaction(contract.functions.uploadFile(content_hash, os.path.basename(path), share_count))
        chunks = split_chunks(data, share_count)
        servers = greedy_allocate(share_count)

        if not servers:
            print("❌ Could not allocate chunks.")
            return
        chunk_dir = rf"D:\chunk\{content_hash.hex()}"
        
        os.makedirs(chunk_dir, exist_ok=True)
        for i, server in enumerate(servers):
            chunk_data=chunks[i]
            chunk_name = f"chunk_{i}.bin"
            ipfs_hash = upload_to_pinata(chunk_data, chunk_name)
            with open(f"{chunk_dir}/chunk_{i}.bin", "wb") as chunk_file:
                chunk_file.write(chunk_data)
            print(f"📦 Allocating chunk {i} to server {server}")
            build_transaction(contract.functions.allocateChunk(content_hash, i, server))

        print("✅ File uploaded and chunks allocated.")
    except Exception as e:
        print("❌ Upload error:", str(e))
    
    
#For viewing the file uploaded by the user
def view_files():
    try:
        contentHashes, fileNames = contract.functions.viewMyFiles().call({'from': ACCOUNT_ADDRESS})
        print("\n🗂️ Your Files:")
        for h, name in zip(contentHashes, fileNames):
            print(f"{name} -> {h.hex()}")
    except Exception as e:
        print("❌ Error:", str(e))
#For deleting a specific file
def delete_file():
    content_hash_hex = input("Enter file hash to delete: ")
    content_hash = w3.to_bytes(hexstr=content_hash_hex)
    try:
        build_transaction(contract.functions.deleteFile(content_hash))
        print("✅ File deleted.")
    except Exception as e:
        print("❌ Delete error:", str(e))
#To view the servers and its available spacedef view_servers():
    servers, caps = contract.functions.getServers().call()
    print("\n🖥️ Available Servers:")
    for s, c in zip(servers, caps):
        print(f"{s} - {c} chunks")

def download_file():
    content_hash_hex = input("Enter file hash to download: ")
    content_hash = w3.to_bytes(hexstr=content_hash_hex)

    try:
        file_info = contract.functions.getFileInfo(content_hash).call()
        file_name = file_info[0]
        chunk_count = file_info[1]

        if file_name == "":
            print("❌ File not found on blockchain.")
            return

        chunk_dir = rf"D:\chunk\{content_hash_hex}"
        reconstructed_chunks = []

        for i in range(chunk_count):
            chunk_path = os.path.join(chunk_dir, f"chunk_{i}.bin")
            if not os.path.exists(chunk_path):
                print(f"❌ Missing chunk {i}. Download failed.")
                return

            with open(chunk_path, "rb") as chunk_file:
                reconstructed_chunks.append(chunk_file.read())

        file_data = b''.join(reconstructed_chunks)
        output_path = f"downloaded_{file_name}"
        with open(output_path, 'wb') as f:
            f.write(file_data)

        print(f"✅ File saved as '{output_path}'")
    except Exception as e:
        print("❌ Download error:", str(e))
def view_servers():
    try:
        servers, caps = contract.functions.getServers().call()
        print("\n🖥️ Available Servers:")
        if not servers:
            print("⚠️ No servers registered.")
            return
        for s, c in zip(servers, caps):
            print(f"Server {s} - Available Capacity: {c} chunks")
    except Exception as e:
        print("❌ Error viewing servers:", str(e))
def main():
    print("\n📦 Welcome to Decentralized Storage CLI")

    authenticated = False
    while not authenticated:
        print("\n🔐 Please login or register to continue:")
        print("1. Register")
        print("2. Login")
        print("0. Exit")
        choice = input("Select: ")

        if choice == "1":
            register()
        elif choice == "2":
            authenticated = login()
        elif choice == "0":
            print("👋 Exiting.")
            return
        else:
            print("❌ Invalid choice.")

    # Show main menu only after successful login
    while True:
        print("\n📁 Storage Dashboard")
        print("1. Upload File")
        print("2. View Files")
        print("3. Delete File")
        print("4. View Server Capacity")
        print("5. Download File")
        print("6.Get file hash")
        print("0. Logout / Exit")
        choice = input("Select: ")

        if choice == "1":
            upload()
        elif choice == "2":
            view_files()
        elif choice == "3":
            delete_file()
        elif choice == "4":
            view_servers()
        elif choice=='6':
            path=input("Enter the file path:")
            ghash=get_hash(path)
            print(ghash)
        elif choice == "5":
            download_file()
        elif choice == "0":
            print("👋 Logged out.")
            break
        else:
            print("❌ Invalid choice.")


if __name__ == "__main__":
    main()