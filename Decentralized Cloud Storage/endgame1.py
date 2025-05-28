import os
import json
import re
from dotenv import load_dotenv
from web3 import Web3
from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = os.urandom(24)  # For session management

# Load environment variables
load_dotenv()
RPC_URL = os.getenv("WEB3_PROVIDER")
PRIVATE_KEY = os.getenv("PRIVATE_KEY")
ACCOUNT_ADDRESS = os.getenv("ACCOUNT_ADDRESS")
CONTRACT_ADDRESS = os.getenv("CONTRACT_ADDRESS")

# Web3 connection
w3 = Web3(Web3.HTTPProvider(RPC_URL))
if not w3.is_connected():
    flash("Cannot connect to Web3 provider.", "error")
    raise Exception("Web3 connection failed")

# Load contract ABI
try:
    with open('StorageContract.json') as f:
        contract_json = json.load(f)
    abi = contract_json['abi']
    contract = w3.eth.contract(address=Web3.to_checksum_address(CONTRACT_ADDRESS), abi=abi)
except Exception as e:
    flash(f"Failed to load contract ABI: {str(e)}", "error")
    raise

def sanitize_filename(filename):
    safe_name = secure_filename(filename)
    safe_name = re.sub(r'\s+', '_', safe_name)  # Replace spaces with underscores
    return safe_name

def convergent_hash(data):
    return Web3.keccak(data)  # Returns 32 bytes (bytes32)

def split_chunks(data: bytes, num_chunks: int):
    if num_chunks <= 0:
        return []
    chunk_size = len(data) // num_chunks
    if chunk_size == 0:
        chunk_size = 1  # Minimum chunk size
    return [data[i:i+chunk_size] for i in range(0, len(data), chunk_size)]

def greedy_allocate(share_count):
    try:
        servers, capacities = contract.functions.getServers().call()
        print(f"Available servers: {servers}, Capacities: {capacities}")  # Debug
        if not servers:
            flash("No servers registered.", "error")
            return []
        available = sorted(zip(capacities, servers), reverse=True)
        allocation = []
        for chunk_id in range(share_count):
            available.sort(reverse=True)
            for i, (cap, server) in enumerate(available):
                if cap > 0:
                    allocation.append(server)
                    available[i] = (cap - 1, server)
                    print(f"Allocated chunk {chunk_id} to server {server}")  # Debug
                    break
            else:
                flash("Not enough server capacity for all chunks.", "error")
                return []
        return allocation
    except Exception as e:
        flash(f"Error in greedy allocation: {str(e)}", "error")
        return []

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

def check_registration():
    try:
        registered = contract.functions.isRegistered(ACCOUNT_ADDRESS).call()
        print(f"Registration status for {ACCOUNT_ADDRESS}: {registered}")  # Debug
        return registered
    except Exception as e:
        flash(f"Error checking registration: {str(e)}", "error")
        return False

@app.route('/')
def home():
    if not session.get('authenticated'):
        return redirect(url_for('login'))
    return render_template('home.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if session.get('authenticated'):
        flash("Already registered.", "warning")
        return redirect(url_for('home'))
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if check_registration():
            flash("Already registered.", "warning")
            return redirect(url_for('home'))
        try:
            build_transaction(contract.functions.registerUser(username, password))
            flash("Registered successfully.", "success")
            return redirect(url_for('login'))
        except Exception as e:
            flash(f"Registration error: {str(e)}", "error")
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if session.get('authenticated'):
        return redirect(url_for('home'))
    if request.method == 'POST':
        password = request.form['password']
        try:
            authenticated = contract.functions.authenticate(password).call({'from': ACCOUNT_ADDRESS})
            print(f"Authentication result: {authenticated}")  # Debug
            if authenticated:
                session['authenticated'] = True
                flash("Login successful.", "success")
                return redirect(url_for('home'))
            else:
                flash("Login failed.", "error")
        except Exception as e:
            flash(f"Login error: {str(e)}", "error")
    return render_template('login.html')

@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if not session.get('authenticated'):
        return redirect(url_for('login'))
    if request.method == 'POST':
        file = request.files['file']
        try:
            share_count = int(request.form['share_count'])
            if share_count <= 0:
                flash("Share count must be positive.", "error")
                return redirect(url_for('upload'))
        except ValueError:
            flash("Invalid share count.", "error")
            return redirect(url_for('upload'))
        if not file:
            flash("No file selected.", "error")
            return redirect(url_for('upload'))
        filename = sanitize_filename(file.filename)
        file_path = os.path.join('uploads', filename)
        os.makedirs('uploads', exist_ok=True)
        file.save(file_path)
        if not os.path.exists(file_path):
            flash("Failed to save uploaded file.", "error")
            return redirect(url_for('upload'))
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
            if not data:
                flash("File is empty.", "error")
                return redirect(url_for('upload'))
            file_hash = convergent_hash(data)
            content_hash = file_hash  # Already bytes32
            print(f"Uploading file: {filename}, Hash: {file_hash.hex()}, Share count: {share_count}")  # Debug
            print("Checking for existing file...")  # Debug
            try:
                existing = contract.functions.getFileInfo(content_hash).call()
                print(f"Existing file info: {existing}")  # Debug
                if existing[0] != "":
                    flash("File already uploaded.", "error")
                    return redirect(url_for('upload'))
            except Exception as e:
                print(f"getFileInfo failed (expected for new file): {str(e)}")  # Debug
                # Continue, as revert means file doesn't exist
            # Check for duplicate filename
            _, user_file_names = contract.functions.viewMyFiles().call({'from': ACCOUNT_ADDRESS})
            if filename in user_file_names:
                flash("A file with the same name already exists.", "error")
                return redirect(url_for('upload'))

            print("Calling uploadFile...")  # Debug
            build_transaction(contract.functions.uploadFile(content_hash, filename, share_count))
            print("uploadFile successful, splitting chunks...")  # Debug
            chunks = split_chunks(data, share_count)
            if len(chunks) < share_count:
                flash("File too small for specified share count.", "error")
                return redirect(url_for('upload'))
            print("Allocating chunks...")  # Debug
            servers = greedy_allocate(share_count)
            if not servers:
                flash("Could not allocate chunks to servers.", "error")
                return redirect(url_for('upload'))
            chunk_dir = rf"D:\chunk\{content_hash.hex()}"  # Use D:\chunk\<file_hash>
            print(f"Creating chunk directory: {chunk_dir}")  # Debug
            os.makedirs(chunk_dir, exist_ok=True)
            for i, server in enumerate(servers):
                chunk_data=chunks[i]
                chunk_name = f"chunk_{i}.bin"
                
                with open(f"{chunk_dir}/chunk_{i}.bin", "wb") as chunk_file:
                    chunk_file.write(chunk_data)
                print(f"📦 Allocating chunk {i} to server {server}")
                build_transaction(contract.functions.allocateChunk(content_hash, i, server))
            flash("File uploaded and chunks allocated.", "success")
        except Exception as e:
            flash(f"Upload error: {str(e)}", "error")
            print(f"Upload error details: {str(e)}")  # Debug
        finally:
            if os.path.exists(file_path):
                os.remove(file_path)  # Clean up
    return render_template('upload.html')

@app.route('/view_files')
def view_files():
    if not session.get('authenticated'):
        return redirect(url_for('login'))
    try:
        contentHashes, fileNames = contract.functions.viewMyFiles().call({'from': ACCOUNT_ADDRESS})
        files = [(h.hex(), name) for h, name in zip(contentHashes, fileNames)]
        print(f"Files retrieved: {files}")  # Debug
        return render_template('view_files.html', files=files)
    except Exception as e:
        flash(f"Error viewing files: {str(e)}", "error")
        return redirect(url_for('home'))

@app.route('/delete_file', methods=['GET', 'POST'])
def delete_file():
    if not session.get('authenticated'):
        return redirect(url_for('login'))
    if request.method == 'POST':
        content_hash_hex = request.form['content_hash'].strip()
        try:
            # Normalize hash: prepend '0x' if missing
            original_input = content_hash_hex
            if not content_hash_hex.startswith('0x'):
                content_hash_hex = '0x' + content_hash_hex
            print(f"Delete - Input hash: {original_input}, Normalized: {content_hash_hex}")  # Debug
            # Validate hash format
            if len(content_hash_hex) != 66 or not re.match(r'^0x[0-9a-fA-F]{64}$', content_hash_hex):
                flash("Invalid content hash format. Must be 64 hexadecimal characters (with or without '0x').", "error")
                return redirect(url_for('delete_file'))
            content_hash = w3.to_bytes(hexstr=content_hash_hex)
            try:
                file_info = contract.functions.getFileInfo(content_hash).call()
                print(f"File info for delete: {file_info}")  # Debug
                if file_info[0] == "":
                    flash("File not found on blockchain.", "error")
                    return redirect(url_for('delete_file'))
            except Exception as e:
                flash("File not found on blockchain.", "error")
                print(f"getFileInfo for delete failed: {str(e)}")  # Debug
                return redirect(url_for('delete_file'))
            build_transaction(contract.functions.deleteFile(content_hash))
            flash("File deleted successfully.", "success")
        except Exception as e:
            flash(f"Delete error: {str(e)}", "error")
            print(f"Delete error details: {str(e)}")  # Debug
        return redirect(url_for('view_files'))
    return render_template('delete_file.html')

@app.route('/view_servers')
def view_servers():
    if not session.get('authenticated'):
        return redirect(url_for('login'))
    try:
        servers, caps = contract.functions.getServers().call()
        server_list = [(s, c) for s, c in zip(servers, caps)]
        print(f"Servers retrieved: {server_list}")  # Debug
        return render_template('view_servers.html', servers=server_list)
    except Exception as e:
        flash(f"Error viewing servers: {str(e)}", "error")
        return redirect(url_for('home'))

@app.route('/download_file', methods=['GET', 'POST'])
def download_file():
    if not session.get('authenticated'):
        return redirect(url_for('login'))

    if request.method == 'POST':
        content_hash_hex = request.form['content_hash'].strip()

        try:
            # Normalize the content hash
            if not content_hash_hex.startswith('0x'):
                content_hash_hex = '0x' + content_hash_hex
            print(f"[DEBUG] Normalized hash: {content_hash_hex}")

            # Validate content hash format
            if len(content_hash_hex) != 66 or not re.match(r'^0x[0-9a-fA-F]{64}$', content_hash_hex):
                flash("Invalid content hash format. Must be 64 hex characters (with or without '0x').", "error")
                return redirect(url_for('download_file'))

            content_hash = w3.to_bytes(hexstr=content_hash_hex)

            # Fetch file information from blockchain
            file_info = contract.functions.getFileInfo(content_hash).call()
            file_name, chunk_count, owner, chunk_locations = file_info[0], file_info[1], file_info[2], file_info[3]

            if file_name == "":
                flash("File not found on blockchain.", "error")
                return redirect(url_for('download_file'))

            print(f"[DEBUG] File to reconstruct: {file_name}, Total chunks: {chunk_count}")

            # Local chunk directory
            folder_name = content_hash_hex[2:] if content_hash_hex.startswith('0x') else content_hash_hex
            chunk_dir = rf"D:\chunk\{folder_name}"
                

            if not os.path.exists(chunk_dir):
                flash(f"Chunk directory not found at: {chunk_dir}", "error")
                return redirect(url_for('download_file'))

            # Reconstruct file from chunks
            reconstructed_chunks = []
            for i in range(chunk_count):
                chunk_path = os.path.join(chunk_dir, f"chunk_{i}.bin")
                if not os.path.exists(chunk_path):
                    flash(f"Missing chunk {i}. Cannot complete download.", "error")
                    return redirect(url_for('download_file'))

                with open(chunk_path, "rb") as chunk_file:
                    reconstructed_chunks.append(chunk_file.read())

            # Combine chunks
            file_data = b''.join(reconstructed_chunks)

            # Save reconstructed file
            os.makedirs('downloads', exist_ok=True)
            output_path = os.path.join('downloads', f"downloaded_{sanitize_filename(file_name)}")
            with open(output_path, 'wb') as out:
                out.write(file_data)

            flash(f"✅ File reconstructed and saved at: {output_path}", "success")
        except Exception as e:
            print(f"[ERROR] Download error: {str(e)}")
            flash(f"Unexpected download error: {str(e)}", "error")

        return redirect(url_for('download_file'))

    return render_template('download_file.html')


@app.route('/get_hash', methods=['GET', 'POST'])
def get_hash_route():
    if not session.get('authenticated'):
        return redirect(url_for('login'))
    if request.method == 'POST':
        file = request.files['file']
        if not file:
            flash("No file selected.", "error")
            return redirect(url_for('get_hash_route'))
        filename = sanitize_filename(file.filename)
        file_path = os.path.join('uploads', filename)
        os.makedirs('uploads', exist_ok=True)
        file.save(file_path)
        hash_value = get_hash(file_path)
        flash(f"File hash: {hash_value}", "success")
        if os.path.exists(file_path):
            os.remove(file_path)  # Clean up
        return redirect(url_for('get_hash_route'))
    return render_template('get_hash.html')

@app.route('/logout')
def logout():
    session.pop('authenticated', None)
    flash("Logged out.", "success")
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)