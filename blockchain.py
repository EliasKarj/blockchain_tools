import sys
import subprocess
import importlib.util
import os
import json
import re
import hashlib
import time
from datetime import datetime
import binascii

# --- 1. AUTOMATIC DEPENDENCY CHECK ---

def install_and_verify(package_name):
    """
    Checks if a library is installed.
    If not, installs it using pip.
    """
    # Check if the spec for the package exists
    if importlib.util.find_spec(package_name) is None:
        print(f"Installing missing package: {package_name}...")
        try:
            # Run pip install command
            subprocess.check_call([sys.executable, "-m", "pip", "install", package_name])
        except subprocess.CalledProcessError:
            # Stop execution if installation fails
            print(f"ERROR: Failed to install {package_name}.")
            sys.exit(1)

# List of required libraries
install_and_verify("flask")
install_and_verify("crcmod")
install_and_verify("requests")
install_and_verify("ecdsa")

# Import the libraries after installation
from flask import Flask, render_template_string, request, redirect, url_for
import crcmod
import requests
from ecdsa import SigningKey, VerifyingKey, SECP256k1

# Initialize Flask app
app = Flask(__name__)

# Filenames for data storage
FILE_SIMPLE = "db_simple.json"
FILE_SECURE = "db_secure.json"

# Initialize CRC-8 function (for manual testing)
try:
    crc8_func = crcmod.predefined.mkCrcFun('crc-8')
except ImportError:
    print("Error loading CRC module.")
    exit()

# --- CLASSES ---



class Block:
    """
    Represents a single block in the chain.
    Contains data, hash, and linking information.
    """
    def __init__(self, serial, payload, previous_hash, manual_hash=None, algo="SHA-256", nonce=0, difficulty=0):
        self.serial = serial              # Block number
        self.payload = payload            # Data (e.g., transaction info)
        self.previous_hash = previous_hash # Link to the previous block
        self.algo = algo                  # Hashing algorithm used
        self.nonce = int(nonce)           # Number used for mining (Proof of Work)
        self.difficulty = int(difficulty) # Required zeros at start of hash
        
        # Calculate what the hash SHOULD be
        self.correct_hash = self.calculate_hash()
        
        # Logic: Did the user type a hash manually?
        if manual_hash and manual_hash.strip() != "":
            # Use user-provided hash (for testing errors)
            self.manual_hash = manual_hash.upper().strip()
            self.is_generated = False
        else:
            # Use the mathematically correct hash
            self.manual_hash = self.correct_hash
            self.is_generated = True

    def calculate_hash(self):
        """
        Combines block data into a string and hashes it.
        Format: serial|previous_hash|payload|nonce
        """
        # Create the data string
        data_to_hash = f"{self.serial}|{self.previous_hash}|{self.payload}|{self.nonce}"
        # Encode to bytes
        encoded_data = data_to_hash.encode('utf-8')

        # Select algorithm
        if self.algo == "SHA-256":
            return hashlib.sha256(encoded_data).hexdigest().upper()
        elif self.algo == "MD5":
            return hashlib.md5(encoded_data).hexdigest().upper()
        else:
            # Fallback to CRC-8
            hash_value = crc8_func(encoded_data)
            return f"0X{format(hash_value, '02X')}"

    def mine_block(self):
        """
        Proof of Work:
        Loops through 'nonce' values until the hash starts with required zeros.
        """
        # Define the goal (e.g., "00")
        target = "0" * self.difficulty
        self.nonce = 0
        
        # Start guessing
        while True:
            current_hash = self.calculate_hash()
            # Check if hash meets the target
            if current_hash.startswith(target):
                self.manual_hash = current_hash
                self.correct_hash = current_hash
                self.is_generated = True
                return # Success
            
            self.nonce += 1
            # Safety break to prevent infinite loops
            if self.nonce > 50000000: break

    def is_valid(self):
        """
        Checks if the block is valid.
        1. Does the hash match the data?
        2. Does it meet the difficulty requirement?
        """
        # 1. Compare hash
        if self.algo == "CRC-8":
             # Handle 0X prefix for CRC-8
             input_hash = self.manual_hash if self.manual_hash.startswith("0X") else f"0X{self.manual_hash}"
             matches = input_hash == self.correct_hash
        else:
             matches = self.manual_hash == self.correct_hash
        
        # 2. Check difficulty
        if self.difficulty > 0:
            target = "0" * self.difficulty
            if not self.manual_hash.startswith(target):
                return False
        
        return matches

    def get_value(self):
        """
        Extracts a number from the payload text to calculate balance.
        Example: "Payment +50" -> 50.0
        """
        try:
            # Normalize decimal point
            text = self.payload.replace(',', '.')
            # Regex to find number
            match = re.search(r"[-+]?\d*\.?\d+", text)
            return float(match.group()) if match else 0.0
        except:
            return 0.0

    def to_dict(self):
        """Converts block to dictionary for JSON saving."""
        return {
            "serial": self.serial, "payload": self.payload, "previous_hash": self.previous_hash,
            "manual_hash": self.manual_hash, "algo": self.algo, "nonce": self.nonce, "difficulty": self.difficulty
        }

class Blockchain:
    """
    Manages the list of blocks and file operations.
    """
    def __init__(self, filename):
        self.chain = []
        self.filename = filename
        self.load_data() # Load from file on startup

    def add_block(self, serial, payload, prev_hash, manual_hash, algo, difficulty=0, mine=False):
        """Creates a new block and adds it to the chain."""
        new_block = Block(serial, payload, prev_hash, manual_hash, algo, 0, difficulty)
        
        # If mining is requested, run the mining loop
        if mine:
            new_block.mine_block()
            
        self.chain.append(new_block)
        self.save_data() # Save immediately

    def delete_block(self, index):
        """Removes a block by index."""
        if 0 <= index < len(self.chain):
            self.chain.pop(index)
            self.save_data()

    def clear_chain(self):
        """Wipes the entire chain."""
        self.chain = []
        self.save_data()

    def get_total_balance(self):
        """Sum of all numbers found in payloads."""
        return sum(block.get_value() for block in self.chain)

    def get_last_info(self):
        """Returns info for the autofill button."""
        if not self.chain:
            return {"hash": "0" * 8, "next_serial": "1"}
        
        last = self.chain[-1]
        try: 
            next_s = int(last.serial) + 1
        except: 
            next_s = "?"
            
        return {"hash": last.manual_hash, "next_serial": str(next_s)}

    def save_data(self):
        """Saves chain to JSON file."""
        data = [block.to_dict() for block in self.chain]
        try:
            with open(self.filename, 'w') as f:
                json.dump(data, f, indent=4)
        except: pass

    def load_data(self):
        """Loads chain from JSON file."""
        if os.path.exists(self.filename):
            try:
                with open(self.filename, 'r') as f:
                    data = json.load(f)
                    # Reconstruct Block objects
                    self.chain = [Block(d['serial'], d['payload'], d['previous_hash'], d.get('manual_hash'), d.get('algo'), d.get('nonce', 0), d.get('difficulty', 0)) for d in data]
            except: pass

# Initialize two separate blockchains
chain_simple = Blockchain(FILE_SIMPLE)
chain_secure = Blockchain(FILE_SECURE)

# --- BITCOIN API LOGIC ---

def get_bitcoin_block(query=None):
    """
    Fetches real block data from Blockchain.info API.
    """
    try:
        if not query:
            # Get latest block hash
            url = "https://blockchain.info/latestblock"
            data = requests.get(url).json()
            block_hash = data['hash']
        else:
            block_hash = query

        # Get raw block details
        url = f"https://blockchain.info/rawblock/{block_hash}"
        block = requests.get(url).json()
        
        # Process the first 5 transactions
        transactions = []
        for tx in block['tx'][:5]:
            outputs = []
            for out in tx['out']:
                # Convert Satoshi to Bitcoin
                value_btc = out['value'] / 100000000
                addr = out.get('addr', 'Unknown Address')
                outputs.append({'addr': addr, 'value': value_btc})
            
            transactions.append({
                'hash': tx['hash'],
                'outputs': outputs
            })

        return {
            "height": block['height'],
            "hash": block['hash'],
            "prev_hash": block['prev_block'],
            "merkle_root": block['mrkl_root'],
            "time": datetime.utcfromtimestamp(block['time']).strftime('%Y-%m-%d %H:%M:%S'),
            "nonce": block['nonce'],
            "n_tx": block['n_tx'],
            "size": block['size'],
            "transactions": transactions
        }
    except Exception as e:
        print(f"API Error: {e}")
        return {"error": "Block not found or connection error."}

# --- HTML TEMPLATE (English) ---

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Blockchain Lab</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <script>
        function autofill() {
            // Fetch values passed by Flask
            var lastHash = "{{ last_info.hash }}";
            var nextSerial = "{{ last_info.next_serial }}";
            
            var prevInput = document.getElementById('prevHashInput');
            var serialInput = document.getElementById('serialInput');

            if(prevInput) prevInput.value = lastHash;
            if(serialInput) serialInput.value = nextSerial;
        }
        
        function showLoading() {
            var btn = document.getElementById('mineBtn');
            if(btn) {
                btn.innerHTML = '<span class="spinner-border spinner-border-sm"></span> Mining...';
                btn.disabled = true;
                document.getElementById('mineForm').submit();
            }
        }
    </script>
    <style>
        body { background-color: #f4f6f8; }
        .hash-font { font-family: 'Courier New', monospace; font-size: 0.8rem; word-break: break-all; }
        .key-font { font-family: 'Courier New', monospace; font-size: 0.75rem; word-break: break-all; color: #d63384; font-weight: bold; }
        .valid-row { border-left: 5px solid #198754; background: white; }
        .invalid-row { border-left: 5px solid #dc3545; background: #fff5f5; }
        .btc-row { border-left: 5px solid #f7931a; background: white; }
        .wallet-row { border-left: 5px solid #6610f2; background: white; }
        .nonce-badge { background: #6610f2; color: white; font-size: 0.75em; padding: 2px 5px; border-radius: 4px; }
        .nav-tabs .nav-link { color: #495057; }
        .nav-tabs .nav-link.active { font-weight: bold; border-top: 3px solid #0d6efd; color: #0d6efd; }
        .btn-trash { font-weight: bold; text-decoration: none; }
    </style>
</head>
<body>

<nav class="navbar navbar-dark bg-dark mb-4 shadow-sm">
    <div class="container">
        <span class="navbar-brand mb-0 h1">Blockchain Laboratory</span>
    </div>
</nav>

<div class="container">
    <ul class="nav nav-tabs mb-4">
        <li class="nav-item">
            <a class="nav-link {% if mode == 'simple' %}active{% endif %}" href="/">Manual / Testing</a>
        </li>
        <li class="nav-item">
            <a class="nav-link {% if mode == 'secure' %}active{% endif %}" href="/secure">Mining (PoW)</a>
        </li>
        <li class="nav-item">
            <a class="nav-link {% if mode == 'explorer' %}active{% endif %}" href="/explorer">Global Network (Bitcoin)</a>
        </li>
        <li class="nav-item">
            <a class="nav-link {% if mode == 'wallet' %}active{% endif %}" href="/wallet">Crypto Wallet</a>
        </li>
    </ul>

    {% if mode == 'wallet' %}
    
    <div class="row">
        <div class="col-md-12 mb-4">
            <div class="card shadow-sm wallet-row">
                <div class="card-header bg-primary text-white fw-bold">1. Generate Key Pair (Wallet)</div>
                <div class="card-body">
                    <form action="/wallet" method="post">
                        <input type="hidden" name="action" value="generate">
                        <button class="btn btn-primary mb-3">Create New Wallet</button>
                    </form>

                    {% if wallet_data %}
                        <div class="alert alert-secondary">
                            <label class="fw-bold small text-muted">PRIVATE KEY (KEEP SECRET):</label>
                            <div class="key-font text-danger">{{ wallet_data.private_key }}</div>
                            <hr>
                            <label class="fw-bold small text-muted">PUBLIC KEY (ADDRESS):</label>
                            <div class="key-font text-success">{{ wallet_data.public_key }}</div>
                        </div>
                    {% endif %}
                </div>
            </div>
        </div>

        <div class="col-md-6 mb-4">
            <div class="card shadow-sm h-100">
                <div class="card-header bg-dark text-white fw-bold">2. Sign Message</div>
                <div class="card-body">
                    <form action="/wallet" method="post">
                        <input type="hidden" name="action" value="sign">
                        <div class="mb-2">
                            <label class="small">Message (Payload)</label>
                            <input type="text" name="msg" class="form-control" placeholder="e.g. Paying 50 BTC" value="{{ sign_result.msg if sign_result else '' }}" required>
                        </div>
                        <div class="mb-2">
                            <label class="small">Private Key</label>
                            <input type="text" name="priv_key" class="form-control" placeholder="Paste red key here" value="{{ sign_result.priv_key if sign_result else '' }}" required>
                        </div>
                        <button class="btn btn-dark w-100">Sign</button>
                    </form>
                    
                    {% if sign_result and sign_result.signature %}
                        <div class="mt-3 p-2 bg-light border rounded">
                            <label class="small fw-bold">SIGNATURE:</label>
                            <div class="hash-font text-break text-primary">{{ sign_result.signature }}</div>
                        </div>
                    {% endif %}
                </div>
            </div>
        </div>

        <div class="col-md-6 mb-4">
            <div class="card shadow-sm h-100">
                <div class="card-header bg-success text-white fw-bold">3. Verify</div>
                <div class="card-body">
                    <form action="/wallet" method="post">
                        <input type="hidden" name="action" value="verify">
                        <div class="mb-2">
                            <label class="small">Message</label>
                            <input type="text" name="msg" class="form-control" placeholder="Original message" required>
                        </div>
                        <div class="mb-2">
                            <label class="small">Public Key</label>
                            <input type="text" name="pub_key" class="form-control" placeholder="Paste green key here" required>
                        </div>
                        <div class="mb-2">
                            <label class="small">Signature</label>
                            <input type="text" name="signature" class="form-control" placeholder="Paste signature here" required>
                        </div>
                        <button class="btn btn-success w-100">Verify Signature</button>
                    </form>

                    {% if verify_result %}
                        <div class="mt-3 text-center">
                            {% if verify_result.valid %}
                                <div class="alert alert-success fw-bold">[VALID] Signature is authentic</div>
                            {% else %}
                                <div class="alert alert-danger fw-bold">[INVALID] Signature rejected</div>
                            {% endif %}
                        </div>
                    {% endif %}
                </div>
            </div>
        </div>
    </div>

    {% elif mode == 'explorer' %}
    
    <div class="row">
        <div class="col-md-12">
            <div class="card shadow-sm mb-4">
                <div class="card-body">
                    <h5 class="card-title text-primary">Search Real Bitcoin Block</h5>
                    <form action="/explorer" method="post" class="d-flex gap-2">
                        <input type="text" name="query" class="form-control" placeholder="Enter Block Hash (or leave empty for latest)">
                        <button class="btn btn-primary fw-bold">Search</button>
                    </form>
                    <div class="form-text">Data fetched from Blockchain.com API.</div>
                </div>
            </div>

            {% if btc_block %}
                {% if btc_block.error %}
                    <div class="alert alert-danger">{{ btc_block.error }}</div>
                {% else %}
                    <div class="card shadow btc-row mb-4">
                        <div class="card-header bg-warning text-dark fw-bold d-flex justify-content-between">
                            <span>Bitcoin Block #{{ btc_block.height }}</span>
                            <span>{{ btc_block.time }}</span>
                        </div>
                        <div class="card-body">
                            <div class="row mb-2">
                                <div class="col-md-2 fw-bold">Hash:</div>
                                <div class="col-md-10 hash-font small">{{ btc_block.hash }}</div>
                            </div>
                            <div class="row text-center mt-3">
                                <div class="col-md-4"><small>NONCE</small><div class="fw-bold">{{ btc_block.nonce }}</div></div>
                                <div class="col-md-4"><small>TRANSACTIONS</small><div class="fw-bold">{{ btc_block.n_tx }}</div></div>
                                <div class="col-md-4"><small>SIZE</small><div class="fw-bold">{{ btc_block.size }}</div></div>
                            </div>
                        </div>
                    </div>
                    
                    <h5 class="mb-3">Transactions (Top 5)</h5>
                    <div class="table-responsive">
                        <table class="table table-bordered bg-white shadow-sm">
                            <thead class="table-light"><tr><th>TX Hash</th><th>Transfers</th></tr></thead>
                            <tbody>
                                {% for tx in btc_block.transactions %}
                                <tr>
                                    <td class="hash-font text-primary small" style="width:30%">{{ tx.hash[:20] }}...</td>
                                    <td>
                                        <ul class="list-unstyled mb-0 small">
                                            {% for out in tx.outputs %}
                                            <li class="d-flex justify-content-between border-bottom py-1">
                                                <span class="text-muted">{{ out.addr[:20] }}...</span>
                                                <span class="fw-bold text-success">{{ "%.8f"|format(out.value) }} BTC</span>
                                            </li>
                                            {% endfor %}
                                        </ul>
                                    </td>
                                </tr>
                                {% endfor %}
                            </tbody>
                        </table>
                    </div>
                {% endif %}
            {% endif %}
        </div>
    </div>

    {% else %}

    <div class="row">
        <div class="col-md-4">
            <div class="card shadow-sm border-0 mb-3">
                <div class="card-header fw-bold text-white {% if mode == 'simple' %}bg-primary{% else %}bg-success{% endif %} d-flex justify-content-between align-items-center">
                    {% if mode == 'simple' %}Add Block{% else %}Mine Block{% endif %}
                    <button type="button" class="btn btn-sm btn-light text-dark fw-bold" onclick="autofill()">Get Last</button>
                </div>
                <div class="card-body">
                    <form action="{% if mode == 'simple' %}/add_simple{% else %}/mine_secure{% endif %}" method="post" id="mineForm" {% if mode == 'secure' %}onsubmit="event.preventDefault(); showLoading();"{% endif %}>
                        
                        {% if mode == 'secure' %}
                        <div class="mb-2">
                            <label class="small fw-bold">Difficulty</label>
                            <select name="difficulty" class="form-select form-select-sm">
                                <option value="1">1 (Easy)</option>
                                <option value="2" selected>2 (Normal)</option>
                                <option value="3">3 (Hard)</option>
                                <option value="4">4 (Hardcore)</option>
                            </select>
                        </div>
                        {% else %}
                        <div class="mb-2">
                            <label class="small fw-bold">Algorithm</label>
                            <select name="algo" class="form-select form-select-sm">
                                <option value="CRC-8">CRC-8 (Paper Test)</option>
                                <option value="SHA-256">SHA-256</option>
                                <option value="MD5">MD5</option>
                            </select>
                        </div>
                        {% endif %}

                        <div class="input-group mb-2">
                            <span class="input-group-text">#</span>
                            <input type="text" name="serial" id="serialInput" class="form-control" placeholder="Serial" required>
                        </div>
                        <div class="mb-2">
                            <input type="text" name="prev_hash" id="prevHashInput" class="form-control" placeholder="Prev Hash" required>
                        </div>
                        <div class="mb-3">
                            <input type="text" name="payload" class="form-control fw-bold" placeholder="Payload (e.g. +100)" required>
                        </div>

                        {% if mode == 'simple' %}
                        <div class="mb-3">
                            <input type="text" name="manual_hash" class="form-control form-control-sm" placeholder="Hash (Optional)">
                            <div class="form-text">Leave empty to auto-generate.</div>
                        </div>
                        {% endif %}

                        <button type="submit" id="mineBtn" class="btn w-100 fw-bold {% if mode == 'simple' %}btn-primary{% else %}btn-success{% endif %}">
                            {% if mode == 'simple' %}Add to Chain{% else %}START MINING{% endif %}
                        </button>
                    </form>
                </div>
            </div>

            <div class="card bg-dark text-white p-3 text-center shadow mb-3">
                <small>BALANCE</small>
                <h2 class="mb-0">{{ "%.2f"|format(total_balance) }}</h2>
            </div>

            <form action="{% if mode == 'simple' %}/clear_simple{% else %}/clear_secure{% endif %}" method="post">
                <button class="btn btn-outline-danger btn-sm w-100" onclick="return confirm('Clear entire list?')">Clear List</button>
            </form>
        </div>

        <div class="col-md-8">
            {% if not chain %}
                <div class="alert alert-light text-center">Chain is empty.</div>
            {% endif %}

            {% for b in chain[::-1] %}
            <div class="card mb-2 shadow-sm {% if b.is_valid() %}valid-row{% else %}invalid-row{% endif %}">
                <div class="card-body py-2">
                    <div class="d-flex justify-content-between align-items-center">
                        <h6 class="mb-0">#{{ b.serial }} <span class="badge bg-secondary">{{ b.algo }}</span></h6>
                        <div>
                            {% if b.nonce > 0 %}<span class="nonce-badge">Nonce: {{ b.nonce }}</span>{% endif %}
                            
                            <form action="{% if mode == 'simple' %}/delete_simple/{{ loop.index0 }}{% else %}/delete_secure/{{ loop.index0 }}{% endif %}" method="post" style="display:inline;">
                                <button class="btn btn-sm text-danger border-0 btn-trash">DELETE</button>
                            </form>
                        </div>
                    </div>
                    
                    <div class="fs-5 fw-bold text-primary my-1">{{ b.payload }}</div>

                    <div class="row g-0 mt-2 bg-light rounded p-2" style="font-size: 0.8rem;">
                        <div class="col-12 text-muted">PREV: <span class="hash-font">{{ b.previous_hash }}</span></div>
                        <div class="col-12 text-dark mt-1">
                            HASH: <span class="hash-font fw-bold">{{ b.manual_hash }}</span>
                            {% if not b.is_valid() %}
                                <span class="text-danger fw-bold ms-2">ERROR! Expected: {{ b.correct_hash }}</span>
                            {% endif %}
                        </div>
                    </div>
                </div>
            </div>
            {% endfor %}
        </div>
    </div>
    {% endif %}
</div>

</body>
</html>
"""

# --- FLASK ROUTES ---

@app.route('/')
def index_simple():
    """Renders the Manual / Testing page."""
    return render_template_string(HTML_TEMPLATE, mode='simple', chain=chain_simple.chain, total_balance=chain_simple.get_total_balance(), last_info=chain_simple.get_last_info())

@app.route('/secure')
def index_secure():
    """Renders the Mining (PoW) page."""
    return render_template_string(HTML_TEMPLATE, mode='secure', chain=chain_secure.chain, total_balance=chain_secure.get_total_balance(), last_info=chain_secure.get_last_info())

@app.route('/explorer', methods=['GET', 'POST'])
def explorer():
    """Renders the Real Bitcoin Explorer page."""
    btc_block = None
    if request.method == 'POST':
        query = request.form.get('query')
        btc_block = get_bitcoin_block(query)
    
    # We pass last_info here too to prevent JS errors with the autofill function
    return render_template_string(HTML_TEMPLATE, mode='explorer', btc_block=btc_block, last_info=chain_simple.get_last_info())

@app.route('/wallet', methods=['GET', 'POST'])
def wallet():
    """Renders the Crypto Wallet page."""
    wallet_data = None
    sign_result = None
    verify_result = None
    
    if request.method == 'POST':
        action = request.form.get('action')
        
        # 1. Generate Keys
        if action == 'generate':
            sk = SigningKey.generate(curve=SECP256k1)
            vk = sk.verifying_key
            wallet_data = {
                'private_key': binascii.hexlify(sk.to_string()).decode(),
                'public_key': binascii.hexlify(vk.to_string()).decode()
            }
        
        # 2. Sign Message
        elif action == 'sign':
            msg = request.form.get('msg')
            priv_key_hex = request.form.get('priv_key')
            try:
                sk = SigningKey.from_string(binascii.unhexlify(priv_key_hex), curve=SECP256k1)
                signature = sk.sign(msg.encode())
                sign_result = {
                    'msg': msg,
                    'priv_key': priv_key_hex,
                    'signature': binascii.hexlify(signature).decode()
                }
            except Exception as e:
                sign_result = {'msg': msg, 'priv_key': priv_key_hex, 'signature': "ERROR: " + str(e)}

        # 3. Verify Signature
        elif action == 'verify':
            msg = request.form.get('msg')
            pub_key_hex = request.form.get('pub_key')
            sig_hex = request.form.get('signature')
            try:
                vk = VerifyingKey.from_string(binascii.unhexlify(pub_key_hex), curve=SECP256k1)
                is_valid = vk.verify(binascii.unhexlify(sig_hex), msg.encode())
                verify_result = {'valid': True}
            except:
                verify_result = {'valid': False}

    return render_template_string(HTML_TEMPLATE, mode='wallet', 
                                  last_info=chain_simple.get_last_info(),
                                  wallet_data=wallet_data,
                                  sign_result=sign_result,
                                  verify_result=verify_result)

# --- ACTIONS (SIMPLE CHAIN) ---

@app.route('/add_simple', methods=['POST'])
def add_simple():
    """Adds a block to the simple chain."""
    chain_simple.add_block(
        request.form.get('serial'), request.form.get('payload'),
        request.form.get('prev_hash'), request.form.get('manual_hash'),
        request.form.get('algo'), difficulty=0, mine=False
    )
    return redirect(url_for('index_simple'))

@app.route('/delete_simple/<int:rev_index>', methods=['POST'])
def delete_simple(rev_index):
    """Deletes a block from the simple chain."""
    # Convert reversed index (UI) to real index (List)
    real_index = len(chain_simple.chain) - 1 - rev_index
    chain_simple.delete_block(real_index)
    return redirect(url_for('index_simple'))

@app.route('/clear_simple', methods=['POST'])
def clear_simple():
    """Clears the simple chain."""
    chain_simple.clear_chain()
    return redirect(url_for('index_simple'))

# --- ACTIONS (SECURE CHAIN) ---

@app.route('/mine_secure', methods=['POST'])
def mine_secure():
    """Mines a block for the secure chain."""
    chain_secure.add_block(
        request.form.get('serial'), request.form.get('payload'),
        request.form.get('prev_hash'), manual_hash="", 
        algo="SHA-256", 
        difficulty=request.form.get('difficulty'), mine=True
    )
    return redirect(url_for('index_secure'))

@app.route('/delete_secure/<int:rev_index>', methods=['POST'])
def delete_secure(rev_index):
    """Deletes a block from the secure chain."""
    real_index = len(chain_secure.chain) - 1 - rev_index
    chain_secure.delete_block(real_index)
    return redirect(url_for('index_secure'))

@app.route('/clear_secure', methods=['POST'])
def clear_secure():
    """Clears the secure chain."""
    chain_secure.clear_chain()
    return redirect(url_for('index_secure'))

if __name__ == '__main__':
    # Start the server in debug mode
    app.run(debug=True)