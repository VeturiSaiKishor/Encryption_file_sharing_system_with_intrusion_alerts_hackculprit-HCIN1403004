#this is a fully integrated code that runs Flask encryption file sharing server with ngrok, prints the public URL, and then runs the client upload and download script using that URL

# Install required packages
!pip install flask flask_httpauth pycryptodome pyngrok requests

# Imports
from flask import Flask, request, jsonify
from flask_httpauth import HTTPBasicAuth
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import os
import logging
from pyngrok import ngrok
import threading
import time
import requests
import base64

# Flask app and auth setup
app = Flask(__name__)
auth = HTTPBasicAuth()

users = {
    "user1": generate_password_hash("password1"),
    "user2": generate_password_hash("password2")
}

FAILED_LOGIN_THRESHOLD = 3
failed_login_attempts = {}

UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

logging.basicConfig(filename='intrusion.log', level=logging.INFO, format='%(asctime)s %(message)s')

@auth.verify_password
def verify_password(username, password):
    if username in users and check_password_hash(users.get(username), password):
        failed_login_attempts[username] = 0
        return username
    else:
        failed_login_attempts[username] = failed_login_attempts.get(username, 0) + 1
        if failed_login_attempts[username] >= FAILED_LOGIN_THRESHOLD:
            alert_msg = f"ALERT: User '{username}' has {failed_login_attempts[username]} failed login attempts!"
            print(alert_msg)
            logging.info(alert_msg)
        return None

def encrypt_file(file_data, key):
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(file_data)
    return cipher.nonce + tag + ciphertext

def decrypt_file(encrypted_data, key):
    nonce = encrypted_data[:16]
    tag = encrypted_data[16:32]
    ciphertext = encrypted_data[32:]
    cipher = AES.new(key, AES.MODE_EAX, nonce)
    data = cipher.decrypt_and_verify(ciphertext, tag)
    return data

@app.route('/upload', methods=['POST'])
@auth.login_required
def upload_file():
    username = auth.current_user()
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400

    file_data = file.read()
    key = get_random_bytes(16)
    encrypted_data = encrypt_file(file_data, key)

    filename = secure_filename(file.filename) + '.enc'
    filepath = os.path.join(UPLOAD_FOLDER, filename)
    with open(filepath, 'wb') as f:
        f.write(encrypted_data)

    log_msg = f"User '{username}' uploaded file '{filename}'"
    print(log_msg)
    logging.info(log_msg)

    return jsonify({'message': 'File uploaded and encrypted', 'key': key.hex(), 'filename': filename}), 200

@app.route('/download/<filename>', methods=['GET'])
@auth.login_required
def download_file(filename):
    username = auth.current_user()
    safe_filename = secure_filename(filename)
    filepath = os.path.join(UPLOAD_FOLDER, safe_filename)
    if not os.path.exists(filepath):
        return jsonify({'error': 'File not found'}), 404

    with open(filepath, 'rb') as f:
        encrypted_data = f.read()

    log_msg = f"User '{username}' downloaded file '{safe_filename}'"
    print(log_msg)
    logging.info(log_msg)

    encoded_file = base64.b64encode(encrypted_data).decode('utf-8')
    return jsonify({'filename': safe_filename, 'file_data_base64': encoded_file}), 200

# Function to run Flask app in a thread
def run_flask():
    app.run(port=5000)

# Start ngrok tunnel
ngrok.set_auth_token("2xlbKkWOLD214ZJF9RsrRaCo4ld_7MmeSA9ZLuQGNVqTf7kRG")  # Replace with your ngrok authtoken
public_tunnel = ngrok.connect(5000)
public_url = public_tunnel.public_url
print(f"Ngrok tunnel URL: {public_url}")

# Start Flask app in background thread
flask_thread = threading.Thread(target=run_flask)
flask_thread.daemon = True
flask_thread.start()

# Wait a moment for server to start
time.sleep(3)

# Client upload and download functions
def client_encrypt_and_upload(filepath):
    with open(filepath, 'rb') as f:
        data = f.read()
    key = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    encrypted_data = cipher.nonce + tag + ciphertext

    files = {'file': (os.path.basename(filepath) + '.enc', encrypted_data)}
    response = requests.post(f"{public_url}/upload", files=files, auth=('user1', 'password1'))
    if response.status_code == 200:
        json_resp = response.json()
        print("Upload successful:", json_resp['message'])
        print("Encryption key (hex):", json_resp['key'])
        return json_resp['key'], json_resp['filename']
    else:
        print("Upload failed:", response.text)
        return None, None

def client_download_and_decrypt(filename, key_hex, output_path):
    response = requests.get(f"{public_url}/download/{filename}", auth=('user1', 'password1'))
    if response.status_code != 200:
        print("Download failed:", response.text)
        return

    json_data = response.json()
    encrypted_b64 = json_data['file_data_base64']
    encrypted_data = base64.b64decode(encrypted_b64)

    key = bytes.fromhex(key_hex)
    try:
        nonce = encrypted_data[:16]
        tag = encrypted_data[16:32]
        ciphertext = encrypted_data[32:]
        cipher = AES.new(key, AES.MODE_EAX, nonce)
        decrypted_data = cipher.decrypt_and_verify(ciphertext, tag)
    except Exception as e:
        print("Decryption failed:", e)
        return

    with open(output_path, 'wb') as f:
        f.write(decrypted_data)
    print(f"File downloaded and decrypted successfully as '{output_path}'")

# Example usage: upload and download a sample file
sample_filename = "sample.txt"

# Create a sample file
with open(sample_filename, "w") as f:
    f.write("This is a test file for encryption and upload.")

# Upload
key_hex, enc_filename = client_encrypt_and_upload(sample_filename)

# Download and decrypt if upload succeeded
if key_hex and enc_filename:
    client_download_and_decrypt(enc_filename, key_hex, "decrypted_" + sample_filename)