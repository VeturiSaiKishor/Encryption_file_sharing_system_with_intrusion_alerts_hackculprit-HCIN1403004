#AES encryption and file upload using Flask
# Install required packages
!pip install flask flask_httpauth pycryptodome pyngrok

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

# Set your ngrok authtoken here (replace the string below with your actual token)
NGROK_AUTH_TOKEN = "2xlbKkWOLD214ZJF9RsrRaCo4ld_7MmeSA9ZLuQGNVqTf7kRG"
ngrok.set_auth_token(NGROK_AUTH_TOKEN)

# Setup Flask app and auth
app = Flask(__name__)
auth = HTTPBasicAuth()

# In-memory user store with hashed passwords (demo)
users = {
    "user1": generate_password_hash("password1"),
    "user2": generate_password_hash("password2")
}

# Intrusion detection parameters
FAILED_LOGIN_THRESHOLD = 3
failed_login_attempts = {}

# Setup upload folder
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Setup logging for intrusion detection
logging.basicConfig(filename='intrusion.log', level=logging.INFO, format='%(asctime)s %(message)s')

# Authentication verification
@auth.verify_password
def verify_password(username, password):
    if username in users and check_password_hash(users.get(username), password):
        failed_login_attempts[username] = 0  # reset on success
        return username
    else:
        failed_login_attempts[username] = failed_login_attempts.get(username, 0) + 1
        if failed_login_attempts[username] >= FAILED_LOGIN_THRESHOLD:
            alert_msg = f"ALERT: User '{username}' has {failed_login_attempts[username]} failed login attempts!"
            print(alert_msg)
            logging.info(alert_msg)
        return None

# AES encryption function
def encrypt_file(file_data, key):
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(file_data)
    return cipher.nonce + tag + ciphertext

# AES decryption function (for completeness)
def decrypt_file(encrypted_data, key):
    nonce = encrypted_data[:16]
    tag = encrypted_data[16:32]
    ciphertext = encrypted_data[32:]
    cipher = AES.new(key, AES.MODE_EAX, nonce)
    data = cipher.decrypt_and_verify(ciphertext, tag)
    return data

# File upload endpoint with authentication
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

    # Return encryption key in hex (handle securely in production)
    return jsonify({'message': 'File uploaded and encrypted', 'key': key.hex()}), 200

# File download endpoint with authentication
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

    import base64
    encoded_file = base64.b64encode(encrypted_data).decode('utf-8')
    return jsonify({'filename': safe_filename, 'file_data_base64': encoded_file}), 200

# Open ngrok tunnel
public_url = ngrok.connect(5000)
print(f" * ngrok tunnel URL: {public_url}")

# Run Flask app
app.run(port=5000)