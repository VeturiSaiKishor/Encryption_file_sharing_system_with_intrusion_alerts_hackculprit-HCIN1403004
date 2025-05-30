#Python script that downloads an encrypted file from your Flask server
!pip install pycryptodome

import requests
import base64
from Crypto.Cipher import AES

# Configuration - replace these with your actual values
SERVER_URL = "https://d2e2-34-139-4-229.ngrok-free.app"  # Your ngrok public URL
FILENAME = "test.enc"              # Encrypted filename on server
USERNAME = "user1"
PASSWORD = "password1"
OUTPUT_DECRYPTED_PATH = "decrypted_file"  # Path to save decrypted file

# Your AES key in hex (from upload response)
AES_KEY_HEX = "your_hex_key_here"

def decrypt_file(encrypted_data, key):
    nonce = encrypted_data[:16]
    tag = encrypted_data[16:32]
    ciphertext = encrypted_data[32:]
    cipher = AES.new(key, AES.MODE_EAX, nonce)
    data = cipher.decrypt_and_verify(ciphertext, tag)
    return data

def download_and_decrypt():
    response = requests.get(f"{SERVER_URL}/download/{FILENAME}", auth=(USERNAME, PASSWORD))
    if response.status_code != 200:
        print(f"Failed to download file: {response.status_code} {response.text}")
        return

    json_data = response.json()
    encrypted_b64 = json_data['file_data_base64']
    encrypted_data = base64.b64decode(encrypted_b64)

    key = bytes.fromhex(AES_KEY_HEX)
    try:
        decrypted_data = decrypt_file(encrypted_data, key)
    except Exception as e:
        print(f"Decryption failed: {e}")
        return

    with open(OUTPUT_DECRYPTED_PATH, 'wb') as f:
        f.write(decrypted_data)

    print(f"File downloaded and decrypted successfully as '{OUTPUT_DECRYPTED_PATH}'")

if __name__ == "__main__":
    download_and_decrypt()