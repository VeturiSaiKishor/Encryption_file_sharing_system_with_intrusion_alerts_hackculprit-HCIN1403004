#Python script that uploads an encrypted file from your Flask server
import requests
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64

# Server URL and credentials
SERVER_URL = "https://d2e2-34-139-4-229.ngrok-free.app"  # Replace with your actual ngrok URL
USERNAME = "user1"
PASSWORD = "password1"

# AES encryption function
def encrypt_file(filepath, key):
    with open(filepath, 'rb') as f:
        data = f.read()
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return cipher.nonce + tag + ciphertext

# AES decryption function
def decrypt_file(encrypted_data, key, output_path):
    nonce = encrypted_data[:16]
    tag = encrypted_data[16:32]
    ciphertext = encrypted_data[32:]
    cipher = AES.new(key, AES.MODE_EAX, nonce)
    data = cipher.decrypt_and_verify(ciphertext, tag)
    with open(output_path, 'wb') as f:
        f.write(data)

# Upload encrypted file
def upload_file(filepath):
    key = get_random_bytes(16)  # Generate a random AES key
    encrypted_data = encrypt_file(filepath, key)

    # Save encrypted file locally (optional)
    with open("encrypted_upload.enc", "wb") as f:
        f.write(encrypted_data)

    # Upload encrypted file to server
    files = {'file': ('encrypted_upload.enc', encrypted_data)}
    response = requests.post(f"{SERVER_URL}/upload", files=files, auth=(USERNAME, PASSWORD))
    if response.status_code == 200:
        print("Upload successful")
        print("Encryption key (hex):", key.hex())
        return key
    else:
        print("Upload failed:", response.text)
        return None

# Download encrypted file and decrypt
def download_and_decrypt(filename, key, output_path):
    response = requests.get(f"{SERVER_URL}/download/{filename}", auth=(USERNAME, PASSWORD))
    if response.status_code == 200:
        json_data = response.json()
        encrypted_b64 = json_data['file_data_base64']
        encrypted_data = base64.b64decode(encrypted_b64)
        decrypt_file(encrypted_data, key, output_path)
        print(f"File downloaded and decrypted to {output_path}")
    else:
        print("Download failed:", response.text)
from google.colab import files
uploaded = files.upload()
# Example usage
if __name__ == "__main__":
    # Replace 'test.txt' with your file to upload
    key = upload_file("test.txt")
    if key:
        # Replace 'test.txt.enc' with the encrypted filename on server
        download_and_decrypt("test.txt.enc", key, "decrypted_test.txt")