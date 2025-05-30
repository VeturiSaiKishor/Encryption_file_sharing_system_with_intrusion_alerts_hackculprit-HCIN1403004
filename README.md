**AES Encrypted File Sharing System with Intrusion Alerts**
This repository contains a secure file sharing system implemented in Python using AES encryption and Flask. It includes server and client scripts for encrypted file upload and download, as well as an integrated Google Colab notebook example that runs the entire system with ngrok tunneling and intrusion alert logging.

Overview
The system enables users to securely upload and download files encrypted with AES. It uses HTTP Basic Authentication to restrict access and logs intrusion attempts after multiple failed login attempts.

**Files**
1. flask_file_upload.py
Flask server application that accepts file uploads.
Encrypts uploaded files using AES before saving.
Provides an endpoint to download encrypted files.
Implements HTTP Basic Authentication.
Logs intrusion alerts after 3 failed login attempts per user.
2. file_download_client.py
Python client script to download an encrypted file from the Flask server.
Decrypts the downloaded file locally using the AES key.
Requires the encryption key (hex) obtained during upload.
3. file_upload_client.py
Python client script to encrypt a local file and upload it to the Flask server.
Generates a random AES key for encryption.
Prints the encryption key (hex) needed for later decryption.
4. colab_integrated_notebook.py
Fully integrated example combining server and client in one Google Colab notebook.
Runs the Flask server with ngrok tunneling.
Demonstrates file upload, download, encryption, decryption, and intrusion alert logging.
Useful for quick testing and demonstration.

**Setup and Usage**
Prerequisites
Python 3.7+
Required Python packages (install via pip install -r requirements.txt or individually):
flask
flask_httpauth
pycryptodome
pyngrok
requests
Running the Flask Server
Replace the placeholder YOUR_NGROK_AUTHTOKEN_HERE in the server script with your ngrok authtoken.
Run flask_file_upload.py to start the server.
The server will print the ngrok public URL for external access.
Using the Client Scripts
Use file_upload_client.py to encrypt and upload files.
Use file_download_client.py to download and decrypt files.
Both scripts require the server URL, username, password, and encryption key (for download).
Using the Colab Notebook
Open colab_integrated_notebook.py in Google Colab.
Replace the ngrok authtoken placeholder.
Run the notebook cells to start the server, upload, download, and decrypt files seamlessly.

**Security Notes**
AES keys are generated randomly per file and must be securely stored by the client.
HTTP Basic Authentication is used for simplicity; consider stronger auth for production.
Intrusion alerts log repeated failed login attempts to intrusion.log.
Ngrok free tunnels are temporary; URLs change on restart.

**License**
This project is licensed under the MIT License.
