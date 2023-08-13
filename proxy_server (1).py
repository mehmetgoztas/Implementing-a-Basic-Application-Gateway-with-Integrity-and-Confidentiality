import os
import socket
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding

PROXY_SERVER_IP = 'localhost'
PROXY_SERVER_PORT = 9999
FILE_SERVER_IP = 'localhost'
FILE_SERVER_PORT = 9998
KEY_SIZE = 32  # AES256
BLOCK_SIZE = 16  # block size

USERS = {
    'mehmet': '123456',
    'beril': '123456',
}

CACHE = {}

def authenticate(client):
    credentials = client.recv(4096).decode().split(':')
    username = credentials[0]
    password = credentials[1]

    if username in USERS and USERS[username] == password:
        client.send(b'1')  
        return True
    
    else:
        client.send(b'0')
        return False

def main():
    proxy_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    proxy_server.bind((PROXY_SERVER_IP, PROXY_SERVER_PORT))
    proxy_server.listen(5)

    print(f"[*] Listening on {PROXY_SERVER_IP}:{PROXY_SERVER_PORT}")
    while True:
        client, address = proxy_server.accept()
        
        if not authenticate(client):
            print("Authentication failed")
            continue

        #public key
        pem = client.recv(2048)
        public_key = serialization.load_pem_public_key(
            pem,
        )

        #session key
        session_key = os.urandom(KEY_SIZE)

        # encrypt session key
        encrypted_session_key = public_key.encrypt(
            session_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            )
        )

    
        client.send(len(encrypted_session_key).to_bytes(2, 'big'))
        client.send(encrypted_session_key)  

        file_request = client.recv(4096).decode()

        if file_request in CACHE:
            print("Serving from cache")
            file_data = CACHE[file_request]
        else:
            #file server
            file_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            file_server.connect((FILE_SERVER_IP, FILE_SERVER_PORT))
            
            file_server.send(file_request.encode())
            
            file_data = b''
            while True:
                chunk = file_server.recv(4096)
                if not chunk:
                    break
                file_data += chunk
            
            #  unencrypted file data in cache
            CACHE[file_request] = file_data

        padder = sym_padding.PKCS7(128).padder()
        padded_data = padder.update(file_data) + padder.finalize()
        iv = os.urandom(BLOCK_SIZE)
        cipher = Cipher(algorithms.AES(session_key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        encrypted_file_data = iv + encryptor.update(padded_data) + encryptor.finalize()

        # send encrypted file to client
        client.send(len(encrypted_file_data).to_bytes(4, 'big')) 
        client.send(encrypted_file_data)

if __name__ == "__main__":
    main()
