import os
import socket
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding

PROXY_SERVER_IP = 'localhost'
PROXY_SERVER_PORT = 9999
KEY_SIZE = 32  # AES256

BLOCK_SIZE = 16  # AES block size

#  RSA key pair oluşturma 
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
public_key = private_key.public_key()

# Serialize public key
pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
)

def login(client):
    client.send(b'mehmet:123456')
    
    login_result = client.recv(1)
    return login_result == b'1'

def verify_data_integrity(original_file, received_file):
    original_hash = hashes.Hash(hashes.SHA256())
    received_hash = hashes.Hash(hashes.SHA256())

    with open(original_file, 'rb') as f:
        original_data = f.read()
        original_hash.update(original_data)

    with open(received_file, 'rb') as f:
        received_data = f.read()
        received_hash.update(received_data)

    original_digest = original_hash.finalize()
    received_digest = received_hash.finalize()

    return original_digest == received_digest

def main():
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((PROXY_SERVER_IP, PROXY_SERVER_PORT))
    
    if not login(client):
        print("Authentication failed")
        return
    else:
        print("Authentication Successful")

    client.send(pem)
    
    # receive encrypted session key
    encrypted_session_key_length = int.from_bytes(client.recv(2), 'big')  
    encrypted_session_key = client.recv(encrypted_session_key_length)  

    # decrypt session key
    session_key = private_key.decrypt(
        encrypted_session_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        )
    )
    
    client.send(b"file1")
    
    # take encrypted file data
    encrypted_file_data_length = int.from_bytes(client.recv(4), 'big')  
    encrypted_file_data = client.recv(encrypted_file_data_length)

    print(len(encrypted_file_data))
    print(encrypted_file_data[:BLOCK_SIZE])

    # decrypt file data
    cipher = Cipher(algorithms.AES(session_key), modes.CBC(encrypted_file_data[:BLOCK_SIZE]))
    decryptor = cipher.decryptor()
    unpadder = sym_padding.PKCS7(128).unpadder()
    file_data = unpadder.update(decryptor.update(encrypted_file_data[BLOCK_SIZE:])) + unpadder.finalize()

    print(len(file_data))
    received_file_path = 'received_file'
    try:
        with open(received_file_path, 'wb') as f:
            f.write(file_data)
        print("File written successfully")

        if verify_data_integrity('file1.txt', received_file_path):
            print("Data integrity check passed. The received file is identical to the original file.")
        else:
            print("Data integrity check failed. The received file has been modified.")

    except Exception as e:
        print(f"An error occurred while writing the file: {e}")
        
if __name__ == "__main__":
    main()
