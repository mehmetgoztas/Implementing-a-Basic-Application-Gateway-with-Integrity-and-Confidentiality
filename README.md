# Implementing-a-Basic-Application-Gateway-with-Integrity-and-Confidentiality
# Secure File Transfer System with Proxy Server

## Introduction

This project implements a secure file transfer system using a proxy server. The system allows clients to securely transfer files from a file server through the proxy server, ensuring confidentiality, integrity, and authenticity of the transferred files. This documentation covers the design, implementation details, and usage of the proxy server.

## Design Overview

The proxy server acts as an intermediary between the client and the file server, facilitating secure file transfer. It provides encryption and authentication mechanisms to ensure the confidentiality and integrity of the data. The system consists of three main components: the client, the proxy server, and the file server. The client initiates file transfer requests, the proxy server handles the requests, and the file server hosts the files to be transferred.

## Programming Language and Libraries

The proxy server is implemented using the Python programming language. It leverages various libraries to enable secure file transfer, including:

- `socket`: Provides socket programming functionalities for network communication.
- `os`: Offers operating system-dependent functionalities for file operations and generating random numbers.
- `cryptography`: A library that provides cryptographic primitives and high-level encryption/decryption interfaces.

## Encryption and Hashing Algorithms

The proxy server utilizes the following encryption and hashing algorithms to ensure secure file transfer:

- RSA: An asymmetric encryption algorithm used for secure key exchange and authentication. The proxy server and the client generate RSA key pairs to establish a secure communication channel.
- AES-256: A symmetric encryption algorithm used for encrypting file data. It provides a high level of security and efficiency.
- SHA-256: A cryptographic hash function used for data integrity verification. It ensures that the received file data has not been tampered with during transmission.

## Implementation Details

1. **Request Handling:**
The proxy server listens for incoming client connections on a specified IP address and port. When a client connects, it verifies the client's credentials by comparing them against the user database. If the authentication is successful, the server proceeds with the file transfer process. Otherwise, the connection is rejected.

2. **Proxy Functionality:**
Once the client is authenticated, the server establishes a secure communication channel with the client using RSA encryption. The server generates a session key, encrypts it using the client's public key, and sends it to the client. The client decrypts the session key using its private key, establishing a shared secret key between the client and the server.

3. **File Transfer Process:**
Upon receiving a file request from the client, the proxy server checks if the requested file is available in its cache. If found, the server retrieves the file from the cache and proceeds with the encryption and transmission steps. If the file is not in the cache, the server establishes a connection with the file server.

4. **Encryption and Transmission:**
The proxy server sends the file request to the file server and receives the requested file data. It then encrypts the file data using AES-256 in CBC (Cipher Block Chaining) mode with a randomly generated Initialization Vector (IV). The file data is padded using the PKCS7 padding scheme to ensure proper block alignment.

5. **Secure File Transfer:**
Finally, the server sends the encrypted file data along with the IV to the client, completing the file transfer process. The client receives the encrypted file data, decrypts it using the shared secret key, and verifies the integrity of the received file using SHA-256 hashes.

The implemented proxy server ensures secure file transfer by encrypting the file data, authenticating the client, and verifying data integrity. It provides a robust and reliable mechanism for clients to securely transfer files.


