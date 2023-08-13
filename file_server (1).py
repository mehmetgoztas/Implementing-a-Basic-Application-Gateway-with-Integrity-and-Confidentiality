import socket
import os

# Constants
FILE_SERVER_IP = 'localhost'
FILE_SERVER_PORT = 9998
FILES = {
    "file1": "file1.txt",
    "file2": "file2.txt",
    "file3": "file3.txt",
    "file4": "file4.txt",
    "file5": "file5.txt",
}

def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((FILE_SERVER_IP, FILE_SERVER_PORT))
    server.listen(5)
    print(f"[*] Listening on {FILE_SERVER_IP}:{FILE_SERVER_PORT}")

    while True:
        client, addr = server.accept()
        print(f"[*] Accepted connection from {addr[0]}:{addr[1]}")

        file_request = client.recv(1024).decode()
        file_path = FILES.get(file_request)

        if file_path and os.path.isfile(file_path):
            with open(file_path, "rb") as f:
                file_data = f.read()
                print(len(file_data))
                client.send(file_data)
        else:
            client.send(b"File not found.")

        client.close()

if __name__ == "__main__":
    main()
