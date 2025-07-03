import hashlib
import os
import socket
import threading

IP = 'localhost'
PORT = 1989
ADDR = (IP, PORT)
SIZE = 1024
FORMAT = "utf-8"

def handle_client(conn, addr):
    print(f"[NEW CONNECTION] {addr} connected.")
    data = conn.recv(SIZE).decode(FORMAT)
    data = data.split("\n")[0]
    cmd = data.split(" ")[0]

    if cmd == "GET":
        filename = data.split(" ")[1]
        response = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"
        try:
            with open(filename[1:], 'rb') as file:
                response = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"
                content = file.read()
                response += content
        except:
            response = b"HTTP/1.1 404 Not Found\r\nContent-Type: text/html\r\n\r\n"
            response += b'404 - Page Not Found'

    conn.sendall(response)
    print(f"[DISCONNECTED] {addr} disconnected")
    conn.close()

def main():
    print("[STARTING] Server starting...")
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(ADDR)
    server.listen()
    print(f"[LISTENING] Server listening on {IP}:{PORT}.")

    while True:
        conn, addr = server.accept()
        thread = threading.Thread(target=handle_client, args=(conn, addr))
        thread.start()
        print(f"[ACTIVE CONNECTIONS] {threading.active_count() - 1}")

if __name__ == "__main__":
    main()
