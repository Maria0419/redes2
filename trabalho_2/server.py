import hashlib
import os
import socket
import threading

IP = socket.gethostbyname(socket.gethostname())
PORT = 1996
ADDR = (IP, PORT)
SIZE = 1024
FORMAT = "utf-8"
SERVER_DATA_PATH = "server_data"

connected_clients = []
clients_lock = threading.Lock()

def broadcast_to_all(message):
    """Send a message to all connected clients"""
    with clients_lock:
        disconnected_clients = []
        for client in connected_clients:
            try:
                client.send(f"BROADCAST@{message}".encode(FORMAT))
            except:
                disconnected_clients.append(client)
        
        # Remove disconnected clients
        for client in disconnected_clients:
            connected_clients.remove(client)

def handle_client(conn, addr):
    print(f"[NEW CONNECTION] {addr} connected.")
    conn.send("OK@Welcome.".encode(FORMAT))
    
    with clients_lock:
        connected_clients.append(conn)

    try:
        while True:
            
            conn.settimeout(1.0)
            try:
                data = conn.recv(SIZE).decode(FORMAT)
                if not data:
                    break
                    
                data = data.split("@")
                cmd = data[0]

                if cmd == "Exit":
                    send_data = "OK@Disconnected from the server."
                    conn.send(send_data.encode(FORMAT))            
                    break

                elif cmd == "File":
                    name = data[1]
                    filepath = os.path.join(SERVER_DATA_PATH, name)
                    
                    if not os.path.exists(filepath):
                        send_data = f"NOK@The file {name} does not exist."
                        conn.send(send_data.encode(FORMAT))
                    else:
                        file_size = os.path.getsize(filepath)
                        
                        sha256_hash = hashlib.sha256()
                        with open(filepath, "rb") as f:
                            for byte_block in iter(lambda: f.read(4096), b""):
                                sha256_hash.update(byte_block)
                        file_hash = sha256_hash.hexdigest()
                        
                        send_data = f"OK@{name}@{file_size}@{file_hash}"
                        conn.send(send_data.encode(FORMAT))
                        
                        with open(filepath, "rb") as f:
                            while (chunk := f.read(SIZE)):
                                conn.send(chunk)
                        
                        send_data = "OK@End of file."
                        conn.send(send_data.encode(FORMAT))
                        print(f"End of file {name}.")

                elif cmd == "Chat":
                    print(f"Receiving message from client: {data[1]}")
                    send_data = "OK@"
                    send_data += data[1]
                    conn.send(send_data.encode(FORMAT))
                
                elif cmd == "Help":
                    help_data = "OK@"
                    help_data += "Exit: Disconnect from the server.\n"
                    help_data += "File <NAME.EXT>: Sends a file.\n"
                    help_data += "Chat: Prints data received from client.\n"
                    help_data += "Help: Lists the commands."
                    conn.send(help_data.encode(FORMAT))
                    
            except socket.timeout:
                continue
            except ConnectionResetError:
                break
                
    except Exception as e:
        print(f"[ERROR] Error handling client {addr}: {e}")
    finally:
        with clients_lock:
            if conn in connected_clients:
                connected_clients.remove(conn)
        print(f"[DISCONNECTED] {addr} disconnected")
        conn.close()

def server_console_handler():
    """Handle server console input for broadcasting messages"""
    print("[SERVER CONSOLE] Type messages to broadcast to all clients. Type 'quit' to stop server.")
    while True:
        try:
            message = input("[SERVER] > ")
            if message.lower() == 'quit':
                print("[SERVER] Shutting down...")
                os._exit(0)
            elif message.strip():
                broadcast_to_all(message)
                print(f"[BROADCAST] Sent to {len(connected_clients)} clients: {message}")
        except (EOFError, KeyboardInterrupt):
            print("\n[SERVER] Shutting down...")
            os._exit(0)

def main():
    print("[STARTING] Server starting...")
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(ADDR)
    server.listen()
    print(f"[LISTENING] Server listening on {IP}:{PORT}.")

    console_thread = threading.Thread(target=server_console_handler, daemon=True)
    console_thread.start()

    while True:
        conn, addr = server.accept()
        thread = threading.Thread(target=handle_client, args=(conn, addr))
        thread.start()
        print(f"[ACTIVE CONNECTIONS] {threading.active_count() - 2}") 

if __name__ == "__main__":
    main()
