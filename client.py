import hashlib
import os
import socket
import threading

IP = socket.gethostbyname(socket.gethostname())
PORT = 1996
ADDR = (IP, PORT)
FORMAT = "utf-8"
SIZE = 1024
CLIENT_DATA_PATH = "client_data"

client_running = True

def main():
    global client_running
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(ADDR)

    data = client.recv(SIZE).decode(FORMAT)
    cmd, msg = data.split("@")
    if cmd == "OK":
        print(f"{msg}")

    receive_thread = threading.Thread(target=receive_messages, args=(client,), daemon=True)
    receive_thread.start()

    while client_running:
        try:
            data = input("> ")
            if not client_running:
                break
                
            data = data.split(" ")
            cmd = data[0]

            if cmd == "Help":
                client.send(cmd.encode(FORMAT))
            elif cmd == "Exit":
                client.send(cmd.encode(FORMAT))
                client_running = False
                break
            elif cmd == "File":
                if len(data) < 2:
                    print("Usage: File <filename>")
                    continue
                path = data[1]
                send_data = f"{cmd}@{path}"
                client.send(send_data.encode(FORMAT))
            elif cmd == "Chat":
                if len(data) < 2:
                    print("Usage: Chat <message>")
                    continue
                string_data = " ".join(data[1:])
                send_data = f"{cmd}@{string_data}"
                client.send(send_data.encode(FORMAT))
            else:
                print("Unknown command. Type 'Help' for available commands.")
                continue
                
        except (EOFError, KeyboardInterrupt):
            print("\nDisconnecting...")
            client_running = False
            break
        except Exception as e:
            print(f"[ERROR]: {e}")
            break

    print("Disconnected from server.")
    client.close()

def receive_messages(client):
    """Handle incoming messages from server in a separate thread"""
    global client_running
    while client_running:
        try:
            client.settimeout(1.0)
            data = client.recv(SIZE).decode(FORMAT)
            if not data:
                break
                
            msg_parts = data.split("@")
            cmd = msg_parts[0]

            if cmd == "DISCONNECTED":
                print(f"\n[SERVER]: {msg_parts[1]}")
                client_running = False
                break
            elif cmd == "BROADCAST":
                msg = "@".join(msg_parts[1:]) if len(msg_parts) > 1 else ""
                print(f"\n[SERVER BROADCAST]: {msg}")
                print("> ", end="", flush=True) 
            elif cmd == "OK":
                if len(msg_parts) == 4:
                    name, size, hash = msg_parts[1], msg_parts[2], msg_parts[3]
                    
                    def format_file_size(size_bytes):
                        size_bytes = int(size_bytes)
                        if size_bytes < 1024:
                            return f"{size_bytes} B"
                        elif size_bytes < 1024 * 1024:
                            return f"{size_bytes / 1024:.2f} KB"
                        elif size_bytes < 1024 * 1024 * 1024:
                            return f"{size_bytes / (1024 * 1024):.2f} MB"
                        else:
                            return f"{size_bytes / (1024 * 1024 * 1024):.2f} GB"
                    
                    print(f"\nName: {name}")
                    print(f"Size: {format_file_size(size)}")
                    print(f"Hash: {hash}")

                    tam = 0
                    with open(os.path.join(CLIENT_DATA_PATH, name), "wb") as f:
                        rounds = int(int(size) / SIZE) + 1
                        while tam < int(size):
                            if rounds == 1:
                                file_data = client.recv(int(size))
                            else:
                                if tam + SIZE < int(size):
                                    file_data = client.recv(SIZE)
                                else:
                                    file_data = client.recv(int(size) - tam)
                            tam += len(file_data)
                            if (tam > int(size)):
                                file_data = file_data[:int(size) - tam]
                            f.write(file_data)

                    with open(os.path.join(CLIENT_DATA_PATH, name), "rb") as f:
                        sha256_hash = hashlib.sha256()
                        for byte_block in iter(lambda: f.read(4096), b""):
                            sha256_hash.update(byte_block)
                        file_hash = sha256_hash.hexdigest()

                        if file_hash == hash:
                            print("Hash verified successfully!")
                        else:
                            print("Hash verification failed!")

                        print("File received successfully.")
                    
                    end_data = client.recv(SIZE).decode(FORMAT)
                    end_parts = end_data.split("@")
                    if end_parts[0] == "OK" and len(end_parts) > 1:
                        print(f"Server: {end_parts[1]}")
                    print("> ", end="", flush=True)  
                else:
                    msg = "@".join(msg_parts[1:]) if len(msg_parts) > 1 else ""
                    print(f"\n{msg}")
                    print("> ", end="", flush=True) 
            elif cmd == "NOK":
                msg = "@".join(msg_parts[1:]) if len(msg_parts) > 1 else ""
                print(f"\n[ERROR]: {msg}")
                print("> ", end="", flush=True) 
                
        except socket.timeout:
            continue
        except ConnectionResetError:
            print("\n[ERROR]: Connection lost to server")
            client_running = False
            break
        except Exception as e:
            print(f"\n[ERROR]: {e}")
            client_running = False
            break

if __name__ == "__main__":
    main()
