import socket
import threading
import json
import os
import shutil
from crypto_utils import extract_data

# Configuration
HOST = '0.0.0.0'
PORT = 9999
UPLOAD_DIR = "server_uploads"
USER_DB = "users.json"

# Shared State
users = {} # {username: {'key': des_key, 'online': False}}
offline_messages = {} # {username: [{'from': sender, 'message': encrypted_msg}, ...]}
lock = threading.Lock()

if not os.path.exists(UPLOAD_DIR):
    os.makedirs(UPLOAD_DIR)

def load_users():
    """Load users from JSON file on startup."""
    global users
    if os.path.exists(USER_DB):
        try:
            with open(USER_DB, 'r') as f:
                data = json.load(f)
                # Reconstruct users dict, ensuring 'online' is False initially
                for u, info in data.items():
                    users[u] = {'key': info['key'], 'online': False}
            print(f"Loaded {len(users)} users from {USER_DB}.")
        except Exception as e:
            print(f"Error loading users: {e}")

def save_users():
    """Save users to JSON file."""
    try:
        data = {u: {'key': users[u]['key']} for u in users}
        with open(USER_DB, 'w') as f:
            json.dump(data, f, indent=4)
        print(f"Saved users to {USER_DB}.")
    except Exception as e:
        print(f"Error saving users: {e}")

def handle_client(conn, addr):
    print(f"New connection from {addr}")
    user_online = None
    
    try:
        while True:
            # Protocol: Length-prefixed JSON or simple line-based?
            # Let's use simple line-based JSON for commands, but binary for file upload might be needed.
            # Ideally, we read dynamic buffer. For simplicity, let's assume commands fit in 4096 bytes or we implement a read_n.
            
            # Simple Protocol: 
            # 1. Send Command JSON string line.
            # 2. If upload, send size, then bytes.
            
            data = conn.recv(1024*4).decode('utf-8')
            if not data:
                break
            
            # Because TCP is a stream, we might get multiple JSONs or partials. 
            # For this simple project, we assume the client sends one command and waits for response.
            try:
                request = json.loads(data)
            except json.JSONDecodeError:
                conn.sendall(json.dumps({'status': 'error', 'message': 'Invalid JSON'}).encode('utf-8'))
                continue

            command = request.get('command')
            
            if command == 'REGISTER':
                # {command: REGISTER, username: ..., image_size: ...}
                username = request.get('username')
                img_size = request.get('image_size')
                
                conn.sendall(json.dumps({'status': 'ready_for_upload'}).encode('utf-8'))
                
                # Receive Image
                received = 0
                img_path = os.path.join(UPLOAD_DIR, f"{username}_reg.png")
                with open(img_path, 'wb') as f:
                    while received < img_size:
                        chunk = conn.recv(min(4096, img_size - received))
                        if not chunk: break
                        f.write(chunk)
                        received += len(chunk)
                
                # Extract Key from Image
                try:
                    extracted_key = extract_data(img_path)
                    if not extracted_key:
                        conn.sendall(json.dumps({'status': 'error', 'message': 'No key found in image'}).encode('utf-8'))
                    else:
                        with lock:
                            users[username] = {'key': extracted_key, 'online': True}
                        save_users() # Save to file
                        user_online = username
                        print(f"User '{username}' registered with key: {extracted_key}")
                        conn.sendall(json.dumps({'status': 'success', 'message': 'Registered successfully'}).encode('utf-8'))
                except Exception as e:
                    print(f"Error extracting: {e}")
                    conn.sendall(json.dumps({'status': 'error', 'message': 'Registration failed'}).encode('utf-8'))

            elif command == 'LOGIN':
                 # Just set online status if already registered
                 username = request.get('username')
                 with lock:
                     if username in users:
                         users[username]['online'] = True
                         user_online = username
                         conn.sendall(json.dumps({'status': 'success'}).encode('utf-8'))
                     else:
                         conn.sendall(json.dumps({'status': 'error', 'message': 'User not found'}).encode('utf-8'))

            elif command == 'LIST_USERS':
                with lock:
                    # Return list of {username: ..., online: ...}
                    user_list = [{'username': u, 'online': users[u]['online']} for u in users]
                conn.sendall(json.dumps({'status': 'success', 'users': user_list}).encode('utf-8'))

            elif command == 'SEND':
                # {command: SEND, to: target_user, message: encrypted_msg_hex}
                # Wait, the protocol says:
                # 1. Server decrypts (using sender key) -> verifies sender
                # 2. Server encrypts (using receiver key) -> puts in box
                
                # BUT, Client sends the message ALREADY ENCRYPTED with ITS OWN KEY?
                # The transcript says: "Client tarafındaki bilinen anahtar değeriyle bu mesaj şifreleniyor... Sunucu... C1'in anahtar değeriyle beraber gelen mesaj deşifreleniyor... sunucu bu mesajı C2'ye... C2'nin anahtar değerini kullanarak mesajı şifreliyor".
                
                # So:
                # Client A sends: Encrypt(Msg, KeyA)
                # Server: Decrypt(Msg, KeyA) -> Plaintext -> Encrypt(Plaintext, KeyB) -> Store/Send to B
                
                sender = user_online
                target = request.get('to')
                ciphertext_hex = request.get('message')
                
                if not sender:
                     conn.sendall(json.dumps({'status': 'error', 'message': 'Not logged in'}).encode('utf-8'))
                     continue

                with lock:
                    sender_info = users.get(sender)
                    target_info = users.get(target)
                
                if not sender_info or not target_info:
                    conn.sendall(json.dumps({'status': 'error', 'message': 'User not found'}).encode('utf-8'))
                    continue
                
                # 1. Decrypt from Sender
                from crypto_utils import decrypt_msg, encrypt_msg
                sender_key = sender_info['key']
                plaintext = decrypt_msg(ciphertext_hex, sender_key)
                
                if plaintext.startswith("[Decryption Error]"):
                    conn.sendall(json.dumps({'status': 'error', 'message': 'Server failed to decrypt. Wrong key?'}).encode('utf-8'))
                    continue
                
                print(f"Relaying message: {sender} -> {target} : '{plaintext}'")
                
                # 2. Encrypt for Target
                target_key = target_info['key']
                new_ciphertext = encrypt_msg(plaintext, target_key)
                
                # 3. Store/Deliver
                with lock:
                    if target not in offline_messages:
                        offline_messages[target] = []
                    offline_messages[target].append({'from': sender, 'message': new_ciphertext})
                
                conn.sendall(json.dumps({'status': 'success', 'message': 'Message sent'}).encode('utf-8'))

            elif command == 'POLL':
                # Check messages for current user
                username = user_online
                if not username:
                    conn.sendall(json.dumps({'status': 'error'}).encode('utf-8'))
                    continue
                
                with lock:
                    msgs = offline_messages.get(username, [])
                    # In a real app we might clear them, but let's keep the transcript wording "C2 ne zaman online olursa...". 
                    # Usually we verify they got it. For now, let's return them and clear.
                    if msgs:
                        del offline_messages[username]
                
                conn.sendall(json.dumps({'status': 'success', 'messages': msgs}).encode('utf-8'))

            elif command == 'LOGOUT':
                if user_online:
                   with lock:
                       if user_online in users:
                           users[user_online]['online'] = False
                   print(f"User {user_online} logged out")
                   user_online = None
                   conn.sendall(json.dumps({'status': 'success'}).encode('utf-8'))
            
            elif command == 'EXIT':
                break
                
    except Exception as e:
        print(f"Error handling client {addr}: {e}")
    finally:
        if user_online:
            with lock:
                if user_online in users:
                    users[user_online]['online'] = False
            print(f"User {user_online} disconnected")
        conn.close()

def start_server():
    load_users() # Load users at start
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        server.bind((HOST, PORT))
    except OSError:
        print(f"Error: Port {PORT} is busy. Is the server already running?")
        return
        
    server.listen()
    print(f"Server listening on {HOST}:{PORT}")
    
    while True:
        conn, addr = server.accept()
        thread = threading.Thread(target=handle_client, args=(conn, addr))
        thread.start()

if __name__ == "__main__":
    start_server()
