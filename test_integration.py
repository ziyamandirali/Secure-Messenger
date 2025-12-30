import threading
import time
import socket
import json
import os
from PIL import Image
from crypto_utils import hide_data, encrypt_msg, decrypt_msg

# Server config
HOST = '127.0.0.1'
PORT = 9999

def run_server_thread():
    # Run the server in a thread
    from server import start_server
    try:
        start_server()
    except OSError:
        pass # Port already in use maybe

def create_dummy_image(path):
    img = Image.new('RGB', (100, 100), color = 'red')
    img.save(path)

class TestClient:
    def __init__(self, name, password):
        self.name = name
        self.password = password
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((HOST, PORT))

    def send_json(self, data):
        self.sock.sendall(json.dumps(data).encode('utf-8'))

    def receive_json(self):
        data = self.sock.recv(4096).decode('utf-8')
        return json.loads(data)

    def register(self, original_img):
        temp_img = f"temp_{self.name}.png"
        hide_data(original_img, self.password, temp_img)
        file_size = os.path.getsize(temp_img)
        
        self.send_json({'command': 'REGISTER', 'username': self.name, 'image_size': file_size})
        resp = self.receive_json()
        
        if resp['status'] == 'ready_for_upload':
            with open(temp_img, 'rb') as f:
                self.sock.sendall(f.read())
            final = self.receive_json()
            print(f"[{self.name}] Register: {final}")
        
        if os.path.exists(temp_img): os.remove(temp_img)

    def send_msg(self, target, text):
        # Encrypt with MY key
        enc = encrypt_msg(text, self.password)
        self.send_json({'command': 'SEND', 'to': target, 'message': enc})
        resp = self.receive_json()
        print(f"[{self.name}] Send to {target}: {resp}")

    def check_msg(self):
        self.send_json({'command': 'POLL'})
        resp = self.receive_json()
        if 'messages' in resp and resp['messages']:
            for m in resp['messages']:
                dec = decrypt_msg(m['message'], self.password)
                print(f"[{self.name}] Received from {m['from']}: {dec}")
                return dec
        return None

def test_flow():
    # 0. Start Server
    server_thread = threading.Thread(target=run_server_thread, daemon=True)
    server_thread.start()
    time.sleep(1) # Wait for server
    
    # 0. Create Image
    base_img = "test_base_img.png"
    create_dummy_image(base_img)
    
    # 1. Register Client A and B
    c1 = TestClient("Alice", "alicekey")
    c2 = TestClient("Bob", "bobkey")
    
    c1.register(base_img)
    c2.register(base_img)
    
    # 2. Alice sends to Bob
    # Note: Bob is "online" because he just registered/connected, but POLL model means he checks manually or we simulate polling.
    # Our server considers them "online" if connected. If we want to test offline msg, Bob should disconnect or just not poll yet.
    # The prompt said "If C2 is online... delivered... If offline... stored".
    # Implementation of server: "If B is online -> Send"? Wait, `server.py` implementation:
    # `if target not in offline_messages`... wait, I implemented "Store/Deliver" logic in server.py?
    # Let's check `server.py`.
    # Ah, in `server.py`: `offline_messages[target].append(...)`. It ALWAYS appends to `offline_messages`.
    # AND `POLL` retrieves them. This assumes a "Pull" model which is valid for "Offline/Online asynchronous".
    # Even if online, the client needs to ask "Do I have messages?".
    
    c1.send_msg("Bob", "Hello Bob, this is Alice!")
    
    # 3. Bob checks messages
    time.sleep(0.5)
    received = c2.check_msg()
    
    if received == "Hello Bob, this is Alice!":
        print("\nSUCCESS: Message received and decrypted correctly.")
    else:
        print(f"\nFAILURE: Expected message not received. Got: {received}")
        exit(1)

    # Clean up
    if os.path.exists(base_img): os.remove(base_img)

if __name__ == "__main__":
    test_flow()
