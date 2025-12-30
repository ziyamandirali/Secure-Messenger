import socket
import json
import os
import time
from crypto_utils import hide_data, encrypt_msg, decrypt_msg

HOST = '127.0.0.1'
PORT = 9999

class SecureClient:
    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.username = None
        self.password_key = None # Kept in memory to encrypt/decrypt messages

    def connect(self):
        try:
            self.sock.connect((HOST, PORT))
            print(f"Connected to server at {HOST}:{PORT}")
        except Exception as e:
            print(f"Could not connect: {e}")
            exit()

    def send_json(self, data):
        msg = json.dumps(data)
        self.sock.sendall(msg.encode('utf-8'))

    def receive_json(self):
        try:
            data = self.sock.recv(1024*4).decode('utf-8')
            if not data: return None
            return json.loads(data)
        except:
            return None

    def register(self):
        print("\n--- REGISTER ---")
        username = input("Username: ")
        password = input("Password (will be your Key): ")
        image_path = input("Path to Image (e.g., download an image first): ")
        
        if not os.path.exists(image_path):
            print("Image file not found!")
            return False

        # Hide password in image
        temp_img = "temp_reg_image.png"
        try:
            hide_data(image_path, password, temp_img)
        except Exception as e:
            print(f"Steganography error: {e}")
            return False
            
        # Send Register Command
        file_size = os.path.getsize(temp_img)
        cmd = {
            'command': 'REGISTER',
            'username': username,
            'image_size': file_size
        }
        self.send_json(cmd)
        
        # Wait for 'ready_for_upload'
        resp = self.receive_json()
        if resp and resp.get('status') == 'ready_for_upload':
            with open(temp_img, 'rb') as f:
                data = f.read()
                self.sock.sendall(data)
                
            # Wait for final success
            final_resp = self.receive_json()
            print(f"Server: {final_resp}")
            if final_resp.get('status') == 'success':
                self.username = username
                self.password_key = password
                try: os.remove(temp_img)
                except: pass
                return True
        else:
            print(f"Server Error: {resp}")
        
        return False

    def login(self):
        print("\n--- LOGIN ---")
        username = input("Username: ")
        password = input("Password (Your Key): ")
        
        cmd = {'command': 'LOGIN', 'username': username}
        self.send_json(cmd)
        resp = self.receive_json()
        print(f"Server: {resp}")
        
        if resp.get('status') == 'success':
            self.username = username
            self.password_key = password
            return True
        return False

    def list_users(self):
        cmd = {'command': 'LIST_USERS'}
        self.send_json(cmd)
        resp = self.receive_json()
        if resp and 'users' in resp:
            print(f"Online Users: {resp['users']}")

    def send_message(self):
        target = input("To User: ")
        msg = input("Message: ")
        
        # Encrypt with MY key
        encrypted_hex = encrypt_msg(msg, self.password_key)
        
        cmd = {
            'command': 'SEND',
            'to': target,
            'message': encrypted_hex
        }
        self.send_json(cmd)
        resp = self.receive_json()
        print(f"Server: {resp}")

    def check_messages(self):
        cmd = {'command': 'POLL'}
        self.send_json(cmd)
        resp = self.receive_json()
        
        if resp and 'messages' in resp:
            msgs = resp['messages']
            if not msgs:
                print("No new messages.")
            else:
                print(f"\n--- {len(msgs)} New Messages ---")
                for m in msgs:
                    sender = m['from']
                    enc_txt = m['message']
                    # Decrypt with MY key (Server re-encrypted it for me)
                    dec_txt = decrypt_msg(enc_txt, self.password_key)
                    print(f"From {sender}: {dec_txt}")
        else:
            print(f"Server Error: {resp}")

    def run(self):
        self.connect()
        while True:
            if not self.username:
                choice = input("\n1. Register\n2. Login\nChoice: ")
                if choice == '1':
                    if self.register():
                        print(f"Logged in as {self.username}")
                elif choice == '2':
                    if self.login():
                        print(f"Logged in as {self.username}")
            else:
                print(f"\nLogged in as: {self.username}")
                choice = input("1. List Users\n2. Send Message\n3. Check Messages\n4. Exit\nChoice: ")
                if choice == '1':
                    self.list_users()
                elif choice == '2':
                    self.send_message()
                elif choice == '3':
                    self.check_messages()
                elif choice == '4':
                    self.send_json({'command': 'EXIT'})
                    break

if __name__ == "__main__":
    client = SecureClient()
    client.run()
