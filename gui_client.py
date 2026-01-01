import tkinter as tk
from tkinter import messagebox, filedialog, simpledialog
import socket
import json
import os
import threading
import time
from PIL import Image, ImageTk  # Added ImageTk
from crypto_utils import hide_data, encrypt_msg, decrypt_msg

HOST = '127.0.0.1'
PORT = 9999

class SecureMessengerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Messenger (Steganography + DES)")
        self.root.geometry("600x600") # Increased height for preview
        
        self.sock = None
        self.username = None
        self.password_key = None
        self.connected = False
        
        # Frames
        self.login_frame = tk.Frame(root)
        self.main_frame = tk.Frame(root)
        
        self.setup_login_ui()
        self.setup_main_ui()
        
        self.show_frame(self.login_frame)
        
        # Connect initially
        self.connect_server()

    def connect_server(self):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((HOST, PORT))
            self.connected = True
        except Exception as e:
            messagebox.showerror("Connection Error", f"Cannot connect to server: {e}")
            self.connected = False

    def send_json(self, data):
        if not self.connected: return
        try:
            self.sock.sendall(json.dumps(data).encode('utf-8'))
        except:
            self.connected = False

    def receive_json(self):
        if not self.connected: return None
        try:
            data = self.sock.recv(4096*2).decode('utf-8')
            if not data: return None
            # Handle stacked JSONs if any (simple fix)
            # For this demo, assuming one response per request usually
            return json.loads(data)
        except:
            return None

    def show_frame(self, frame):
        self.login_frame.pack_forget()
        self.main_frame.pack_forget()
        frame.pack(fill="both", expand=True)

    # --- UI SETUP ---
    def setup_login_ui(self):
        tk.Label(self.login_frame, text="Secure Messenger Login", font=("Arial", 16)).pack(pady=20)
        
        tk.Label(self.login_frame, text="Username:").pack()
        self.user_entry = tk.Entry(self.login_frame)
        self.user_entry.pack()
        
        tk.Label(self.login_frame, text="Password (Key):").pack()
        self.pass_entry = tk.Entry(self.login_frame, show="*")
        self.pass_entry.pack()
        
        # Image Selection
        self.img_path = tk.StringVar()
        tk.Label(self.login_frame, text="Image (for Registration):").pack(pady=(10,0))
        tk.Entry(self.login_frame, textvariable=self.img_path, width=40).pack()
        tk.Button(self.login_frame, text="Browse...", command=self.browse_image).pack()
        
        # Image Preview Label
        self.preview_label = tk.Label(self.login_frame, text="No image selected", bg="#ddd", width=20, height=10)
        self.preview_label.pack(pady=10)
        
        tk.Button(self.login_frame, text="Login", command=self.login, width=15).pack(pady=(20, 5))
        tk.Button(self.login_frame, text="Register", command=self.register, width=15).pack()

    def setup_main_ui(self):
        # Top Bar
        top_bar = tk.Frame(self.main_frame)
        top_bar.pack(fill="x", padx=5, pady=5)
        
        self.user_label = tk.Label(top_bar, text="User: ???", font=("Arial", 10, "bold"))
        self.user_label.pack(side="left")
        
        tk.Button(top_bar, text="Log Out", command=self.logout, bg="#ffcccc").pack(side="right")
        
        # Sidebar for Users
        left_panel = tk.Frame(self.main_frame, width=150, bg="#f0f0f0")
        left_panel.pack(side="left", fill="y")
        
        tk.Label(left_panel, text="Users", bg="#f0f0f0").pack(pady=5)
        self.user_listbox = tk.Listbox(left_panel)
        self.user_listbox.pack(fill="both", expand=True, padx=5)
        self.user_listbox.bind('<Button-1>', self.on_listbox_click)
        tk.Button(left_panel, text="Refresh Users", command=self.refresh_users).pack(pady=5)
        
        # Chat Area
        right_panel = tk.Frame(self.main_frame)
        right_panel.pack(side="right", fill="both", expand=True)
        
        self.chat_display = tk.Text(right_panel, state='disabled', height=20)
        self.chat_display.pack(fill="both", expand=True, padx=5, pady=5)
        
        input_frame = tk.Frame(right_panel)
        input_frame.pack(fill="x", padx=5, pady=5)
        
        self.msg_entry = tk.Entry(input_frame)
        self.msg_entry.pack(side="left", fill="x", expand=True)
        tk.Button(input_frame, text="Send", command=self.send_message).pack(side="right")
        
        # Poll Loop
        self.root.after(2000, self.poll_messages)

    def on_listbox_click(self, event):
        """Handle listbox clicks to prevent selecting empty space"""
        # Get index nearest to the click
        index = self.user_listbox.nearest(event.y)
        # Get bounding box of that item: (x, y, width, height)
        bbox = self.user_listbox.bbox(index)
        
        # If no item or click is outside the item's vertical range
        if not bbox or event.y > bbox[1] + bbox[3]:
            # Clicked on empty space
            self.user_listbox.selection_clear(0, tk.END)
            return "break" # Prevent default selection behavior
            
    # --- ACTIONS ---
    def browse_image(self):
        filename = filedialog.askopenfilename(filetypes=[("Images", "*.png *.jpg *.jpeg"), ("All Files", "*.*")])
        if filename:
            self.img_path.set(filename)
            self.show_preview(filename)

    def show_preview(self, path):
        try:
            img = Image.open(path)
            img.thumbnail((150, 150)) # Resize for preview
            photo = ImageTk.PhotoImage(img)
            self.preview_label.config(image=photo, text="", width=150, height=150)
            self.preview_label.image = photo # Keep reference
        except Exception as e:
            self.preview_label.config(text="Invalid Image", image="")

    def logout(self):
        # Notify Server
        if self.connected and self.username:
            try:
                self.send_json({'command': 'LOGOUT'})
                self.receive_json() # Wait for ack (optional but good practice)
            except:
                pass

        # Reset State
        self.username = None
        self.password_key = None
        self.chat_display.config(state='normal')
        self.chat_display.delete('1.0', tk.END)
        self.chat_display.config(state='disabled')
        
        self.show_frame(self.login_frame)

    def login(self):
        user = self.user_entry.get()
        pwd = self.pass_entry.get()
        if not user or not pwd:
            messagebox.showwarning("Input", "Username and Password required")
            return
            
        self.send_json({'command': 'LOGIN', 'username': user, 'password': pwd})
        resp = self.receive_json()
        if resp and resp.get('status') == 'success':
            self.username = user
            self.password_key = pwd
            self.user_label.config(text=f"User: {self.username}")
            self.show_frame(self.main_frame)
            self.refresh_users()
        else:
            messagebox.showerror("Error", "Login failed. User might not exist.")

    def register(self):
        user = self.user_entry.get()
        pwd = self.pass_entry.get()
        img_file = self.img_path.get()
        
        if not user or not pwd or not img_file:
            messagebox.showwarning("Input", "All fields required for registration")
            return
            
        if not os.path.exists(img_file):
            messagebox.showerror("Error", "Image file not found")
            return

        # Steganography
        temp_img = f"temp_reg_{user}.png"
        try:
            hide_data(img_file, pwd, temp_img)
        except Exception as e:
            messagebox.showerror("Steganography Error", str(e))
            return
            
        # Send
        try:
            size = os.path.getsize(temp_img)
            self.send_json({'command': 'REGISTER', 'username': user, 'image_size': size})
            resp = self.receive_json()
            
            if resp and resp.get('status') == 'ready_for_upload':
                with open(temp_img, 'rb') as f:
                    self.sock.sendall(f.read())
                
                final = self.receive_json()
                if final and final.get('status') == 'success':
                    messagebox.showinfo("Success", "Registered Successfully!")
                    self.username = user
                    self.password_key = pwd
                    self.user_label.config(text=f"User: {self.username}")
                    self.show_frame(self.main_frame)
                    self.refresh_users()
                else:
                    messagebox.showerror("Register Failed", str(final))
            else:
                messagebox.showerror("Error", f"Server not ready: {resp}")
        except Exception as e:
            messagebox.showerror("Error", str(e))
        finally:
            if os.path.exists(temp_img): os.remove(temp_img)

    def refresh_users(self):
        self.send_json({'command': 'LIST_USERS'})
        resp = self.receive_json()
        if resp and 'users' in resp:
            self.user_listbox.delete(0, tk.END)
            # Sort: Online first, then alphabetical
            sorted_users = sorted(resp['users'], key=lambda x: (not x['online'], x['username']))
            
            # Re-implementing the loop cleanly
            valid_users = [u for u in sorted_users if u['username'] != self.username]
            
            for index, u in enumerate(valid_users):
                uname = u['username']
                is_online = u['online']
                
                # Use standard bullet point
                display_text = f"● {uname}" 
                self.user_listbox.insert(tk.END, display_text)
                
                # Color the item
                color = "green" if is_online else "red"
                self.user_listbox.itemconfig(index, {'fg': color})

    def send_message(self):
        selection = self.user_listbox.curselection()
        if not selection:
            messagebox.showwarning("Select User", "Please select a user to message from the list.")
            return
        target_display = self.user_listbox.get(selection[0])
        # Format is "● Username" -> split by space
        target = target_display.split(" ", 1)[1]
        msg = self.msg_entry.get()
        if not msg: return
        
        try:
            # Encrypt
            enc_hex = encrypt_msg(msg, self.password_key)
            self.send_json({'command': 'SEND', 'to': target, 'message': enc_hex})
            resp = self.receive_json() # Wait for ack
            
            self.log_chat(f"To {target}: {msg}")
            self.msg_entry.delete(0, tk.END)
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def poll_messages(self):
        if self.connected and self.username:
            try:
                # We need to manage socket carefully since recv blocks.
                # If username is None (logged out), we shouldn't polls.
                self.send_json({'command': 'POLL'})
                
                resp = self.receive_json()
                
                if resp and 'messages' in resp and resp['messages']:
                    for m in resp['messages']:
                        sender = m['from']
                        try:
                            dec = decrypt_msg(m['message'], self.password_key)
                            self.log_chat(f"From {sender}: {dec}")
                        except:
                             self.log_chat(f"From {sender}: [Decryption Failed]")
            except Exception as e:
                print(f"Poll error: {e}")
        
        self.root.after(3000, self.poll_messages)

    def log_chat(self, text):
        self.chat_display.config(state='normal')
        self.chat_display.insert(tk.END, text + "\n")
        self.chat_display.see(tk.END)
        self.chat_display.config(state='disabled')

if __name__ == "__main__":
    root = tk.Tk()
    gui = SecureMessengerGUI(root)
    root.mainloop()
