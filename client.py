import socket
import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import tkinter as tk
from tkinter import scrolledtext, messagebox
import threading
import hashlib  # Added for hashing passwords


# AES Encryption/Decryption
def encrypt_message(key, plaintext):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return iv + ciphertext


def decrypt_message(key, ciphertext):
    iv = ciphertext[:16]
    actual_ciphertext = ciphertext[16:]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    return decryptor.update(actual_ciphertext) + decryptor.finalize()


# Client Chat Application
class ChatClient:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Chat Client")
        self.root.geometry("500x600")
        self.session_key = None
        self.username = None
        self.running = False

        # Initialize login/registration page
        self.initialize_auth_page()

    def hash_password(self, password):
        """Hashes a password using SHA-256."""
        return hashlib.sha256(password.encode()).hexdigest()

    def login(self):
        username = self.username_entry.get()
        password = self.password_entry.get()

        # Hash the entered password
        hashed_password = self.hash_password(password)

        if os.path.exists("credentials.txt"):
            try:
                with open("credentials.txt", "r", encoding="utf-8") as f:
                    credentials = f.read().splitlines()
                if f"{username}:{hashed_password}" in credentials:
                    self.username = username
                    self.initialize_chat_page()
                else:
                    messagebox.showerror("Error", "Invalid username or password!")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to read credentials: {str(e)}")
        else:
            messagebox.showerror("Error", "No users registered yet!")

    def register(self):
        username = self.username_entry.get()
        password = self.password_entry.get()

        if username and password:
            # Check for invalid characters in username or password
            if ":" in username or ":" in password:
                messagebox.showerror("Error", "Username and password cannot contain ':'")
                return

            # Hash the password before storing it
            hashed_password = self.hash_password(password)
            try:
                with open("credentials.txt", "a", encoding="utf-8") as f:
                    f.write(f"{username}:{hashed_password}\n")
                messagebox.showinfo("Success", "Registration successful! Please login.")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save credentials: {str(e)}")
        else:
            messagebox.showerror("Error", "Please fill out all fields!")

    def initialize_auth_page(self):
        # Clear the window
        for widget in self.root.winfo_children():
            widget.destroy()

        # Title
        tk.Label(self.root, text="Secure Chat System", font=("Helvetica", 18, "bold"), fg="#4CAF50").pack(pady=20)

        # Username Entry
        tk.Label(self.root, text="Username", font=("Helvetica", 12)).pack()
        self.username_entry = tk.Entry(self.root, font=("Helvetica", 12))
        self.username_entry.pack(pady=5)

        # Password Entry
        tk.Label(self.root, text="Password", font=("Helvetica", 12)).pack()
        self.password_entry = tk.Entry(self.root, show="*", font=("Helvetica", 12))
        self.password_entry.pack(pady=5)

        # Buttons
        tk.Button(self.root, text="Login", font=("Helvetica", 12, "bold"), bg="#4CAF50", fg="white",
                  command=self.login).pack(pady=10)
        tk.Button(self.root, text="Register", font=("Helvetica", 12, "bold"), bg="#007BFF", fg="white",
                  command=self.register).pack()

    def initialize_chat_page(self):
        # Clear the window
        for widget in self.root.winfo_children():
            widget.destroy()

        # Title
        tk.Label(self.root, text=f"Welcome, {self.username}", font=("Helvetica", 16, "bold"), fg="#4CAF50").pack(pady=10)

        # Chat Display
        self.chat_display = scrolledtext.ScrolledText(self.root, state='disabled', wrap='word', bg="#f4f4f9", fg="#333",
                                                      font=("Helvetica", 12))
        self.chat_display.pack(pady=10, padx=10, fill=tk.BOTH, expand=True)

        # Message Entry
        self.message_entry = tk.Entry(self.root, font=("Helvetica", 14), bg="#f4f4f9", fg="#333", borderwidth=2)
        self.message_entry.pack(pady=10, padx=10, fill=tk.X)
        self.message_entry.bind("<Return>", self.send_message)

        # Send Button
        self.send_button = tk.Button(self.root, text="Send", command=self.send_message, bg="#4CAF50", fg="white",
                                     font=("Helvetica", 12, "bold"))
        self.send_button.pack(pady=10)

        # Start the connection
        self.connect_to_server()

    def connect_to_server(self):
        try:
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.connect(("localhost", 1111))

            # Receive RSA Public Key
            pubkey_data = self.client_socket.recv(1024)
            self.pubkey = rsa.PublicKey.load_pkcs1(pubkey_data)

            # Generate and send encrypted session key
            self.session_key = os.urandom(16)
            encrypted_session_key = rsa.encrypt(self.session_key, self.pubkey)
            self.client_socket.send(encrypted_session_key)

            self.display_message("System: Connected to the server.\n")

            # Start receiving messages
            self.running = True
            self.receive_thread = threading.Thread(target=self.receive_messages, daemon=True)
            self.receive_thread.start()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to connect to the server: {str(e)}")

    def send_message(self, event=None):
        message = self.message_entry.get()
        if message.strip():
            try:
                encrypted_message = encrypt_message(self.session_key, f"{self.username}: {message}".encode())
                self.client_socket.send(encrypted_message)
                self.display_message(f"You: {message}\n")
                self.message_entry.delete(0, tk.END)
            except Exception as e:
                self.display_message(f"System: Failed to send message: {str(e)}\n")

    def receive_messages(self):
        while self.running:
            try:
                encrypted_response = self.client_socket.recv(1024)
                if encrypted_response:
                    response = decrypt_message(self.session_key, encrypted_response).decode()
                    self.display_message(f"{response}\n")
            except Exception as e:
                self.display_message(f"System: Connection error: {str(e)}\n")
                break

    def display_message(self, message):
        self.chat_display.config(state='normal')
        self.chat_display.insert(tk.END, message)
        self.chat_display.config(state='disabled')
        self.chat_display.see(tk.END)

    def close_connection(self):
        self.running = False
        self.client_socket.close()

if __name__ == "__main__":
    root = tk.Tk()
    app = ChatClient(root)

    def on_closing():
        if app.running:
            app.close_connection()
        root.destroy()

    root.protocol("WM_DELETE_WINDOW", on_closing)
    root.mainloop()
