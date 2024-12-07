import socket
import threading
import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

# Store active clients and their session keys
clients = []
session_keys = {}

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

# Broadcast messages to all connected clients
def broadcast(message, sender_socket):
    for client_socket in clients:
        if client_socket != sender_socket:
            try:
                # Encrypt the message for each client using their session key
                encrypted_message = encrypt_message(session_keys[client_socket], message)
                client_socket.send(encrypted_message)
            except Exception as e:
                print(f"Error broadcasting message: {e}")

# Handle communication with a single client
def handle_client(client_socket, client_address):
    print(f"[NEW CONNECTION] {client_address} connected.")
    clients.append(client_socket)

    try:
        # Generate RSA keys
        public_key, private_key = rsa.newkeys(512)

        # Send the public key to the client
        client_socket.send(public_key.save_pkcs1())

        # Receive and decrypt the session key
        encrypted_session_key = client_socket.recv(1024)
        session_key = rsa.decrypt(encrypted_session_key, private_key)
        session_keys[client_socket] = session_key

        # Notify all clients
        broadcast(f"System: {client_address} has joined the chat.".encode(), client_socket)

        # Listen for messages
        while True:
            encrypted_message = client_socket.recv(1024)
            if not encrypted_message:
                break
            
            # Decrypt the message
            decrypted_message = decrypt_message(session_keys[client_socket], encrypted_message).decode()

            # Display both encrypted and decrypted messages
            print(f"[{client_address}]")
            print(f"  - Encrypted: {encrypted_message}")
            print(f"  - Decrypted: {decrypted_message}")

            # Broadcast the decrypted message to other clients
            broadcast(decrypted_message.encode(), client_socket)

    except Exception as e:
        print(f"[ERROR] {e}")

    finally:
        # Clean up
        print(f"[DISCONNECT] {client_address} disconnected.")
        clients.remove(client_socket)
        del session_keys[client_socket]
        client_socket.close()
        broadcast(f"System: {client_address} has left the chat.".encode(), None)

# Main server setup
def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(("localhost", 1111))
    server_socket.listen(5)
    print("[STARTING] Server is starting...")

    while True:
        client_socket, client_address = server_socket.accept()
        client_thread = threading.Thread(target=handle_client, args=(client_socket, client_address))
        client_thread.start()

        print(f"[ACTIVE CONNECTIONS] {threading.active_count() - 1}")

        # Generate RSA keys and send public key to client
        public_key, private_key = rsa.newkeys(512)
        client_socket.send(public_key.save_pkcs1())

        # Receive and decrypt session key
        encrypted_session_key = client_socket.recv(1024)
        session_key = rsa.decrypt(encrypted_session_key, private_key)
        session_keys[client_socket] = session_key



if __name__ == "__main__":
    start_server()
