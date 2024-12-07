
# Secure Chat System

A Python-based secure chat application that implements end-to-end encryption for private messaging. The system ensures user data security using the following features:

## Features
1. **AES Encryption**:
   - Uses AES with CFB mode for encrypting chat messages.
   - Ensures message confidentiality over the network.

2. **RSA Key Exchange**:
   - RSA is used to securely exchange the AES session key between the client and server.

3. **User Authentication**:
   - Users can register and log in with credentials stored securely using SHA-256 hashed passwords.

4. **Multi-client Support**:
   - Supports multiple clients connecting to a single server, enabling group chat functionality.

5. **Error Handling and Debugging**:
   - Integrated detailed error handling and debugging logs for encryption, decryption, and data transmission.

## Technologies Used
- **Programming Language**: Python
- **Cryptography Libraries**:
  - `cryptography` for AES encryption.
  - `rsa` for key exchange.
- **Socket Programming**: For client-server communication.
- **Tkinter**: For building the GUI.

## How to Run
1. **Clone the Repository**:
   ```bash
   git clone <repository-url>
   cd secure-chat-system
