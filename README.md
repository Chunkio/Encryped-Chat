This project implements a simple end-to-end encrypted chat system using Python sockets and the cryptography library. It allows multiple clients to connect to a central server, join chat rooms, and exchange encrypted messages. Messages are securely transmitted and stored in a local SQLite database on the server.

Features

End-to-end AES encryption using keys derived via PBKDF2-HMAC (SHA-256)

Multi-client chat support using threads

Support for multiple chat rooms (default: general)

SQLite database logging of messages with timestamps

Symmetric key encryption for simplicity and efficiency

Project Structure
server.py   # Handles client connections, encryption, and message storage
client.py   # Connects to the server, sends and receives encrypted messages

Requirements

Python 3.8 or higher

cryptography library

sqlite3 (included with Python)

No external dependencies beyond the standard library and cryptography

To install dependencies:

pip install cryptography

How It Works

The server listens for incoming client connections.

Each client connects using a shared secret password that derives a 256-bit AES key.

All messages are encrypted before being sent and decrypted upon receipt.

The server stores messages in an SQLite database with timestamps and user info.

Clients can send messages to rooms and see others’ messages in real-time.

Running the Project
1. Start the Server

Run this command in a terminal:

python server.py


The server will start listening on 127.0.0.1:5555.

2. Start a Client

In a new terminal window, run:

python client.py


The client will connect to the server automatically.
You can open multiple client terminals to simulate multiple users.

3. Send Messages

Once connected, you can:

Send messages to the chat room.

Receive real-time encrypted messages from other clients.

Switch between rooms if additional ones are added in the server code.

Security Details

Encryption Algorithm: AES (CBC mode)

Key Derivation: PBKDF2-HMAC (SHA-256, 100,000 iterations)

Salt: Static salt for demo purposes (should be randomized per user in production)

Padding: PKCS7

Data Encoding: Base64 for message transmission

Notes

This implementation is for educational use and demonstration of encryption and networking concepts.

For production use, unique salts, user authentication, and improved key management should be implemented.

Ensure the same shared password is used by both server and clients.
