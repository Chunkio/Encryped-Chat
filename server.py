import socket
import threading
import json
import sqlite3
from datetime import datetime
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import os
import base64

class ChatServer:
    def __init__(self, host='127.0.0.1', port=5555):
        self.host = host
        self.port = port
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.clients = {}  # {socket: username}
        self.rooms = {'general': set()}  # {room_name: set of usernames}
        self.key = self.derive_key("server_secret_password")
        self.init_database()
        
    def derive_key(self, password):
        """Derive a 256-bit key from password"""
        salt = b'chat_app_salt_2024'  # In production, use random salt per user
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        return kdf.derive(password.encode())
    
    def init_database(self):
        """Initialize SQLite database for message persistence"""
        self.conn = sqlite3.connect('chat_history.db', check_same_thread=False)
        self.cursor = self.conn.cursor()
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                room TEXT,
                username TEXT,
                message TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        self.conn.commit()
    
    def encrypt_message(self, message):
        """Encrypt message using AES-256-CBC"""
        iv = os.urandom(16)
        cipher = Cipher(
            algorithms.AES(self.key),
            modes.CBC(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(message.encode()) + padder.finalize()
        
        encrypted = encryptor.update(padded_data) + encryptor.finalize()
        return base64.b64encode(iv + encrypted).decode()
    
    def decrypt_message(self, encrypted_message):
        """Decrypt AES-256-CBC encrypted message"""
        try:
            data = base64.b64decode(encrypted_message)
            iv = data[:16]
            encrypted = data[16:]
            
            cipher = Cipher(
                algorithms.AES(self.key),
                modes.CBC(iv),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            
            padded = decryptor.update(encrypted) + decryptor.finalize()
            unpadder = padding.PKCS7(128).unpadder()
            message = unpadder.update(padded) + unpadder.finalize()
            
            return message.decode()
        except Exception as e:
            return f"[Decryption Error: {e}]"
    
    def save_message(self, room, username, message):
        """Save message to database"""
        self.cursor.execute(
            'INSERT INTO messages (room, username, message) VALUES (?, ?, ?)',
            (room, username, message)
        )
        self.conn.commit()
    
    def get_room_history(self, room, limit=50):
        """Retrieve recent messages from a room"""
        self.cursor.execute(
            'SELECT username, message, timestamp FROM messages WHERE room = ? ORDER BY id DESC LIMIT ?',
            (room, limit)
        )
        return list(reversed(self.cursor.fetchall()))
    
    def broadcast(self, message, room='general', exclude=None):
        """Broadcast message to all clients in a room"""
        encrypted = self.encrypt_message(json.dumps(message))
        
        if room in self.rooms:
            # Only send to clients who are in this specific room
            users_in_room = self.rooms[room]
            for client_socket, username in list(self.clients.items()):
                if username in users_in_room and client_socket != exclude:
                    try:
                        client_socket.send(encrypted.encode() + b'\n')
                    except:
                        pass
    
    def handle_client(self, client_socket, address):
        """Handle individual client connection"""
        username = None
        current_room = 'general'
        
        try:
            # Receive username
            encrypted_data = client_socket.recv(4096).decode().strip()
            username = self.decrypt_message(encrypted_data)
            self.clients[client_socket] = username
            self.rooms['general'].add(username)
            
            print(f"[+] {username} connected from {address}")
            
            # Send room history
            history = self.get_room_history('general')
            for hist_username, hist_message, timestamp in history:
                msg = {
                    'type': 'history',
                    'username': hist_username,
                    'message': hist_message,
                    'timestamp': timestamp
                }
                encrypted = self.encrypt_message(json.dumps(msg))
                client_socket.send(encrypted.encode() + b'\n')
            
            # Notify others
            self.broadcast({
                'type': 'system',
                'message': f'{username} joined the chat'
            }, current_room, exclude=client_socket)
            
            # Handle messages
            while True:
                encrypted_data = client_socket.recv(4096).decode().strip()
                if not encrypted_data:
                    break
                
                data = json.loads(self.decrypt_message(encrypted_data))
                
                if data['type'] == 'message':
                    message = data['message']
                    self.save_message(current_room, username, message)
                    self.broadcast({
                        'type': 'message',
                        'username': username,
                        'message': message
                    }, current_room)
                    
                elif data['type'] == 'join_room':
                    new_room = data['room']
                    if new_room not in self.rooms:
                        self.rooms[new_room] = set()
                    
                    self.rooms[current_room].discard(username)
                    self.rooms[new_room].add(username)
                    
                    self.broadcast({
                        'type': 'system',
                        'message': f'{username} left the room'
                    }, current_room)
                    
                    current_room = new_room
                    
                    self.broadcast({
                        'type': 'system',
                        'message': f'{username} joined the room'
                    }, current_room, exclude=client_socket)
                    
                    # Send new room history
                    history = self.get_room_history(current_room)
                    for hist_username, hist_message, timestamp in history:
                        msg = {
                            'type': 'history',
                            'username': hist_username,
                            'message': hist_message,
                            'timestamp': timestamp
                        }
                        encrypted = self.encrypt_message(json.dumps(msg))
                        client_socket.send(encrypted.encode() + b'\n')
                    
        except Exception as e:
            print(f"[!] Error handling {username}: {e}")
        finally:
            if username and client_socket in self.clients:
                # Remove from current room
                if current_room in self.rooms:
                    self.rooms[current_room].discard(username)
                    self.broadcast({
                        'type': 'system',
                        'message': f'{username} left the chat'
                    }, current_room)
                del self.clients[client_socket]
                print(f"[-] {username} disconnected")
            client_socket.close()
    
    def start(self):
        """Start the chat server"""
        self.server.bind((self.host, self.port))
        self.server.listen()
        print(f"[*] Server listening on {self.host}:{self.port}")
        print(f"[*] Encryption: AES-256-CBC")
        print(f"[*] Message persistence: SQLite (chat_history.db)")
        
        try:
            while True:
                client_socket, address = self.server.accept()
                thread = threading.Thread(
                    target=self.handle_client,
                    args=(client_socket, address)
                )
                thread.daemon = True
                thread.start()
        except KeyboardInterrupt:
            print("\n[*] Shutting down server...")
            self.conn.close()
            self.server.close()

if __name__ == "__main__":
    server = ChatServer()
    server.start()