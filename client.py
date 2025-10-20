import socket
import threading
import json
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import os
import base64

class ChatClient:
    def __init__(self, host='127.0.0.1', port=5555):
        self.host = host
        self.port = port
        self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.key = self.derive_key("server_secret_password")
        self.current_room = 'general'
        self.running = True
        
    def derive_key(self, password):
        """Derive a 256-bit key from password"""
        salt = b'chat_app_salt_2024'
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        return kdf.derive(password.encode())
    
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
            return f"[Decryption Error]"
    
    def receive_messages(self):
        """Receive and decrypt messages from server"""
        while self.running:
            try:
                encrypted_data = self.client.recv(4096).decode().strip()
                if not encrypted_data:
                    break
                
                data = json.loads(self.decrypt_message(encrypted_data))
                
                if data['type'] == 'message':
                    print(f"\n[{data['username']}]: {data['message']}")
                    print(f"You > ", end='', flush=True)
                    
                elif data['type'] == 'system':
                    print(f"\n[SYSTEM] {data['message']}")
                    print(f"You > ", end='', flush=True)
                    
                elif data['type'] == 'history':
                    timestamp = data['timestamp'].split('.')[0]  # Remove microseconds
                    print(f"[{timestamp}] [{data['username']}]: {data['message']}")
                    
            except Exception as e:
                if self.running:
                    print(f"\n[!] Connection error: {e}")
                break
    
    def send_message(self, message):
        """Encrypt and send message to server"""
        encrypted = self.encrypt_message(message)
        self.client.send(encrypted.encode() + b'\n')
    
    def start(self):
        """Start the chat client"""
        try:
            self.client.connect((self.host, self.port))
            print(f"[*] Connected to {self.host}:{self.port}")
            print(f"[*] Encryption: AES-256-CBC")
            
            # Get username
            username = input("Enter your username: ")
            self.send_message(username)
            
            print(f"\n[*] Welcome to the encrypted chat, {username}!")
            print("[*] Current room: general")
            print("\nCommands:")
            print("  /join <room>  - Join a different room")
            print("  /leave        - Return to general room")
            print("  /quit         - Exit the program")
            print("\n--- Chat History ---")
            
            # Start receiving thread
            receive_thread = threading.Thread(target=self.receive_messages)
            receive_thread.daemon = True
            receive_thread.start()
            
            # Wait for history to load
            import time
            time.sleep(0.5)
            print("--- End of History ---\n")
            
            # Send messages
            while self.running:
                message = input("You > ")
                
                if message.startswith('/quit'):
                    self.running = False
                    print("[*] Exiting program...")
                    break
                
                elif message.startswith('/leave'):
                    if self.current_room == 'general':
                        print("[*] You are already in the general room")
                    else:
                        data = {
                            'type': 'join_room',
                            'room': 'general'
                        }
                        self.send_message(json.dumps(data))
                        self.current_room = 'general'
                        print(f"[*] Returned to general room")
                        print("\n--- Chat History ---")
                        time.sleep(0.5)
                        print("--- End of History ---\n")
                    
                elif message.startswith('/join '):
                    room = message.split(' ', 1)[1]
                    if room == self.current_room:
                        print(f"[*] You are already in room: {room}")
                    else:
                        data = {
                            'type': 'join_room',
                            'room': room
                        }
                        self.send_message(json.dumps(data))
                        self.current_room = room
                        print(f"[*] Switched to room: {room}")
                        print("\n--- Chat History ---")
                        time.sleep(0.5)
                        print("--- End of History ---\n")
                    
                elif message.strip():
                    data = {
                        'type': 'message',
                        'message': message
                    }
                    self.send_message(json.dumps(data))
                    
        except Exception as e:
            print(f"[!] Error: {e}")
        finally:
            self.running = False
            self.client.close()
            print("\n[*] Disconnected from server")

if __name__ == "__main__":
    client = ChatClient()
    client.start()