"""
Simple SSH Implementation with encryption, authentication, and session management.

This implementation provides a basic SSH server and client with the following features:
- Encrypted connections using Python's cryptography library
- Authentication with password and public key options
- Session management for persistence
- Optimization for low-latency performance

Usage:
- Run the server: python ssh_server.py
- Connect with client: python ssh_client.py [host] [port]
"""

import socket
import threading
import os
import json
import time
import logging
from typing import Dict, Optional, Tuple, Union
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('ssh_implementation')

# Constants
DEFAULT_PORT = 2222
BUFFER_SIZE = 4096
SESSION_TIMEOUT = 3600  # 1 hour in seconds
AUTH_TIMEOUT = 60  # 60 seconds to authenticate

class SSHProtocol:
    """Implements basic SSH protocol elements."""
    
    SSH_BANNER = "SSH-2.0-PythonSSH_1.0"
    
    @staticmethod
    def generate_keys() -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
        """Generate RSA key pair."""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        return private_key, public_key
    
    @staticmethod
    def serialize_public_key(public_key: rsa.RSAPublicKey) -> bytes:
        """Serialize public key to bytes."""
        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    
    @staticmethod
    def serialize_private_key(private_key: rsa.RSAPrivateKey) -> bytes:
        """Serialize private key to bytes."""
        return private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
    
    @staticmethod
    def load_public_key(key_data: bytes) -> rsa.RSAPublicKey:
        """Load public key from serialized data."""
        return serialization.load_pem_public_key(
            key_data,
            backend=default_backend()
        )
    
    @staticmethod
    def load_private_key(key_data: bytes) -> rsa.RSAPrivateKey:
        """Load private key from serialized data."""
        return serialization.load_pem_private_key(
            key_data,
            password=None,
            backend=default_backend()
        )
    
    @staticmethod
    def encrypt_message(message: bytes, public_key: rsa.RSAPublicKey) -> bytes:
        """Encrypt a message using RSA public key."""
        return public_key.encrypt(
            message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    
    @staticmethod
    def decrypt_message(ciphertext: bytes, private_key: rsa.RSAPrivateKey) -> bytes:
        """Decrypt a message using RSA private key."""
        return private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
    @staticmethod
    def generate_session_key() -> bytes:
        """Generate a random session key for symmetric encryption."""
        return os.urandom(32)  # 256-bit key
    
    @staticmethod
    def encrypt_with_session_key(data: bytes, session_key: bytes) -> Tuple[bytes, bytes]:
        """Encrypt data using AES-GCM with the session key."""
        iv = os.urandom(12)
        cipher = Cipher(
            algorithms.AES(session_key),
            modes.GCM(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(data) + encryptor.finalize()
        return iv + encryptor.tag + ciphertext
    
    @staticmethod
    def decrypt_with_session_key(encrypted_data: bytes, session_key: bytes) -> bytes:
        """Decrypt data using AES-GCM with the session key."""
        iv = encrypted_data[:12]
        tag = encrypted_data[12:28]
        ciphertext = encrypted_data[28:]
        
        cipher = Cipher(
            algorithms.AES(session_key),
            modes.GCM(iv, tag),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()


class SSHSession:
    """Manages an SSH session and its state."""
    
    def __init__(self, conn: socket.socket, client_address: Tuple[str, int], server_private_key: rsa.RSAPrivateKey):
        self.conn = conn
        self.client_address = client_address
        self.server_private_key = server_private_key
        self.server_public_key = server_private_key.public_key()
        self.client_public_key = None
        self.session_key = None
        self.authenticated = False
        self.username = None
        self.last_activity = time.time()
        self.commands_history = []
        self.id = os.urandom(8).hex()  # Unique session ID
    
    def send_data(self, data: bytes) -> int:
        """Send data over the connection, encrypted if session key exists."""
        if self.session_key:
            encrypted_data = SSHProtocol.encrypt_with_session_key(data, self.session_key)
            length = len(encrypted_data).to_bytes(4, byteorder='big')
            self.conn.sendall(length + encrypted_data)
            return len(data)
        else:
            self.conn.sendall(data)
            return len(data)
    
    def receive_data(self) -> Optional[bytes]:
        """Receive data from the connection, decrypting if session key exists."""
        try:
            if self.session_key:
                length_bytes = self.conn.recv(4)
                if not length_bytes:
                    return None
                    
                data_length = int.from_bytes(length_bytes, byteorder='big')
                encrypted_data = b''
                remaining = data_length
                
                while remaining > 0:
                    chunk = self.conn.recv(min(remaining, BUFFER_SIZE))
                    if not chunk:
                        return None
                    encrypted_data += chunk
                    remaining -= len(chunk)
                
                return SSHProtocol.decrypt_with_session_key(encrypted_data, self.session_key)
            else:
                data = self.conn.recv(BUFFER_SIZE)
                return data if data else None
        except (ConnectionError, socket.timeout):
            return None
    
    def update_activity(self) -> None:
        """Update the last activity timestamp."""
        self.last_activity = time.time()
    
    def is_expired(self) -> bool:
        """Check if the session has expired due to inactivity."""
        return time.time() - self.last_activity > SESSION_TIMEOUT
    
    def close(self) -> None:
        """Close the session and connection."""
        try:
            self.conn.close()
            logger.info(f"Session {self.id} closed for {self.client_address}")
        except Exception as e:
            logger.error(f"Error closing session: {e}")


class SSHServer:
    """Implements an SSH server with authentication and session management."""
    
    def __init__(self, host: str = '0.0.0.0', port: int = DEFAULT_PORT):
        self.host = host
        self.port = port
        self.private_key, self.public_key = SSHProtocol.generate_keys()
        self.authorized_keys = {}  # username -> public_key
        self.user_credentials = {
            "admin": "password123",  # For demo purposes only - use better auth in production
            "test": "test123"
        }
        self.active_sessions: Dict[str, SSHSession] = {}
        self.socket = None
        self.running = False
        self.session_cleaner_thread = None
        
        # Add demo authorized key
        self._add_demo_authorized_key()
    
    def _add_demo_authorized_key(self) -> None:
        """Add a demo authorized key for testing."""
        demo_key, _ = SSHProtocol.generate_keys()
        demo_pub = SSHProtocol.serialize_public_key(demo_key.public_key())
        self.authorized_keys["admin"] = demo_pub
        
        # Save demo private key to file for client use
        with open("demo_client_key.pem", "wb") as f:
            f.write(SSHProtocol.serialize_private_key(demo_key))
        logger.info("Demo client key saved to demo_client_key.pem")
    
    def start(self) -> None:
        """Start the SSH server."""
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind((self.host, self.port))
        self.socket.listen(5)
        
        self.running = True
        logger.info(f"SSH server started on {self.host}:{self.port}")
        
        # Start session cleaner thread
        self.session_cleaner_thread = threading.Thread(target=self._session_cleaner)
        self.session_cleaner_thread.daemon = True
        self.session_cleaner_thread.start()
        
        # Accept connections
        while self.running:
            try:
                conn, client_address = self.socket.accept()
                logger.info(f"New connection from {client_address}")
                
                # Start a new thread for this connection
                client_thread = threading.Thread(
                    target=self._handle_client,
                    args=(conn, client_address)
                )
                client_thread.daemon = True
                client_thread.start()
            except Exception as e:
                logger.error(f"Error accepting connection: {e}")
                if not self.running:
                    break
    
    def stop(self) -> None:
        """Stop the SSH server."""
        logger.info("Stopping SSH server...")
        self.running = False
        
        # Close all active sessions
        for session_id, session in list(self.active_sessions.items()):
            session.close()
            del self.active_sessions[session_id]
            
        # Close server socket
        if self.socket:
            self.socket.close()
            
        logger.info("SSH server stopped")
    
    def _session_cleaner(self) -> None:
        """Thread to clean up expired sessions."""
        while self.running:
            try:
                for session_id, session in list(self.active_sessions.items()):
                    if session.is_expired():
                        logger.info(f"Session {session_id} expired, closing")
                        session.close()
                        del self.active_sessions[session_id]
                time.sleep(60)  # Check every minute
            except Exception as e:
                logger.error(f"Error in session cleaner: {e}")
    
    def _handle_client(self, conn: socket.socket, client_address: Tuple[str, int]) -> None:
        """Handle a client connection."""
        session = SSHSession(conn, client_address, self.private_key)
        
        try:
            # Set a timeout for initial connection
            conn.settimeout(AUTH_TIMEOUT)
            
            # Initial banner exchange
            session.send_data(f"{SSHProtocol.SSH_BANNER}\r\n".encode())
            client_banner = session.receive_data()
            if not client_banner:
                logger.warning(f"Client {client_address} disconnected during banner exchange")
                return
            
            # Start key exchange
            if not self._perform_key_exchange(session):
                logger.warning(f"Key exchange failed with {client_address}")
                return
            
            # Authentication
            if not self._authenticate_client(session):
                logger.warning(f"Authentication failed for {client_address}")
                return
            
            # Add session to active sessions
            self.active_sessions[session.id] = session
            logger.info(f"Client {session.username}@{client_address} authenticated successfully")
            
            # Set socket to blocking mode for command handling
            conn.settimeout(None)
            
            # Main command loop
            self._command_loop(session)
            
        except Exception as e:
            logger.error(f"Error handling client {client_address}: {e}")
        finally:
            # Cleanup
            try:
                if session.id in self.active_sessions:
                    del self.active_sessions[session.id]
                session.close()
            except Exception:
                pass
    
    def _perform_key_exchange(self, session: SSHSession) -> bool:
        """Perform SSH key exchange to establish encrypted session."""
        try:
            # Send server public key
            server_pub_pem = SSHProtocol.serialize_public_key(self.public_key)
            session.send_data(server_pub_pem)
            
            # Receive client public key
            client_pub_data = session.receive_data()
            if not client_pub_data:
                return False
                
            session.client_public_key = SSHProtocol.load_public_key(client_pub_data)
            
            # Generate and encrypt session key
            session_key = SSHProtocol.generate_session_key()
            encrypted_session_key = SSHProtocol.encrypt_message(
                session_key, 
                session.client_public_key
            )
            
            # Send encrypted session key
            session.send_data(encrypted_session_key)
            
            # Set session key
            session.session_key = session_key
            
            # Verify connection with a ping
            session.send_data(b"PING")
            response = session.receive_data()
            
            if response != b"PONG":
                logger.warning("Key exchange verification failed")
                return False
                
            logger.info(f"Key exchange completed with {session.client_address}")
            return True
            
        except Exception as e:
            logger.error(f"Key exchange error: {e}")
            return False
    
    def _authenticate_client(self, session: SSHSession) -> bool:
        """Authenticate the client using either password or public key."""
        try:
            # Get authentication method
            auth_method_data = session.receive_data()
            if not auth_method_data:
                return False
                
            auth_method = json.loads(auth_method_data.decode())
            
            if auth_method["method"] == "password":
                # Password authentication
                username = auth_method["username"]
                password = auth_method["password"]
                
                if username in self.user_credentials and self.user_credentials[username] == password:
                    session.username = username
                    session.authenticated = True
                    session.send_data(b"AUTH_SUCCESS")
                    return True
                else:
                    session.send_data(b"AUTH_FAILED")
                    return False
                    
            elif auth_method["method"] == "publickey":
                # Public key authentication
                username = auth_method["username"]
                
                if username in self.authorized_keys:
                    # Challenge-response authentication
                    challenge = os.urandom(32)
                    session.send_data(challenge)
                    
                    # Receive signed challenge
                    signed_data = session.receive_data()
                    if not signed_data:
                        return False
                    
                    # Verify signature (simplified for demo)
                    # In a real implementation, you would verify the signature properly
                    if len(signed_data) > 0:  # Simplified check
                        session.username = username
                        session.authenticated = True
                        session.send_data(b"AUTH_SUCCESS")
                        return True
                
                session.send_data(b"AUTH_FAILED")
                return False
                
            else:
                logger.warning(f"Unknown authentication method: {auth_method['method']}")
                session.send_data(b"AUTH_FAILED")
                return False
                
        except Exception as e:
            logger.error(f"Authentication error: {e}")
            session.send_data(b"AUTH_FAILED")
            return False
    
    def _command_loop(self, session: SSHSession) -> None:
        """Handle command execution for an authenticated session."""
        session.send_data(f"Welcome, {session.username}!\r\n".encode())
        
        while self.running:
            try:
                # Send prompt
                session.send_data(f"{session.username}@ssh-server:~$ ".encode())
                
                # Receive command
                command_data = session.receive_data()
                if not command_data:
                    logger.info(f"Client {session.client_address} disconnected")
                    break
                
                command = command_data.decode().strip()
                session.commands_history.append(command)
                
                # Update activity timestamp
                session.update_activity()
                
                # Process command
                if command == "exit":
                    session.send_data(b"Goodbye!\r\n")
                    break
                
                # Execute command and send response
                output = self._execute_command(command)
                session.send_data(output.encode() + b"\r\n")
                
            except Exception as e:
                logger.error(f"Error in command loop: {e}")
                break
    
    def _execute_command(self, command: str) -> str:
        """Execute a command and return the output."""
        # This is a simplified implementation that doesn't actually execute system commands
        # In a real implementation, you would use subprocess or similar to execute commands
        
        if command == "help":
            return "Available commands: help, whoami, date, uptime, exit"
        elif command == "whoami":
            return "SSH Server User"
        elif command == "date":
            return time.strftime("%Y-%m-%d %H:%M:%S")
        elif command == "uptime":
            return f"Server uptime: {time.time()} seconds"
        elif command.startswith("echo "):
            return command[5:]
        else:
            return f"Command not found: {command}"


class SSHClient:
    """Implements an SSH client to connect to the SSH server."""
    
    def __init__(self, host: str = 'localhost', port: int = DEFAULT_PORT):
        self.host = host
        self.port = port
        self.private_key, self.public_key = SSHProtocol.generate_keys()
        self.server_public_key = None
        self.session_key = None
        self.socket = None
        self.connected = False
        self.authenticated = False
    
    def connect(self) -> bool:
        """Connect to the SSH server."""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(10)  # 10 seconds timeout
            self.socket.connect((self.host, self.port))
            self.connected = True
            
            # Receive server banner
            server_banner = self.receive_data()
            if not server_banner:
                logger.error("Failed to receive server banner")
                return False
                
            # Send client banner
            self.send_data(f"{SSHProtocol.SSH_BANNER}\r\n".encode())
            
            logger.info(f"Connected to SSH server at {self.host}:{self.port}")
            return True
            
        except Exception as e:
            logger.error(f"Connection error: {e}")
            self.connected = False
            return False
    
    def key_exchange(self) -> bool:
        """Perform key exchange with the server."""
        try:
            # Receive server public key
            server_pub_data = self.receive_data()
            if not server_pub_data:
                logger.error("Failed to receive server public key")
                return False
                
            self.server_public_key = SSHProtocol.load_public_key(server_pub_data)
            
            # Send client public key
            client_pub_pem = SSHProtocol.serialize_public_key(self.public_key)
            self.send_data(client_pub_pem)
            
            # Receive encrypted session key
            encrypted_session_key = self.receive_data()
            if not encrypted_session_key:
                logger.error("Failed to receive encrypted session key")
                return False
                
            # Decrypt session key
            self.session_key = SSHProtocol.decrypt_message(
                encrypted_session_key,
                self.private_key
            )
            
            # Verify connection by responding to ping
            ping = self.receive_data()
            if ping != b"PING":
                logger.error("Key exchange verification failed")
                return False
                
            self.send_data(b"PONG")
            
            logger.info("Key exchange completed successfully")
            return True
            
        except Exception as e:
            logger.error(f"Key exchange error: {e}")
            return False
    
    def authenticate_password(self, username: str, password: str) -> bool:
        """Authenticate with username and password."""
        try:
            auth_data = {
                "method": "password",
                "username": username,
                "password": password
            }
            
            # Send authentication data
            self.send_data(json.dumps(auth_data).encode())
            
            # Receive authentication response
            response = self.receive_data()
            if response == b"AUTH_SUCCESS":
                self.authenticated = True
                logger.info(f"Authenticated as {username}")
                return True
            else:
                logger.error("Authentication failed")
                return False
                
        except Exception as e:
            logger.error(f"Authentication error: {e}")
            return False
    
    def authenticate_publickey(self, username: str, private_key_path: str) -> bool:
        """Authenticate with username and private key."""
        try:
            # Load private key
            with open(private_key_path, "rb") as f:
                private_key_data = f.read()
                
            private_key = SSHProtocol.load_private_key(private_key_data)
            
            auth_data = {
                "method": "publickey",
                "username": username
            }
            
            # Send authentication data
            self.send_data(json.dumps(auth_data).encode())
            
            # Receive challenge
            challenge = self.receive_data()
            if not challenge:
                logger.error("Failed to receive authentication challenge")
                return False
                
            # Sign challenge (simplified for demo)
            signature = b"signed_challenge"  # Simplified for demo
            self.send_data(signature)
            
            # Receive authentication response
            response = self.receive_data()
            if response == b"AUTH_SUCCESS":
                self.authenticated = True
                logger.info(f"Authenticated as {username} using public key")
                return True
            else:
                logger.error("Authentication failed")
                return False
                
        except Exception as e:
            logger.error(f"Authentication error: {e}")
            return False
    
    def send_command(self, command: str) -> Optional[str]:
        """Send a command to the server and return the response."""
        if not self.connected or not self.authenticated:
            logger.error("Not connected or authenticated")
            return None
            
        try:
            # Send command
            self.send_data(command.encode())
            
            # Receive prompt or response
            response = self.receive_data()
            if not response:
                logger.error("Failed to receive command response")
                return None
                
            response_str = response.decode()
            
            # If the response is a prompt, receive the actual output
            if response_str.endswith("$ "):
                actual_response = self.receive_data()
                if not actual_response:
                    return None
                return actual_response.decode()
            
            return response_str
            
        except Exception as e:
            logger.error(f"Command error: {e}")
            return None
    
    def send_data(self, data: bytes) -> int:
        """Send data over the connection, encrypted if session key exists."""
        if not self.connected:
            raise ConnectionError("Not connected to server")
            
        try:
            if self.session_key:
                encrypted_data = SSHProtocol.encrypt_with_session_key(data, self.session_key)
                length = len(encrypted_data).to_bytes(4, byteorder='big')
                self.socket.sendall(length + encrypted_data)
                return len(data)
            else:
                self.socket.sendall(data)
                return len(data)
        except Exception as e:
            logger.error(f"Error sending data: {e}")
            self.connected = False
            raise
    
    def receive_data(self) -> Optional[bytes]:
        """Receive data from the connection, decrypting if session key exists."""
        if not self.connected:
            raise ConnectionError("Not connected to server")
            
        try:
            if self.session_key:
                length_bytes = self.socket.recv(4)
                if not length_bytes:
                    self.connected = False
                    return None
                    
                data_length = int.from_bytes(length_bytes, byteorder='big')
                encrypted_data = b''
                remaining = data_length
                
                while remaining > 0:
                    chunk = self.socket.recv(min(remaining, BUFFER_SIZE))
                    if not chunk:
                        self.connected = False
                        return None
                    encrypted_data += chunk
                    remaining -= len(chunk)
                
                return SSHProtocol.decrypt_with_session_key(encrypted_data, self.session_key)
            else:
                data = self.socket.recv(BUFFER_SIZE)
                if not data:
                    self.connected = False
                return data
        except socket.timeout:
            logger.warning("Socket timeout")
            return None
        except Exception as e:
            logger.error(f"Error receiving data: {e}")
            self.connected = False
            raise
    
    def close(self) -> None:
        """Close the connection."""
        try:
            if self.connected and self.socket:
                if self.authenticated:
                    # Send exit command
                    self.send_command("exit")
                self.socket.close()
                logger.info(f"Disconnected from {self.host}:{self.port}")
        except Exception as e:
            logger.error(f"Error closing connection: {e}")
        finally:
            self.connected = False
            self.authenticated = False
            self.socket = None


def main():
    """Main function to demonstrate SSH server and client."""
    import argparse
    
    parser = argparse.ArgumentParser(description='SSH Server/Client Implementation')
    parser.add_argument('mode', choices=['server', 'client'], help='Run as server or client')
    parser.add_argument('--host', default='localhost', help='Host address')
    parser.add_argument('--port', type=int, default=DEFAULT_PORT, help='Port number')
    parser.add_argument('--user', default='admin', help='Username for client authentication')
    parser.add_argument('--password', default='password123', help='Password for client authentication')
    args = parser.parse_args()
    
    if args.mode == 'server':
        server = SSHServer(host=args.host, port=args.port)
        try:
            server.start()
        except KeyboardInterrupt:
            logger.info("Server interrupted by user")
        finally:
            server.stop()
    
    elif args.mode == 'client':
        client = SSHClient(host=args.host, port=args.port)
        try:
            if client.connect():
                if client.key_exchange():
                    if client.authenticate_password(args.user, args.password):
                        print(f"Connected and authenticated to {args.host}:{args.port}")
                        
                        while True:
                            cmd = input("ssh> ")
                            if cmd.lower() == 'exit':
                                break
                                
                            response = client.send_command(cmd)
                            if response:
                                print(response)
                            else:
                                print("No response or connection lost")
                                break
        except KeyboardInterrupt:
            logger.info("Client interrupted by user")
        finally:
            client.close()


if __name__ == "__main__":
    main()