#!/usr/bin/env python3
"""
Example client for the Secure Chat Server
Demonstrates how to connect and communicate with the server
Uses string:
config_file
or configuration
"""

import asyncio
import logging
import websockets
import json
import ssl
import base64
import sys
import time

config_file = "config.json"

from pathlib import Path
from datetime import datetime
from typing import Dict, Any, Optional
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend

from database_manager import DatabaseManager
# Ensure the data directory exists
Path("data").mkdir(exist_ok=True)   
# Try to import prompt_toolkit, fall back to input if not available 
try:
    from prompt_toolkit import prompt
    HAS_PROMPT_TOOLKIT = True
except ImportError:
    HAS_PROMPT_TOOLKIT = False
    print("Warning: prompt_toolkit not available, using basic input")
    
    # Define a fallback prompt function that mimics prompt_toolkit's behavior
    def prompt(message: str = "", *, default: str = "") -> str:
        if default:
            user_input = input(f"{message}[{default}] ")
            return user_input if user_input.strip() else default
        else:
            return input(message)

# Set up logging
LOG_DIR = Path("logs")
LOG_DIR.mkdir(exist_ok=True)
LOG_FILE = LOG_DIR / f"chat_client_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"

WORKSPACE_PATH = "."
SERVER_CERT_FILE = "server_certificate.crt"

# These are used for encrypting messages between users. Each user has a unique key pair.
RSA_USER_PRIVATE_KEY_PATH = "_PRIVATE_RSA.pem"
RSA_USER_PUBLIC_KEY_PATH = "_PUBLIC_RSA.pem"
RSA_KEYS_PATH = "keys/"



# Create logger
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)    

# File handler
file_handler = logging.FileHandler(LOG_FILE)
file_handler.setLevel(logging.DEBUG)
file_handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - [%(levelname)s] %(message)s'))
logger.addHandler(file_handler)

# Prevent logs from propagating to the root logger (keeps console clean)
logger.propagate = True

class ChatClient:
    raw_json_to_send = None
    def set_username(self, username: str):
        self.username = username

    def set_password(self, password: str):
        self.password = password

    def __init__(self):
        self.config = self.load_config(config_file)
        self.ssl_cert = self.config["server"].get("ssl_cert_path", SERVER_CERT_FILE)
        self.username = self.config["client"]["username"]
        self.password = self.config["client"]["password"]
        protocol = "wss" if self.config["server"].get("use_ssl", True) else "ws"
        self.server_uri = f"{protocol}://{self.config['server']['host']}:{self.config['server']['port']}"
        self.private_key = None
        self.public_key = None
        self.server_public_key = None
        self.connected_users = {}
        self.authenticated = False
        self.friends_db = {}
        if self.config["encryption"]["store_keys"]:
            Path(self.config["encryption"]["keys_directory"]).mkdir(exist_ok=True)
        from crypto_handler import CryptoHandler
        from network import ChatClientNetwork
        self.crypto = CryptoHandler(self)
        self.crypto.initialize_keys()
        self.network = ChatClientNetwork(self)


    def load_config(self, file=config_file) -> Dict[str, Any]:
        """Load configuration from JSON file"""
        try:
            with open(file, 'r') as f:
                config = json.load(f)
            print(f"✓ Loaded configuration from {file}")
            return config
        except FileNotFoundError:
            print(f"❌ Configuration file {file} not found!")
            print("Creating default configuration...")
            self.create_default_config(file)
            sys.exit(1)
        except json.JSONDecodeError as e:
            print(f"❌ Invalid JSON in {file}: {e}")
            sys.exit(1)
    
    def create_default_config(self, config_file: str):
        """Create a default configuration file"""
        default_config: Dict[str, Any] = {
            "client": {
                "username": "your_username",
                "password": "your_password",
                "auto_login": True,
                "auto_generate_keys": True
            },
            "server": {
                "host": "localhost",
                "port": 8100,
                "use_ssl": True,
                "connection_timeout": 30,
                "ping_interval": 30,
                "ping_timeout": 40,
                "ssl_enabled": True,
                "ssl_cert_path": SERVER_CERT_FILE
            },
            "encryption": {
                "key_size": 2048,
                "auto_encrypt_private_messages": False,
                "store_keys": True,
                "keys_directory": "data/clientkeys/"
            },
            "ui": {
                "show_timestamps": True,
                "show_encryption_status": True,
                "auto_accept_friend_requests": False,
                "notification_sound": False
            },
            "debug": {
                "verbose_logging": False,
                "save_message_history": True,
                "log_file": "client.log"
            }
        }
        
        with open(config_file, 'w') as f:
            json.dump(default_config, f, indent=2)
        print(f"✓ Created default config at {config_file}")
        print("Please edit the configuration file and run the client again.")
    
    def log(self, message: str):
        """Log message if verbose logging is enabled"""
        if self.config["debug"]["verbose_logging"]:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            log_msg = f"[{timestamp}] {message}"
            print(log_msg)
            
            if self.config["debug"]["save_message_history"]:
                with open(self.config["debug"]["log_file"], 'a') as f:
                    f.write(log_msg + "\n")
    
    def ensure_connected(self):
        """Ensure websocket is connected"""
        if self.websocket is None:
            raise ValueError("Not connected to server")
    
    def ensure_private_key(self):
        self.crypto.ensure_private_key()
    
    async def send_message(self, message: Dict[str, Any]):
        """Safely send a message through websocket"""
        if self.websocket is None:
            raise ValueError("Not connected to server")
        await self.websocket.send(json.dumps(message))
    
    async def connect(self, listen: bool = True, ssl_cert_path = SERVER_CERT_FILE):
        """Connect to the chat server"""
        try:
            print(f"🔗 Connecting to {self.server_uri}...")
            
            # Configure SSL context for self-signed certificates
            ssl_context = None
            if self.config["server"].get("use_ssl", True):
                import ssl
                ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                
                # For self-signed certificates, disable verification
                ssl_context.check_hostname = False
                ssl_context.verify_mode = ssl.CERT_NONE
                
                # Optional: If you want to verify against a specific self-signed cert
                if Path(ssl_cert_path).exists():
                    print(f"[SSL_CERT_PATH] Using certificate file: {ssl_cert_path}")
                    # Load the server's self-signed certificate as a trusted CA
                    ssl_context.load_verify_locations(ssl_cert_path)
                    ssl_context.verify_mode = ssl.CERT_REQUIRED
                else:
                    print(f"[SSL_CERT_PATH] Certificate file not found: {ssl_cert_path}")
                    print("[SSL] Using insecure connection (no certificate verification)")
                
                # Enable all ciphers for maximum compatibility
                ssl_context.set_ciphers('ALL:@SECLEVEL=0')
                

            
            print(f"[DEBUG] Attempting connection with timeout: {self.config['server']['connection_timeout']}s")
            
            self.websocket = await websockets.connect(
                self.server_uri,
                ssl=ssl_context,
                ping_interval=None,  # Disable built-in WebSocket PING/PONG
                ping_timeout=None,   # Use our custom protocol instead
                open_timeout=self.config["server"]["connection_timeout"],     # Use config timeout
                close_timeout=5      # Add close timeout
            )
            print(f"✓ Connected to {self.server_uri}")
            print("[DEBUG] WebSocket built-in PING/PONG disabled - using custom protocol")

            # Wait for server info
            server_info = await self.websocket.recv()
            await self.handle_server_info(json.loads(server_info))
            
            # Register or login with server
            if self.config["client"]["auto_login"]:
                success = await self.register_or_login()
                if success:
                    print("✓ Authentication successful")
                    self.IsConnectedToServer = True
                    self.authenticated = True
                else:
                    self.IsConnectedToServer = False
                    self.lastError = "Authentication failed when trying to log in."
                    print("❌ Authentication failed")
            else:
                # Just register without auto-login
                await self.register()

        except ConnectionRefusedError as e:
            self.IsConnectedToServer = False
            self.lastError = f"Connection refused: {e}"
            print(f"❌ Connection refused: Server may not be running on {self.server_uri}")
            return False
        except asyncio.TimeoutError as e:
            self.IsConnectedToServer = False
            self.lastError = f"Connection timeout: {e}"
            print(f"❌ Connection timeout: Server did not respond within timeout period")
            return False
        except ssl.SSLError as e:
            self.IsConnectedToServer = False
            self.lastError = f"SSL error: {e}"
            print(f"❌ SSL error: {e}")
            return False
        except Exception as e:
            self.IsConnectedToServer = False
            self.lastError = str(e)
            print(f"❌ Connection error: {e}")
            print(f"❌ Error type: {type(e).__name__}")
            return False
    
    async def register_or_login(self):
        """Try to register, if user exists then login"""
        # First try to register
        await self.register()
        
        # Wait for response
        try:
            if self.websocket is None:
                raise ValueError("Not connected to server")
            response = await asyncio.wait_for(self.websocket.recv(), timeout=5.0)
            data: Dict[str, Any] = json.loads(response)

            if data.get("type") == "registration_success":
                print(f"✓ Registered successfully as {data.get('username')}")
                return True
            elif data.get("type") == "error" and "already exists" in data.get("message", ""):
                print(f"👤 User exists, attempting login...")
                # Try to login
                success = await self.login()
                return success
            else:
                print(f"❌ Registration failed: {data.get('message')}")
                return False
                
        except asyncio.TimeoutError:
            print("❌ No response from server")
            return False
    
    async def login(self):
        """Login to the server"""
        self.ensure_connected()
        
        login_message: Dict[str, Any] = {
            "type": "login",
            "username": self.username,
            "password": self.password
        }
        
        await self.send_message(login_message)
        
        try:
            response = await asyncio.wait_for(self.websocket.recv(), timeout=5.0)  # type: ignore
            data: Dict[str, Any] = json.loads(response)
            
            if data.get("type") == "login_success":
                print(f"✓ Logged in successfully as {data.get('username')}")
                return True
            else:
                print(f"❌ Login failed: {data.get('message')}")
                return False
                
        except asyncio.TimeoutError:
            print("❌ No response from server during login")
            return False
    
    async def handle_server_info(self, server_info: Dict[str, Any]):
        """Handle server information message"""
        if server_info.get("type") == "server_info":
            server_public_key_pem: Optional[str] = server_info.get("server_public_key")
            if server_public_key_pem:
                self.server_public_key = serialization.load_pem_public_key(
                    server_public_key_pem.encode(),
                    backend=default_backend()
                )
            version = server_info.get("server_version")
            features = server_info.get("supported_features", [])
            print(f"🖥️  Server version: {version}")
            if self.config["debug"]["verbose_logging"]:
                print(f"📋 Supported features: {', '.join(features)}")
            print(f"Connected to server version {version}")

    async def handle_ping(self, ping_message: Dict[str, Any]):
        """Handle PING messages from the server and respond with PONG containing username and timestamp"""
        #print(f"[DEBUG] Handling PING: {ping_message}")  # Debug print

        username = ping_message.get("username")
        timestamp = ping_message.get("timestamp")
        if username is None or timestamp is None:
            print("❌ Received malformed PING from server (missing username or timestamp)")
            return

        if username == self.username:
            pong_response: Dict[str, Any] = {
                "type": "PONG",  # Use lowercase to match what the server expects
                "username": username,
                "timestamp": timestamp
            }
            #print(f"Sending PONG to server with username: {username}, timestamp: {timestamp}")
            if self.websocket:
                await self.websocket.send(json.dumps(pong_response))
    
    async def register(self):
        """Register with the server"""
        if self.public_key is None:
            raise ValueError("Public key not initialized")
            
        public_key_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
        
        registration_message: Dict[str, Any] = {
            "type": "register",
            "username": self.username,
            "password": self.password,
            "public_key": public_key_pem
        }
        
        self.log(f"Sending registration for user: {self.username}")
        if self.websocket is None:
            raise ValueError("Not connected to server")
            
        await self.send_message(registration_message)
    
    async def listen_for_messages(self):
        """Listen for incoming messages"""

        if self.websocket is None:
            raise ValueError("Not connected to server")
        try:

            async for message in self.websocket:
                #print(f"[DEBUG] Received message: {message}")  # Debug print
                await self.handle_message(json.loads(message))
        except websockets.exceptions.ConnectionClosed as e:
            print(f"[DEBUG] Connection closed in listen_for_messages: {e}")
        except Exception as e:
            print(f"[DEBUG] Error listening for messages: {e}")
        finally:
            print("[DEBUG] listen_for_messages finally block reached. Websocket closed or error occurred.")

    async def handle_message(self, message: Dict[str, Any]) -> str:
        message_type = message.get("type")
        timestamp = ""
        if self.config["ui"]["show_timestamps"]:
            timestamp = f"[{datetime.now().strftime('%H:%M:%S')}] "

        if message_type and message_type.upper() == "PING":
            #print(f"🔄 {timestamp}Received PING from server, responding with PONG")
            await self.handle_ping(message)
            

        elif message_type == "registration_success":
            username = message.get('username')
            room = message.get('assigned_room')
            print(f"✅ {timestamp}Successfully registered as {username}")
            if room:
                print(f"🏠 {timestamp}Assigned to room: {room}")
            
        elif message_type == "user_joined":
            username = message.get('username')
            print(f"👋 {timestamp}User {username} joined the chat")
        elif message_type == "user_left":
            username = message.get('username')
            print(f"👋 {timestamp}User {username} left the chat")
        elif message_type == "public_message":
            sender = message.get("sender")
            content = message.get("content")
            room = message.get("room", "")
            room_prefix = f"#{room} " if room else ""
            print(f"💬 {timestamp}{room_prefix}{sender}: {content}")
        elif message_type == "private_message":
            sender = message.get("sender")
            content = message.get("content")
            encrypted = message.get("encrypted", False)
            encryption_status = ""
            if self.config["ui"]["show_encryption_status"]:
                encryption_status = "🔒 " if encrypted else "🔓 "
            if encrypted:
                try:
                    if content:
                        decrypted_content = self.decrypt_message(content)
                        print(f"📨 {timestamp}{encryption_status}[PRIVATE] {sender}: {decrypted_content}")
                    else:
                        print(f"❌ {timestamp}Received encrypted message with no content from {sender}")
                except Exception as e:
                    print(f"❌ {timestamp}Failed to decrypt message from {sender}: {e}")
            else:
                print(f"📨 {timestamp}{encryption_status}[PRIVATE] {sender}: {content}")
        elif message_type == "unread_messages":
            unread_messages = message.get("messages", [])
            if unread_messages:
                print(f"📥 {timestamp}You have {len(unread_messages)} unread messages:")
                for msg in unread_messages:
                    print(f"   - {msg['sender']}: {msg['content']}")
            else:
                print(f"📭 {timestamp}No unread messages.")
        elif message_type == "friend_request_response":
            success = message.get("success")
            friend = message.get("friend_username")
            msg = message.get("message")
            if success:
                print(f"✅ {timestamp}Friend request sent to {friend}")
            else:
                print(f"❌ {timestamp}Friend request to {friend} failed: {msg}")
        elif message_type == "friend_request_accept_response":
            success = message.get("success")
            friend = message.get("friend_username")
            msg = message.get("message")
            if success:
                print(f"🤝 {timestamp}You are now friends with {friend}!")
            else:
                print(f"❌ {timestamp}Failed to accept friend request from {friend}: {msg}")
        elif message_type == "friends_list":
            friends = message.get("friends", [])
            print(f"👥 {timestamp}Your friends ({len(friends)}):")
            for friend in friends:
                last_login = friend.get('last_login')
                if last_login:
                    is_recent = (time.time() - last_login) < 900  # 15 minutes
                    status = "🟢 Online" if is_recent else "⚪ Offline"
                else:
                    status = "❓ Never logged in"
                
                print(f"   - {friend['username']} ({status})")
                
                # Store friend info in memory
                self.friends_db[friend['username']] = {
                    'id': friend.get('id'),
                    'username': friend['username'],
                    'last_login': last_login,
                    'public_key': friend.get('public_key'),
                    'is_online': is_recent if last_login else False
                }
        elif message_type == "friend_requests":
            requests = message.get("requests", [])
            print(f"📬 {timestamp}Friend requests ({len(requests)}):")
            for req in requests:
                print(f"   - From {req['username']}")
        elif message_type == "message_delivered":
            recipient = message.get("recipient")
            online = message.get("online", False)
            status = "delivered" if online else "stored for later delivery"
            print(f"✅ {timestamp}Message to {recipient} {status}")
        elif message_type == "error":
            error_msg = message.get("message")
            print(f"❌ {timestamp}Error: {error_msg}")
        else:
            print(f"🔍 {timestamp}Unknown message type: {message_type}")

        if message_type != "PING":
            print(f"Received {message_type}: {message}")
        return message_type
    
    def encrypt_message(self, message: str, recipient_public_key: Any) -> str:
        """Encrypt a message using recipient's public key"""
        encrypted = recipient_public_key.encrypt(
            message.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return base64.b64encode(encrypted).decode()
    
    def decrypt_message(self, encrypted_message: str) -> str:
        """Decrypt a message using private key"""
        self.ensure_private_key()
        encrypted_data = base64.b64decode(encrypted_message.encode())
        decrypted = self.private_key.decrypt(  # type: ignore
            encrypted_data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return decrypted.decode()
    
    async def get_unread_messages(self):
        """Get unread messages"""
        self.ensure_connected()
        await self.send_message({"type": "get_unread_messages"})
    
    async def send_public_message(self, content: str):
        """Send a public message"""
        self.ensure_connected()
        message: Dict[str, Any] = {
            "type": "public_message",
            "content": content
        }
        await self.send_message(message)  # type: ignore
        print(f"Sent public message: {content}")

    async def send_private_message(self, recipient: str, content: str, encrypt: Optional[bool] = None):
        """Send a private message"""
        if encrypt is None:
            encrypt = self.config["encryption"]["auto_encrypt_private_messages"]
        
        if encrypt:
            # TODO: Implement encryption with recipient's public key
            # For now, send as plain text
            encrypted_content = content
            encrypted = False
        else:
            encrypted_content = content
            encrypted = False
        
        self.ensure_connected()
        
        message: Dict[str, Any] = {
            "type": "private_message",
            "recipient": recipient,
            "content": encrypted_content,
            "encrypted": encrypted
        }
        
        await self.websocket.send(json.dumps(message))  # type: ignore
        print(f"Sent private message to {recipient}: {content}")

    async def send_friend_request(self, friend_username: str):
        """Send a friend request"""
        self.ensure_connected()
        message = {
            "type": "send_friend_request",
            "friend_username": friend_username
        }
        await self.websocket.send(json.dumps(message))  # type: ignore
        print(f"Sent friend request to username:{friend_username}")

    async def accept_friend_request(self, friend_username: str):
        """Accept a friend request"""
        self.ensure_connected()
        message = {
            "type": "accept_friend_request",
            "friend_username": friend_username
        }
        await self.websocket.send(json.dumps(message))  # type: ignore
        print(f"Accepted friend request from {friend_username}")

    async def decline_friend_request(self, friend_username: str):
        """Decline a friend request"""
        self.ensure_connected()
        message = {
            "type": "decline_friend_request",
            "friend_username": friend_username
        }
        await self.websocket.send(json.dumps(message))  # type: ignore
        print(f"Declined friend request from {friend_username}")

    async def get_friends_list(self):
        """Get list of friends"""
        self.ensure_connected()
        message = {"type": "get_friends_list"}
        await self.websocket.send(json.dumps(message))  # type: ignore
        print("Requested friends list")

    async def get_friend_requests(self):
        """Get pending friend requests"""
        self.ensure_connected()
        message = {"type": "get_friend_requests"}
        await self.websocket.send(json.dumps(message))  # type: ignore
        print("Requested friend requests list")

    async def remove_friend(self, friend_username: str):
        """Remove a friend"""
        self.ensure_connected()
        message = {
            "type": "remove_friend",
            "friend_username": friend_username
        }
        await self.websocket.send(json.dumps(message))  # type: ignore
        print(f"Removed friend {friend_username}")

    async def disconnect(self):
        """Disconnect from the server"""
        if self.websocket:
            await self.websocket.close()


async def interactive_shell(client):
    if client.IsConnectedToServer:
        print(f"✅ Successfully connected to the server and logged in with {client.username}")

    print("\n💬 Interactive Secure Chat Shell!")
    print("Type 'help' for available commands. Type 'quit' to exit.")
    print("-" * 40)

    lastcommand = ""
    while True:
        try:
            command = (await asyncio.to_thread(prompt, "\n> ", default=lastcommand)).strip()
            lastcommand = command
            if not command:
                continue
            if command.lower() in ("quit", "exit"):
                break
            if command.lower() == "help":
                print("""
friend list                         - List all friends
friend requests                     - List all friends or friend requests
friend add <user>                  - Send friend request to <user>
friend accept <user>                - Accept friend request from <user>
friend delete <user>                - Delete friend
friend block <user>                 - (Not implemented)
msg send <friend> <message>         - Send encrypted private message
msg unread                         - Get unread messages
msg config autodelete <hours>      - Set auto-delete time for read messages
login <username>                   - Login as <username>
register <username>                - Register as <username>
account update password            - Change password
account update username            - Change username
account update email               - Change email
public <message>                   - Send public message
quit                               - Exit
""")
                continue

            tokens = command.split()
            if not tokens:
                continue

            # FRIEND COMMANDS
            if tokens[0] == "friend":
                if len(tokens) >= 2:
                    if tokens[1] == "list":
                        await client.get_friends_list()
                    elif tokens[1] == "requests":
                        await client.get_friend_requests()
                    elif tokens[1] == "accept" and len(tokens) == 3:
                        print(f"Accepting friend request from {tokens[2]}")                        
                        await client.accept_friend_request(tokens[2])                        
                    elif tokens[1] == "add" and len(tokens) == 3:
                        await client.send_friend_request(tokens[2])
                    elif tokens[1] == "delete" and len(tokens) == 3:
                        await client.remove_friend(tokens[2])
                    elif tokens[1] == "block" and len(tokens) == 3:
                        print(f"Blocking {tokens[2]} (not implemented).")
                    else:
                        print("Unknown friend command.")
                else:
                    print("Usage: friend <list|requests|add|accept|delete|block> ...")

            # MESSAGE COMMANDS
            elif tokens[0] == "msg":
                if len(tokens) >= 2:
                    if tokens[1] == "send" and len(tokens) >= 4:
                        friend = tokens[2]
                        msg = " ".join(tokens[3:])
                        await client.send_private_message(friend, msg, encrypt=False)
                    elif tokens[1] == "unread":
                        await client.get_unread_messages()
                    elif tokens[1] == "config" and len(tokens) == 4 and tokens[2] == "autodelete":
                        try:
                            hours = int(tokens[3])
                            print(f"Set auto-delete to {hours} hours (not implemented in client)")
                        except ValueError:
                            print("Usage: msg config autodelete <hours>")
                    else:
                        print("Unknown message command.")
                else:
                    print("Usage: msg <send|unread|config> ...")

            # LOGIN/REGISTER
            elif tokens[0] == "login" and len(tokens) == 2:
                username = tokens[1]
                password = await asyncio.to_thread(input, "Password: ")
                client.username = username
                client.password = password
                await client.login()
            elif tokens[0] == "register" and len(tokens) == 2:
                username = tokens[1]
                password = await asyncio.to_thread(input, "Password: ")
                client.username = username
                client.password = password
                await client.register()

            # ACCOUNT COMMANDS
            elif tokens[0] == "account" and len(tokens) >= 3 and tokens[1] == "update":
                if tokens[2] == "password":
                    new_pw = await asyncio.to_thread(input, "New password: ")
                    print("Password update not implemented in client.")
                elif tokens[2] == "username":
                    new_un = await asyncio.to_thread(input, "New username: ")
                    print("Username update not implemented in client.")
                elif tokens[2] == "email":
                    new_email = await asyncio.to_thread(input, "New email: ")
                    print("Email update not implemented in client.")
                else:
                    print("Unknown account update command.")

            # PUBLIC MESSAGE
            elif tokens[0] == "public" and len(tokens) > 1:
                msg = " ".join(tokens[1:])
                await client.send_public_message(msg)

            else:
                print("Unknown command. Type 'help' for a list of commands.")

            await asyncio.sleep(0.1)

        except EOFError:
            break
        except KeyboardInterrupt:
            break
        
async def main():
    # Support username/password as command-line arguments
    username = None
    password = None
    ssl_certificate = SERVER_CERT_FILE
    if ssl_certificate.endswith(".crt"):
        print(f"Using SSL certificate: {ssl_certificate}")
        ssl_certificate = SERVER_CERT_FILE
    else:
        ssl_certificate = SERVER_CERT_FILE
        
        print(f"❌ User did not supply a cert file, using {SERVER_CERT_FILE}")

        
    if len(sys.argv) > 1:
        username = sys.argv[1]
    if len(sys.argv) > 2:
        password = sys.argv[2]
        
    client = ChatClient()
    if username:
        client.username = username
    if password:
        client.password = password

    print(f"[CONFIG] Using username: {client.username} (from {'args' if username else config_file})")
    print(f"Connecting to {client.server_uri} as {client.username}...")
    await client.connect(listen=False)

    await client.get_friends_list()

    await asyncio.gather(
        client.listen_for_messages(),
        interactive_shell(client)
    )

