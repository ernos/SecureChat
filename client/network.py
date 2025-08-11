
import asyncio
import json
import websockets
import ssl
import base64
import time

from pathlib import Path
from datetime import datetime
from typing import Dict, Any, Optional
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

class ChatClientNetwork:    
    """
    Handles all networking operations for the chat client (connect, send/receive, etc).
    Used via composition in ChatClient. 
    """
    def __init__(self, client):
        self.client = client  # Reference to ChatClient for config, keys, etc.
        self.websocket = None
        self.connected = self.isConnected()
        self.lastError = None

    async def connect(self, listen: bool = True, ssl_cert_path = None):
        client = self.client
        config = client.config
        self.websocket = None
        try:
            print(f"🔗 Connecting to {client.server_uri}...")
            ssl_context = None
            if config["server"].get("use_ssl", True):
                ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ssl_context.check_hostname = False
                ssl_context.verify_mode = ssl.CERT_NONE
                if Path(ssl_cert_path or client.ssl_cert).exists():
                    print(f"[SSL_CERT_PATH] Using certificate file: {ssl_cert_path or client.ssl_cert}")
                    ssl_context.load_verify_locations(ssl_cert_path or client.ssl_cert)
                    ssl_context.verify_mode = ssl.CERT_REQUIRED
                else:
                    print(f"[SSL_CERT_PATH] Certificate file not found: {ssl_cert_path or client.ssl_cert}")
                    print("[SSL] Using insecure connection (no certificate verification)")
                ssl_context.set_ciphers('ALL:@SECLEVEL=0')
            print(f"[DEBUG] Attempting connection with timeout: {config['server']['connection_timeout']}s")
            self.websocket = await websockets.connect(
                client.server_uri,
                ssl=ssl_context,
                ping_interval=None,
                ping_timeout=None,
                open_timeout=config["server"]["connection_timeout"],
                close_timeout=5
            )
            print(f"✓ Connected to {client.server_uri}")
            print("[DEBUG] WebSocket built-in PING/PONG disabled - using custom protocol")
            server_info = await self.websocket.recv()
            await self.handle_server_info(json.loads(server_info))
            if config["client"]["auto_login"]:
                success = await self.register_or_login()
                if success:
                    print("✓ Authentication successful")
                    client.authenticated = True
                else:
                    self.lastError = "Authentication failed when trying to log in."
                    print("❌ Authentication failed")
            else:
                await self.register()
        except ConnectionRefusedError as e:
            self.lastError = f"Connection refused: {e}"
            print(f"❌ Connection refused: Server may not be running on {client.server_uri}")
            return False
        except asyncio.TimeoutError as e:
            self.lastError = f"Consnection timeout: {e}"
            print(f"❌ Connection timeout: Server did not respond within timeout period")
            return False
        except ssl.SSLError as e:
            self.lastError = f"SSL error: {e}"
            print(f"❌ SSL error: {e}")
            return False
        except Exception as e:
            self.lastError = str(e)
            print(f"❌ Connection error: {e}")
            print(f"❌ Error type: {type(e).__name__}")
            return False

    async def send_message(self, message: Dict[str, Any]):
        if self.websocket is None:
            raise ValueError("Not connected to server")
        await self.websocket.send(json.dumps(message))

    async def register_or_login(self):
        await self.register()
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
                success = await self.login()
                return success
            else:
                print(f"❌ Registration failed: {data.get('message')}")
                return False
        except asyncio.TimeoutError:
            print("❌ No response from server")
            return False

    async def login(self):
        client = self.client
        if self.websocket is None:
            raise ValueError("Not connected to server")
        login_message: Dict[str, Any] = {
            "type": "login",
            "username": client.username,
            "password": client.password
        }
        await self.send_message(login_message)
        try:
            response = await asyncio.wait_for(self.websocket.recv(), timeout=5.0)
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
        client = self.client
        if server_info.get("type") == "server_info":
            server_public_key_pem: Optional[str] = server_info.get("server_public_key")
            if server_public_key_pem:
                client.server_public_key = serialization.load_pem_public_key(
                    server_public_key_pem.encode(),
                    backend=default_backend()
                )
            version = server_info.get("server_version")
            features = server_info.get("supported_features", [])
            print(f"🖥️  Server version: {version}")
            if client.config["debug"]["verbose_logging"]:
                print(f"📋 Supported features: {', '.join(features)}")
            print(f"Connected to server version {version}")

    async def handle_ping(self, ping_message: Dict[str, Any]):
        client = self.client
        username = ping_message.get("username")
        timestamp = ping_message.get("timestamp")
        if username is None or timestamp is None:
            print("❌ Received malformed PING from server (missing username or timestamp)")
            return
        if username == client.username:
            pong_response: Dict[str, Any] = {
                "type": "PONG",
                "username": username,
                "timestamp": timestamp
            }
            if self.websocket:
                await self.websocket.send(json.dumps(pong_response))

    async def register(self):
        client = self.client
        if client.public_key is None:
            raise ValueError("Public key not initialized")
        public_key_pem = client.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
        registration_message: Dict[str, Any] = {
            "type": "register",
            "username": client.username,
            "password": client.password,
            "public_key": public_key_pem
        }
        client.log(f"Sending registration for user: {client.username}")
        if self.websocket is None:
            raise ValueError("Not connected to server")
        await self.send_message(registration_message)

    async def listen_for_messages(self):
        if self.websocket is None:
            raise ValueError("Not connected to server")
        try:
            async for message in self.websocket:
                await self.handle_message(json.loads(message))
        except websockets.exceptions.ConnectionClosed as e:
            print(f"[DEBUG] Connection closed in listen_for_messages: {e}")
        except Exception as e:
            print(f"[DEBUG] Error listening for messages: {e}")
        finally:
            print("[DEBUG] listen_for_messages finally block reached. Websocket closed or error occurred.")

    async def handle_message(self, message: Dict[str, Any]):
        client = self.client
        message_type = message.get("type")
        timestamp = ""
        if client.config["ui"]["show_timestamps"]:
            timestamp = f"[{datetime.now().strftime('%H:%M:%S')}] "
        if message_type and message_type.upper() == "PING":
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
            if client.config["ui"]["show_encryption_status"]:
                encryption_status = "🔒 " if encrypted else "🔓 "
            if encrypted:
                try:
                    if content:
                        decrypted_content = client.decrypt_message(content)
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
                    is_recent = (time.time() - last_login) < 900
                    status = "🟢 Online" if is_recent else "⚪ Offline"
                else:
                    status = "❓ Never logged in"
                print(f"   - {friend['username']} ({status})")
                client.friends_db[friend['username']] = {
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

    async def get_unread_messages(self):
        self.ensure_connected()
        await self.send_message({"type": "get_unread_messages"})

    async def send_public_message(self, content: str):
        self.ensure_connected()
        message: Dict[str, Any] = {
            "type": "public_message",
            "content": content
        }
        await self.send_message(message)
        print(f"Sent public message: {content}")

    async def send_private_message(self, recipient: str, content: str, encrypt: Optional[bool] = None):
        client = self.client
        if encrypt is None:
            encrypt = client.config["encryption"]["auto_encrypt_private_messages"]
        if encrypt:
            try:
                encrypted_content = client.encrypt_message(content)
                encrypted = True
            except Exception as e:
                print(f"❌ Failed to encrypt message: {e}")
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
        await self.websocket.send(json.dumps(message))
        print(f"Sent private message to {recipient}: {content}")

    async def send_friend_request(self, friend_username: str):
        self.ensure_connected()
        message = {
            "type": "send_friend_request",
            "friend_username": friend_username
        }
        await self.websocket.send(json.dumps(message))
        print(f"Sent friend request to username:{friend_username}")

    async def accept_friend_request(self, friend_username: str):
        self.ensure_connected()
        message = {
            "type": "accept_friend_request",
            "friend_username": friend_username
        }
        await self.websocket.send(json.dumps(message))
        print(f"Accepted friend request from {friend_username}")

    async def decline_friend_request(self, friend_username: str):
        self.ensure_connected()
        message = {
            "type": "decline_friend_request",
            "friend_username": friend_username
        }
        await self.websocket.send(json.dumps(message))
        print(f"Declined friend request from {friend_username}")

    async def get_friends_list(self):
        self.ensure_connected()
        message = {"type": "get_friends_list"}
        await self.websocket.send(json.dumps(message))
        print("Requested friends list")

    async def get_friend_requests(self):
        self.ensure_connected()
        message = {"type": "get_friend_requests"}
        await self.websocket.send(json.dumps(message))
        print("Requested friend requests list")

    async def remove_friend(self, friend_username: str):
        self.ensure_connected()
        message = {
            "type": "remove_friend",
            "friend_username": friend_username
        }
        await self.websocket.send(json.dumps(message))
        print(f"Removed friend {friend_username}")

    async def disconnect(self):
        if self.websocket:
            await self.websocket.close()


    def isConnected(self) -> bool:
        if self.websocket:
            return True
        return False

    """ Throws an exception if you are not connected, should be used with care outside of async context 
            see IsConnected instead for function to use safely without catching exceptions"""
    def ensure_connected(self):
        if self.websocket is None:
            raise ValueError("Not connected to server")
