#!/usr/bin/env python3
import asyncio
import websockets
import json
import logging
import ssl
import hashlib
import base64
import os
import secrets
import sys
import time
import ipaddress
import threading
import argparse
from datetime import datetime, timedelta
from typing import Dict, Set, Optional, Tuple, Any, List
from dataclasses import dataclass, asdict
from pathlib import Path
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
from concurrent.futures import ThreadPoolExecutor
from database_manager import DatabaseManager

# Import debug terminal logger
try:
    from debug_terminal import setup_debug_logging, DebugTerminalLogger
    HAS_DEBUG_TERMINAL = True
except ImportError:
    HAS_DEBUG_TERMINAL = False
    setup_debug_logging = lambda x: None
    DebugTerminalLogger = None

# Try to import prompt_toolkit for better console, fall back to input
try:
    from prompt_toolkit import prompt
    from prompt_toolkit.completion import WordCompleter
    from prompt_toolkit.history import InMemoryHistory
    HAS_PROMPT_TOOLKIT = True
except ImportError:
    HAS_PROMPT_TOOLKIT = False
    def prompt(message: str = "", **kwargs) -> str:
        return input(message)

# Additional imports for secure operations
from concurrent.futures import ThreadPoolExecutor
from database_manager import DatabaseManager

# Set up logging
LOG_DIR = Path("logs")
LOG_DIR.mkdir(exist_ok=True)
LOG_FILE = LOG_DIR / f"server_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
CONFIG_FILE = "data/server_config.json"
DATABASE_FILE = "data/server_database.db"
SERVER_CERTFILE = "data/server.crt"
SERVER_KEYFILE = "data/server.key"

# Create logger
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)    

# File handler
file_handler = logging.FileHandler(LOG_FILE)
file_handler.setLevel(logging.DEBUG)
file_handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - [%(levelname)s] %(message)s'))
logger.addHandler(file_handler)

# Console handler for normal output
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
console_handler.setFormatter(logging.Formatter('%(levelname)s: %(message)s'))
logger.addHandler(console_handler)

# Prevent logs from propagating to the root logger (keeps console clean)
logger.propagate = False

# Setup debug terminal if requested
if os.environ.get("DEBUG_TERMINAL") == "true":
    try:
        from debug_logger import setup_debug_logging
        debug_handler = setup_debug_logging("server", terminal="auto", level=logging.DEBUG)
        logger.info("🐛 Debug terminal enabled")
    except ImportError:
        logger.info("⚠️  Debug terminal not available (debug_logger.py not found)")
    except Exception as e:
        logger.info(f"⚠️  Failed to setup debug terminal: {e}")


@dataclass
class User:
    """Represents a connected user"""
    user_id: int  # Database ID
    username: str
    websocket: Any  # websockets connection object
    public_key: Optional[str] = None
    last_active: float = 0
    room: Optional[str] = None
    authenticated: bool = False
    next_ping_time: float = 0  # <-- Add this line
    elapsed_time_since_last_pong: float = 0
    
@dataclass
class Message:
    """Represents a message in the chat system"""
    sender: str
    recipient: Optional[str]  # None for public messages
    content: str
    timestamp: float
    message_type: str  # 'public', 'private', 'system'
    encrypted: bool = False
    signature: Optional[str] = None

@dataclass
class Room:
    """Represents a chat room"""
    name: str
    users: Set[str]
    created_at: float
    is_private: bool = False
    admin: Optional[str] = None
    
    
debugMode: bool = True 
# Timeout configuration moved to SecureChatServer class instance variables
# nextPingTimeout: int = 30   #How many seconds between server sends ping requests
# MaxTimeoutPingRespondPong: int = 40 #how many seconds to wait for a pong, until finally give up and disconnect user.

class SecureChatServer:

    missed_pings = 0
    
    """Main chat server class with encryption support"""
    def __init__(self, host: str = "0.0.0.0", port: int = 8100, use_ssl: bool = True, cert_file: str = None, key_file: str = None, ping_interval: int = 30, ping_timeout: int = 40, enable_debug_terminal: bool = False):

        self.lastSentPingChecksum = time.time()
        self.thisPongTimeStamp = time.time()
        self.host = host
        self.port = port
        self.use_ssl = use_ssl
        self.cert_file = cert_file or "server.crt"
        self.key_file = key_file or "server.key"
        self.ping_interval = ping_interval  # Time between PING messages
        self.ping_timeout = ping_timeout    # Max time to wait for PONG response
        self.connected_users: Dict[str, User] = {}
        self.rooms: Dict[str, Room] = {}
        self.message_history: List[Message] = []
        self.server_private_key = None
        self.server_public_key = None
        self.executor = ThreadPoolExecutor(max_workers=10)
        self.db_manager = DatabaseManager()
        self.message_counter = 0  # Add this line for message tracking
        
        # Debug terminal logger
        self.debug_logger: Optional[DebugTerminalLogger] = None
        if enable_debug_terminal and HAS_DEBUG_TERMINAL:
            self.debug_logger = setup_debug_logging(True)
        
        # Create default public room
        self.rooms["general"] = Room(
            name="general",
            users=set(),
            created_at=time.time(),
            is_private=False
        )
        
        # Initialize server keys
        self._generate_server_keys()
        
        # Initialize SSL if enabled
        if self.use_ssl:
            self._ensure_ssl_certificates()
    
    def _debug_log(self, message: str, level: str = "DEBUG"):
        """Send message to debug terminal if available"""
        if self.debug_logger:
            if level.upper() == "DEBUG":
                self.debug_logger.debug(message, "SERVER")
            elif level.upper() == "INFO":
                self.debug_logger.info(message, "SERVER")
            elif level.upper() == "WARNING":
                self.debug_logger.warning(message, "SERVER")
            elif level.upper() == "ERROR":
                self.debug_logger.error(message, "SERVER")
            elif level.upper() == "CRITICAL":
                self.debug_logger.critical(message, "SERVER")
        
        # Also send to regular logger
        logger_method = getattr(logger, level.lower(), logger.debug)
        logger_method(message)
    
    def _ensure_ssl_certificates(self):
        """Ensure SSL certificates exist, generate self-signed if needed"""
        import os
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
        import ipaddress
        
        if not os.path.exists(self.cert_file) or not os.path.exists(self.key_file):
            logger.info(f"[SSL] Generating self-signed certificate...")
            
            # Generate private key for SSL
            ssl_private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )
            
            # Create certificate
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "CA"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureMessaging"),
                x509.NameAttribute(NameOID.COMMON_NAME, self.host),
            ])
            
            cert = x509.CertificateBuilder().subject_name(
                subject
            ).issuer_name(
                issuer
            ).public_key(
                ssl_private_key.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.utcnow()
            ).not_valid_after(
                datetime.utcnow() + timedelta(days=365)
            ).add_extension(
                x509.SubjectAlternativeName([
                    x509.DNSName(self.host),
                    x509.DNSName("localhost"),
                    x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
                    x509.IPAddress(ipaddress.IPv4Address(self.host)) if self.host != "0.0.0.0" else x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
                ]),
                critical=False,
            ).sign(ssl_private_key, hashes.SHA256(), default_backend())
            
            # Save certificate
            with open(self.cert_file, "wb") as f:
                f.write(cert.public_bytes(Encoding.PEM))
            
            # Save private key
            with open(self.key_file, "wb") as f:
                f.write(ssl_private_key.private_bytes(
                    encoding=Encoding.PEM,
                    format=PrivateFormat.PKCS8,
                    encryption_algorithm=NoEncryption()
                ))
            
            logger.info(f"[SSL] Generated certificate: {self.cert_file}")
            logger.info(f"[SSL] Generated private key: {self.key_file}")
        else:
            logger.info(f"[SSL] Using existing certificate: {self.cert_file}")
    
    def _generate_server_keys(self):
        """Generate RSA key pair for the server"""
        try:
            self.server_private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )
            self.server_public_key = self.server_private_key.public_key()
            logger.info("Server RSA keys generated successfully")
        except Exception as e:
            logger.error(f"Failed to generate server keys: {e}")
            raise
    
    async def start_server(self):
        """Start the websocket server"""
        logger.info(f"Starting secure chat server on {self.host}:{self.port}")
        logger.info(f"[DEBUG] Starting secure chat server on {self.host}:{self.port}")
        
        # Initialize database
        await self.db_manager.initialize()
        logger.info("[DEBUG] Database initialized")
        
        # Create SSL context if SSL is enabled
        ssl_context = None
        if self.use_ssl:
            ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            ssl_context.load_cert_chain(self.cert_file, self.key_file)
            logger.info(f"[SSL] SSL context created using {self.cert_file}")
        else:
            logger.info("[SSL] SSL disabled - using plain WebSocket connections")
        
        async def safe_handle_client(websocket, path=None):
            try:
                await self.handle_client(websocket, path)
            except websockets.exceptions.ConnectionClosedOK:
                logger.info("Client connection closed normally")
            except websockets.exceptions.ConnectionClosedError as e:
                logger.warning(f"Client connection closed with error: {e}")
            except Exception as e:
                logger.error(f"Error handling client: {str(e)}")

        logger.info("[DEBUG] About to start websockets.serve")
        try:
            # Use SSL context if available
            if ssl_context:
                logger.info(f"[SSL] Starting secure WebSocket server (wss://) on {self.host}:{self.port}")
                server = await websockets.serve(
                    safe_handle_client,
                    self.host,
                    self.port,
                    ssl=ssl_context,
                    ping_interval=None,  # Disable built-in WebSocket PING/PONG
                    ping_timeout=None    # Use our custom protocol instead
                )
            else:
                logger.info(f"[PLAIN] Starting plain WebSocket server (ws://) on {self.host}:{self.port}")
                server = await websockets.serve(
                    safe_handle_client,
                    self.host,
                    self.port,
                    ping_interval=None,  # Disable built-in WebSocket PING/PONG
                    ping_timeout=None    # Use our custom protocol instead
                )
            logger.info("[DEBUG] websockets.serve started")
            logger.info("[DEBUG] WebSocket built-in PING/PONG disabled - using custom protocol")
        except Exception as e:
            logger.error(f"Failed to start websocket server: {e}")
            return

        # Start the keepalive ping task
        asyncio.create_task(self.ping_keepalive_task())
        logger.info(f"Server started successfully on {self.host}:{self.port}")
        await asyncio.Future()  # Run forever

    #Connection handling and keep alive PING PONG
    async def handle_client(self, websocket: Any, path: str = None):
        """Handle new client connections"""
        client_ip = websocket.remote_address[0]
        client_port = websocket.remote_address[1]
        #if len(websocket.remote_address) > 1 else None
        logger.info(f"[DEBUG][CONNECT] New connection from {client_ip}")
        self._debug_log(f"New client connection from {client_ip}:{client_port}", "INFO")
        try:
            # Send server public key to client
            await self.send_server_info(websocket)

            # Handle client messages
            msg_counter = 0
            async for message in websocket:
                msg_counter += 1
                msg_id = f"MSG_{msg_counter:04d}"
                port_info = f":{client_port}" if client_port is not None else ""
                self._debug_log(f"Processing message {msg_id} from {client_ip}{port_info}", "DEBUG")
                await self.parse_recieved_message(websocket, message)
        except websockets.exceptions.ConnectionClosed:
            logger.error(f"[DEBUG][DISCONNECT] Client {client_ip} disconnected")
            self._debug_log(f"Client {client_ip} disconnected normally", "INFO")
        except Exception as e:
            logger.error(f"[ERROR][HANDLE_CLIENT] Error handling client {client_ip}: {str(e)}")
        finally:
            await self.handle_disconnect(websocket)
    async def send_server_info(self, websocket: Any):
        """Send server information and public key to client"""
        if self.server_public_key is None:
            raise ValueError("Server public key not initialized")
            
        server_public_key_pem = self.server_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
        
        server_info: Dict[str, Any] = {
            "type": "server_info",
            "server_version": "1.0.0",
            "server_public_key": server_public_key_pem,
            "server_time": time.time(),
            "supported_features": [
                "public_chat",
                "private_messaging",
                "end_to_end_encryption",
                "digital_signatures",
                "file_sharing"
            ],
            "max_message_length": 4096,
            "server_version": "1.0.0"
        }
        

        await self._send_wrapper(websocket, json.dumps(server_info))
    async def parse_recieved_message(self, websocket: Any, raw_message: str):
        """Process incoming messages from clients"""
        try:
            logger.debug(f"RECV raw_message: {raw_message}")
            
            message_data: Dict[str, Any] = json.loads(raw_message)
            message_type = message_data.get("type")
            
            if message_type == "register":
                await self.handle_registration(websocket, message_data)
            elif message_type == "login":
                await self.handle_login(websocket, message_data)
            elif message_type == "public_message":
                await self.handle_public_message(websocket, message_data)
            elif message_type == "private_message":
                await self.handle_private_message(websocket, message_data)
            elif message_type == "join_room":
                await self.handle_join_room(websocket, message_data)
            elif message_type == "leave_room":
                await self.handle_leave_room(websocket, message_data)
            elif message_type == "get_users":
                await self.handle_get_users(websocket)
            elif message_type == "get_unread_messages":
                await self.handle_get_unread_messages(websocket)
            elif message_type == "mark_message_read":
                await self.handle_mark_message_read(websocket, message_data)
            elif message_type == "send_friend_request":
                await self.handle_send_friend_request(websocket, message_data)
            elif message_type == "accept_friend_request":
                await self.handle_accept_friend_request(websocket, message_data)
            elif message_type == "decline_friend_request":
                await self.handle_decline_friend_request(websocket, message_data)
            elif message_type == "remove_friend":
                await self.handle_remove_friend(websocket, message_data)
            elif message_type == "get_friends_list":
                await self.handle_get_friends_list(websocket)
            elif message_type == "get_friend_requests":
                await self.handle_add_friend_requests(websocket)
            elif message_type == "PONG":
                await self.handle_pong(websocket, message_data)
            else:
                logger.info ("UNKNOWN MESSAGE TYPE SENT FROM CLEINT type: " + message_type.get("type") + " username: " + message_type.get("username"))
        except json.JSONDecodeError:
            await self.send_error(websocket, "Invalid JSON format")
        except Exception as e:
            logger.error(f"Error processing message: {e}")
            await self.send_error(websocket, f"Internal server error {e}")
    async def handle_pong(self, websocket, message_data: Dict[str, Any]):
        """Handle PONG messages from clients"""
        username = None
        user = None  # Define user here
        
        for uname, connected_user in self.connected_users.items():
            if connected_user.websocket == websocket:
                username = uname
                user = connected_user  # Store the user object
                user.last_active = time.time()
                break

        if not username or not user:  # Check both username and user
            logger.error("[DEBUG][PONG][WARN] Received PONG from unknown websocket")
            return

        if message_data.get("type", "").upper() == "PONG":
            pong_timestamp = message_data.get("timestamp")
            last_ping = getattr(user, 'last_ping_timestamp', None)
            time_from_ping_to_pong = time.time() - user.elapsed_time_since_last_pong
            
            # Check if response is within timeout
            if ((username == user.username) and 
                (time_from_ping_to_pong < self.ping_timeout) and 
                (user.elapsed_time_since_last_pong > 0.1)):  # Just make sure this condition is met as well
                
                if user is not None:
                    user.next_ping_time = time.time() + self.ping_interval
            
            if((last_ping > 1) and 
                (time_from_ping_to_pong < self.ping_timeout) and 
                (abs(pong_timestamp - last_ping) < 1e-6) and
                (last_ping is not None )):
                    user.elapsed_time_since_last_pong = time.time()
                    user.next_ping_time = time.time() + self.ping_interval
                    
                    time_until_next_ping = time.time() - user.next_ping_time
                    #logger.debug(f"[DEBUG][PONG] VALID PONG Recieved from {username}. Next ping will be sent in: {time_until_next_ping} seconds.")
            else:
                logger.error(f"[DEBUG][PONG][INVALID] Received invalid PONG from {username} (timestamp: {pong_timestamp}, expected: {last_ping})")
    async def send_ping(self, websocket, username):
        """Send a PING to the client and record the timestamp for validation."""
        self.missed_pings = self.missed_pings + 1
        time_stamp = time.time()
        ping_message = {
            "type": "PING",
            "username": username,
            "timestamp": time_stamp
        }

        user = self.connected_users.get(username)
        if user:
            user.last_ping_timestamp = time_stamp
            user.next_ping_time = time_stamp + self.ping_interval
            user.elapsed_time_since_last_pong = time.time()

        await self._send_wrapper(websocket, json.dumps(ping_message))
    async def ping_keepalive_task(self):
        """Periodically check for pong timeout and send pings as per the protocol."""
        while True:
            num_users = len(self.connected_users)
            if num_users == 0:
                #logger.info("[DEBUG] No connected users, skipping ping check")
                await asyncio.sleep(1)
                continue
            
            now = time.time()
            usersocket = None
            for username, user in list(self.connected_users.items()):
                usersocket = user.websocket
                if now - user.elapsed_time_since_last_pong > self.ping_timeout:
                    logger.info(f"[DEBUG] User {username} timed out (no pong). Disconnecting.")
                    await user.websocket.close()
                    self.connected_users.pop(username, None)  # Fixed: use self.connected_users
                    continue
                
                next_ping = getattr(user, 'next_ping_time', 0)
                if now >= next_ping:
                    await self.send_ping(usersocket, username)
                    
    #login, registration etc
    async def disconnectUser(self, username: str):
        """Disconnect a user by username"""
        user = self.connected_users.get(username)
        if user:
            await user.websocket.close()
            del self.connected_users[username]
            logger.info(f"User {username} disconnected")
        else:
            logger.warning(f"Attempted to disconnect non-existent user: {username}")
    async def handle_registration(self, websocket: Any, message_data: Dict[str, Any]):
        """Handle user registration with password"""
        username: Optional[str] = message_data.get("username")
        password: Optional[str] = message_data.get("password")
        public_key_pem: Optional[str] = message_data.get(SERVER_KEYFILE)
        
        self._debug_log(f"Registration attempt for user: {username}", "INFO")
        
        if not username or not password or not public_key_pem:
            self._debug_log(f"Registration failed - missing data for user: {username}", "WARNING")
            await self.send_error(websocket, "Username, password, and public key required")
            return
        
        # Register user in database
        if asyncio.iscoroutinefunction(self.db_manager.register_user):
            success, message = await self.db_manager.register_user(username, password, public_key_pem)
        else:
            loop = asyncio.get_running_loop()
            success, message = await loop.run_in_executor(
                self.executor, self.db_manager.register_user, username, password, public_key_pem
            )
        
        if success:
            # Auto-login the user after successful registration
            if asyncio.iscoroutinefunction(self.db_manager.authenticate_user):
                authenticated, user_data = await self.db_manager.authenticate_user(username, password)
            else:
                loop = asyncio.get_running_loop()
                authenticated, user_data = await loop.run_in_executor(
                    self.executor, self.db_manager.authenticate_user, username, password
                )
            
            if authenticated and user_data:
                # Create user session
                user = User(
                    user_id=user_data['id'],
                    username=username,
                    websocket=websocket,
                    public_key=public_key_pem,
                    last_active=time.time(),
                    room="general",
                    authenticated=True
                )
                
                self.connected_users[username] = user
                self.rooms["general"].users.add(username)
                
                #
                # Get user stats
                #if asyncio.iscoroutinefunction(self.db_manager.get_user_stats):
                #    user_stats = await self.db_manager.get_user_stats(user_data['id'])
                #else:
                #    loop = asyncio.get_running_loop()
                #    user_stats = await loop.run_in_executor(
                #        self.executor, self.db_manager.get_user_stats, user_data['id']
                #    )
                
                response: Dict[str, Any]  = {
                    "type": "registration_success",
                    "username": username,
                    "user_id": user_data['id'],
                    "assigned_room": "general",
                    "user_stats": "",
                    "message": message
                }
                await websocket.send(json.dumps(response))
                
                logger.info(f"User {username} registered and logged in successfully")
            else:
                await self.send_error(websocket, "Registration succeeded but auto-login failed")
        else:
            await self.send_error(websocket, message)
    async def handle_login(self, websocket: Any, message_data: Dict[str, Any]):
        """Handle user login/authentication"""
        username: Optional[str] = message_data.get("username")
        password: Optional[str] = message_data.get("password")
        
        if not username or not password:
            await self.send_error(websocket, "Username and password required")
            return
        
        # Authenticate user
        if asyncio.iscoroutinefunction(self.db_manager.authenticate_user):
            authenticated, user_data = await self.db_manager.authenticate_user(username, password)
        else:
            loop = asyncio.get_running_loop()
            authenticated, user_data = await loop.run_in_executor(
                self.executor, self.db_manager.authenticate_user, username, password
            )
        
        if not authenticated or not user_data:
            await self.send_error(websocket, "Invalid username or password")
            return
        
        # Check if user is already connected
        if username in self.connected_users:
            await self.send_error(websocket, "User already logged in")
            return
        
        # Create user session
        user = User(
            user_id=user_data['id'],
            username=username,
            websocket=websocket,
            public_key=user_data['public_key'],
            last_active=time.time(),
            room="general",
            authenticated=True
        )
        
        self.connected_users[username] = user
        self.rooms["general"].users.add(username)
         
        # Send login success response
        response: Dict[str, Any]  = {
            "type": "login_success",
            "username": username,
            "user_id": user_data['id'],
            "assigned_room": "general",
            "user_stats": "user_stats_placeholder",  # Placeholder for user stats
            "unread_message_count": 0 # len(unread_messages)
        }
        await websocket.send(json.dumps(response))
        
        # Only schedule the send_ping task (do not send a manual PING here)
        send_ping_task = asyncio.create_task(self.send_ping(websocket, username))

        
        logger.info(f"User {username} logged in successfully")
    async def handle_disconnect(self, websocket: Any):
        """Handle user disconnection"""
        # Find and remove the user
        username_to_remove: Optional[str] = None
        for username, user in self.connected_users.items():
            if user.websocket == websocket:
                username_to_remove = username
                break
        
        if username_to_remove:
            user = self.connected_users[username_to_remove]
            room_name = user.room
            
            # Remove from room and connected users
            if room_name and room_name in self.rooms:
                self.rooms[room_name].users.discard(username_to_remove)
            
            del self.connected_users[username_to_remove]
            
            # Notify other users
            if room_name:
                await self.broadcast_to_room(room_name, {
                    "type": "user_left",
                    "username": username_to_remove,
                    "timestamp": time.time()
                })
            
            logger.info(f"User {username_to_remove} disconnected")
    async def send_error(self, websocket: Any, error_message: str):
        """Send error message to client"""
        error_response: Dict[str, Any] = {
            "type": "error",
            "message": error_message,
            "timestamp": time.time()
        }
        try:
            await websocket.send(json.dumps(error_response))
        except websockets.exceptions.ConnectionClosed:
            pass
    async def broadcast_to_room(self, room_name: str, message: Dict[str, Any], exclude_user: Optional[str] = None):
        """Broadcast message to all users in a room"""
        if room_name not in self.rooms:
            return
        
        room = self.rooms[room_name]
        message_json = json.dumps(message)
        
        for username in room.users:
            if username == exclude_user:
                continue
            
            user = self.connected_users.get(username)
            if user:
                try:
                    await user.websocket.send(message_json)
                except websockets.exceptions.ConnectionClosed:
                    # Handle disconnected users
                    pass

    #Messaging
    async def handle_public_message(self, websocket: Any, message_data: Dict[str, Any]):
        """Handle public messages"""
        # Find the sender
        user: Optional[User] = None
        for username, connected_user in self.connected_users.items():
            if connected_user.websocket == websocket:
                user = connected_user
                break
        
        if not user or not user.authenticated:
            await self.send_error(websocket, "User not authenticated")
            return
        
        content: str = message_data.get("content", "")
        if not content.strip():
            await self.send_error(websocket, "Message content cannot be empty")
            return
        
        room_name = user.room
        if not room_name or room_name not in self.rooms:
            await self.send_error(websocket, "User not in a valid room")
            return
        
        # Store message in database
        await self.db_manager.store_message(
            sender_id=user.user_id,
            recipient_id=None,
            room_name=room_name,
            content=content,
            message_type="public",
            encrypted=False
        )
        
        # Create and store message in memory
        message = Message(
            sender=user.username,
            recipient=None,
            content=content,
            timestamp=time.time(),
            message_type="public",
            encrypted=False
        )
        self.message_history.append(message)
        
        # Broadcast to room
        broadcast_message = {
            "type": "public_message",
            "sender": user.username,
            "content": content,
            "timestamp": message.timestamp,
            "room": room_name
        }
        
        await self.broadcast_to_room(room_name, broadcast_message)
        logger.info(f"Public message from {user.username} in room {room_name}")
    async def handle_private_message(self, websocket: Any, message_data: Dict[str, Any]):
        """Handle private messages"""
        # Find the sender
        sender_user: Optional[User] = None
        for username, connected_user in self.connected_users.items():
            if connected_user.websocket == websocket:
                sender_user = connected_user
                break
        
   
        if not sender_user or not sender_user.authenticated:
            
            await self.send_error(websocket, "User not authenticated")
            return
        
        recipient_username: Optional[str] = message_data.get("recipient")
        content: str = message_data.get("content", "")
        encrypted: bool = message_data.get("encrypted", False)
        signature: Optional[str] = message_data.get("signature")
        
        if not recipient_username or not content:
            await self.send_error(websocket, "Recipient and content required")
            return

        
        # Get recipient info from database
        recipient_data = await self.db_manager.get_user_by_username(recipient_username)
        if not recipient_data:
            await self.send_error(websocket, f"User {recipient_username} not found")
            return

        # Check if sender and recipient are friends
        # Check if recipient has sender in their friend list and status is accepted
        are_friends = False
        if hasattr(self.db_manager, 'are_friends'):
            are_friends = await self.db_manager.are_friends(recipient_data['id'], sender_user.user_id)
        else:
            # Fallback: check friends table directly if method not present
            query = "SELECT status FROM friends WHERE user_id = ? AND friend_id = ?"
            cursor = await self.db_manager.db.execute(query, (recipient_data['id'], sender_user.user_id))
            row = await cursor.fetchone()
            if row and row[0] == 'accepted':
                are_friends = True
        if not are_friends:
            await self.send_error(websocket, f"You can only send messages to users who have you in their friend list (accepted)")
            return
        
        
        # Store message in database
        await self.db_manager.store_message(
            sender_id=sender_user.user_id,
            recipient_id=recipient_data['id'],
            room_name=None,
            content=content,
            message_type="private",
            encrypted=encrypted,
            signature=signature,
            auto_delete_hours=recipient_data['auto_delete_hours']
        )
        
        # Create and store message in memory
        message = Message(
            sender=sender_user.username,
            recipient=recipient_username,
            content=content,
            timestamp=time.time(),
            message_type="private",
            encrypted=encrypted,
            signature=signature
        )
        self.message_history.append(message)
        
        
        # Send to recipient if online
        if recipient_username in self.connected_users:
            recipient_user = self.connected_users[recipient_username]
            private_message = {
                "type": "private_message",
                "sender": sender_user.username,
                "content": content,
                "encrypted": encrypted,
                "signature": signature,
                "timestamp": message.timestamp
            }
            
            try:
                await recipient_user.websocket.send(json.dumps(private_message))
            except websockets.exceptions.ConnectionClosed:
                pass  # Message stored in DB, will be delivered when user comes online
        
        # Send confirmation to sender
        confirmation = {
            "type": "message_delivered",
            "recipient": recipient_username,
            "online": recipient_username in self.connected_users,
            "timestamp": message.timestamp
        }
        await websocket.send(json.dumps(confirmation))
        
        logger.info(f"Private message from {sender_user.username} to {recipient_username}")
    
    async def handle_join_room(self, websocket: Any, message_data: Dict[str, Any]):
        """Handle room join requests"""
        # Find the sender
        sender_username = None
        for username, user in self.connected_users.items():
            if user.websocket == websocket:
                sender_username = username
                break
        
        if not sender_username:
            await self.send_error(websocket, "User not registered")
            return
        
        room_name = message_data.get("room_name")
        if not room_name:
            await self.send_error(websocket, "Room name required")
            return
        
        user = self.connected_users[sender_username]
        old_room = user.room
        
        # Remove from old room
        if old_room and old_room in self.rooms:
            self.rooms[old_room].users.discard(sender_username)
            await self.broadcast_to_room(old_room, {
                "type": "user_left",
                "username": sender_username,
                "timestamp": time.time()
            })
        
        # Create room if it doesn't exist
        if room_name not in self.rooms:
            self.rooms[room_name] = Room(
                name=room_name,
                users=set(),
                created_at=time.time(),
                is_private=False
            )
        
        # Add to new room
        self.rooms[room_name].users.add(sender_username)
        user.room = room_name
        
        # Send confirmation
        response = {
            "type": "room_joined",
            "room_name": room_name,
            "timestamp": time.time()
        }
        await websocket.send(json.dumps(response))
        
        # Notify other users in the room
        await self.broadcast_to_room(room_name, {
            "type": "user_joined",
            "username": sender_username,
            "timestamp": time.time()
        }, exclude_user=sender_username)
        
        logger.info(f"User {sender_username} joined room {room_name}")
    async def handle_leave_room(self, websocket: Any, message_data: Dict[str, Any]):
        """Handle room leave requests"""
        # Find the sender
        sender_username = None
        for username, user in self.connected_users.items():
            if user.websocket == websocket:
                sender_username = username
                break
        
        if not sender_username:
            await self.send_error(websocket, "User not registered")
            return
        
        user = self.connected_users[sender_username]
        current_room = user.room
        
        if not current_room or current_room not in self.rooms:
            await self.send_error(websocket, "User not in a room")
            return
        
        # Remove from current room
        self.rooms[current_room].users.discard(sender_username)
        
        # Move to general room
        self.rooms["general"].users.add(sender_username)
        user.room = "general"
        
        # Send confirmation
        response = {
            "type": "room_left",
            "room_name": current_room,
            "new_room": "general",
            "timestamp": time.time()
        }
        await websocket.send(json.dumps(response))
        
        # Notify users in the old room
        await self.broadcast_to_room(current_room, {
            "type": "user_left",
            "username": sender_username,
            "timestamp": time.time()
        })
        
        # Notify users in the general room
        await self.broadcast_to_room("general", {
            "type": "user_joined",
            "username": sender_username,
            "timestamp": time.time()
        }, exclude_user=sender_username)
        
        logger.info(f"User {sender_username} left room {current_room}")
    async def handle_get_users(self, websocket):
        """Handle get users request"""
        # Find the sender
        sender_username = None
        for username, user in self.connected_users.items():
            if user.websocket == websocket:
                sender_username = username
                break
        
        if not sender_username:
            await self.send_error(websocket, "User not registered")
            return
        
        user = self.connected_users[sender_username]
        current_room = user.room
        
        if not current_room or current_room not in self.rooms:
            await self.send_error(websocket, "User not in a valid room")
            return
        
        # Get users in the current room
        room_users = list(self.rooms[current_room].users)
        
        response = {
            "type": "users_list",
            "room": current_room,
            "users": room_users,
            "user_count": len(room_users),
            "timestamp": time.time()
        }
        
        await websocket.send(json.dumps(response))
    async def handle_get_unread_messages(self, websocket):
        """Handle request for unread messages"""
        # Find the sender
        user = None
        for username, connected_user in self.connected_users.items():
            if connected_user.websocket == websocket:
                user = connected_user
                break
        
        if not user or not user.authenticated:
            await self.send_error(websocket, "User not authenticated")
            return
        
        # Get unread messages from database
        unread_messages = await self.db_manager.get_unread_messages(user.user_id)
        
        response = {
            "type": "unread_messages",
            "messages": unread_messages,
            "count": len(unread_messages),
            "timestamp": time.time()
        }
        
        await websocket.send(json.dumps(response))
    async def handle_mark_message_read(self, websocket, message_data):
        """Handle marking a message as read"""
        # Find the sender
        user = None
        for username, connected_user in self.connected_users.items():
            if connected_user.websocket == websocket:
                user = connected_user
                break
        
        if not user or not user.authenticated:
            await self.send_error(websocket, "User not authenticated")
            return
        
        message_id = message_data.get("message_id")
        if not message_id:
            await self.send_error(websocket, "Message ID required")
            return
        
        # Mark message as read in database
        success = await self.db_manager.mark_message_read(message_id, user.user_id)
        
        if success:
            response = {
                "type": "message_marked_read",
                "message_id": message_id,
                "timestamp": time.time()
            }
            await websocket.send(json.dumps(response))
        else:
            await self.send_error(websocket, "Failed to mark message as read")

    # Friend Management Handlers
    async def handle_send_friend_request(self, websocket: Any, message_data: Dict[str, Any]):
        """Handle sending friend requests"""
        sender_user = self._get_authenticated_user(websocket)
        if not sender_user:
            await self.send_error(websocket, f"You are not authenticated {sender_user}")
            return
        
        friend_username = message_data.get("friend_username")
        if not friend_username:
            await self.send_error(websocket, "Error adding friend, no username of friend supplied.")
            return
        
        success, message = await self.db_manager.send_friend_request(
            sender_user.user_id, friend_username
        )
        
        response = {
            "type": "friend_request_response",
            "success": success,
            "message": message,
            "friend_username": friend_username
        }
        
        await websocket.send(json.dumps(response))
    async def handle_accept_friend_request(self, websocket, message_data):
        """Handle accepting friend requests"""
        user = self._get_authenticated_user(websocket)
        if not user:
            await self.send_error(websocket, "User not authenticated")
            return
        
        friend_username = message_data.get("friend_username")
        if not friend_username:
            await self.send_error(websocket, "Friend username required")
            return
        
        success, message = await self.db_manager.accept_friend_request(
            user.user_id, friend_username
        )
        
        response = {
            "type": "friend_request_accept_response",
            "success": success,
            "message": message,
            "friend_username": friend_username
        }
        
        await websocket.send(json.dumps(response))
    async def handle_decline_friend_request(self, websocket: Any, message_data: Dict[str, Any]):
        """Handle declining friend requests"""
        user = self._get_authenticated_user(websocket) # type: ignore
        if not user:
            await self.send_error(websocket, "User not authenticated")
            return
        
        friend_username = message_data.get("friend_username")
        if not friend_username:
            await self.send_error(websocket, "Friend username required")
            return
        
        success, message = await self.db_manager.decline_friend_request(
            user.user_id, friend_username
        )
        
        response = {
            "type": "friend_request_decline_response",
            "success": success,
            "message": message,
            "friend_username": friend_username
        }
        
        await websocket.send(json.dumps(response))
    async def handle_remove_friend(self, websocket, message_data):
        """Handle removing friends"""
        user = self._get_authenticated_user(websocket)
        if not user:
            await self.send_error(websocket, "User not authenticated")
            return
        
        friend_username = message_data.get("friend_username")
        if not friend_username:
            await self.send_error(websocket, "Friend username required")
            return
        
        success, message = await self.db_manager.remove_friend(
            user.user_id, friend_username
        )
        
        response = {
            "type": "remove_friend_response",
            "success": success,
            "message": message,
            "friend_username": friend_username
        }
        
        await websocket.send(json.dumps(response))
    async def handle_get_friends_list(self, websocket):
        """Handle getting friends list"""
        user = self._get_authenticated_user(websocket)
        if(user is None):
            logger.info("[DEBUG] User not authenticated in handle_get_friends_list")
            await self.send_error(websocket, "User IS NOT authenticated")
            return
        if not user:
            await self.send_error(websocket, "User not authenticated")
            return
        
        friends = await self.db_manager.get_friends_list(user.user_id)
        
        response = {
            "type": "friends_list",
            "friends": friends
        }
        logger.debug(f"[DEBUG] Sending friends {json.dumps(response)}")
        await websocket.send(json.dumps(response))
    async def handle_get_friend_requests(self, websocket):
        """Send all friend requests adding him to user"""
        user = self._get_authenticated_user(websocket)
        if not user:
            await self.send_error(websocket, "User not authenticated")
            return
        
        requests = await self.db_manager.get_friend_requests(user.user_id)
        
        response = {
            "type": "friend_requests",
            "requests": requests
        }
        
        await websocket.send(json.dumps(response))


    def _get_authenticated_user(self, websocket) -> Optional[User]:
        """Get authenticated user from websocket connection"""
        for username, user in self.connected_users.items():
            if user.websocket == websocket and user.authenticated:
                return user
        return None

    async def _send_wrapper(self, websocket: Any, message: str) -> None:
        """Wrapper for websocket.send with logging and debug logger.info"""
        self.message_counter += 1
        msg_id = f"MSG_{self.message_counter:04d}"
        client_info = f"{websocket.remote_address[0]}:{websocket.remote_address[1]}"
        try:
            logger.debug(f"[{msg_id}] Sending to {client_info}: {message}")
            await websocket.send(message)
        except Exception as e:
            logger.error(f"[{msg_id}] Failed to send to {client_info}: {str(e)}")
            logger.info(f"[ERROR][SEND][{msg_id}] Failed to send to {client_info}: {str(e)}")
            raise

    async def _recv_wrapper(self, websocket: Any) -> str:
        try:
            message = await websocket.recv()
            client_info = f"{websocket.remote_address[0]}:{websocket.remote_address[1]}"
            logger.info(f"[DEBUG][RECV] From {client_info}: {message}")
            logger.debug(f"[{client_info}] Received: {message}")
            return message
        except Exception as e:
            logger.error(f"Error receiving message: {str(e)}")
            logger.info(f"[ERROR][RECV] Error receiving message from {client_info}: {str(e)}")
            raise

    async def _send_json_response(self, websocket: Any, data: Dict[str, Any]) -> None:
        try:
            message = json.dumps(data)
            await self._send_wrapper(websocket, message)
        except Exception as e:
            logger.error(f"Error sending JSON response: {str(e)}")

class ServerConsole:
    """Interactive server console with administrative commands"""
    
    def __init__(self, server: SecureChatServer):
        self.server = server
        self.running = False
        self.history = InMemoryHistory() if HAS_PROMPT_TOOLKIT else None
        
        # Define available commands
        self.commands = {
            'help': self.cmd_help,
            'status': self.cmd_status,
            'users': self.cmd_users,
            'kick': self.cmd_kick,
            'ban': self.cmd_ban,
            'unban': self.cmd_unban,
            'broadcast': self.cmd_broadcast,
            'rooms': self.cmd_rooms,
            'logs': self.cmd_logs,
            'stats': self.cmd_stats,
            'db': self.cmd_database,
            'debug': self.cmd_debug,
            'ssl': self.cmd_ssl,
            'config': self.cmd_config,
            'shutdown': self.cmd_shutdown,
            'restart': self.cmd_restart,
            'backup': self.cmd_backup,
            'clear': self.cmd_clear,
            'ping': self.cmd_ping,
            'message': self.cmd_send_message,
            'user': self.cmd_user_info,
            'export': self.cmd_export,
            'import': self.cmd_import
        }
        
        if HAS_PROMPT_TOOLKIT:
            self.completer = WordCompleter(list(self.commands.keys()))
        else:
            self.completer = None
    def _parse_json_args(self, args: List[str]) -> Tuple[List[str], Optional[Dict]]:
        """Parse command arguments and extract JSON object if present"""
        json_data = None
        command_args = []
        
        # Join all args and look for JSON object
        full_arg_string = " ".join(args)
        
        # Find JSON object in braces
        brace_start = full_arg_string.find('{')
        if brace_start != -1:
            # Extract everything before the JSON as command args
            before_json = full_arg_string[:brace_start].strip()
            if before_json:
                command_args = before_json.split()
            
            # Extract and parse JSON
            json_string = full_arg_string[brace_start:].strip()
            try:
                json_data = json.loads(json_string)
            except json.JSONDecodeError as e:
                logger.info(f"❌ Invalid JSON format: {e}")
                return command_args, None
        else:
            command_args = args
        
        return command_args, json_data
    
    async def start(self):
        """Start the interactive console"""
        self.running = True
        logger.info("🖥️  Server Console Started")
        logger.info("Type 'help' for available commands")
        logger.info("-" * 50)
        
        while self.running:
            try:
                if HAS_PROMPT_TOOLKIT:
                    command = await asyncio.to_thread(
                        prompt, 
                        "server> ", 
                        completer=self.completer,
                        history=self.history
                    )
                else:
                    command = await asyncio.to_thread(input, "server> ")
                
                command = command.strip()
                if not command:
                    continue
                
                await self.process_command(command)
                
            except (EOFError, KeyboardInterrupt):
                break
            except Exception as e:
                logger.info(f"❌ Console error: {e}")
        
        logger.info("👋 Server console stopped")
    
    async def process_command(self, command: str):
        """Process a console command"""
        parts = command.split()
        if not parts:
            return
        
        cmd = parts[0].lower()
        args = parts[1:]
        
        if cmd in self.commands:
            try:
                await self.commands[cmd](args)
            except Exception as e:
                logger.info(f"❌ Command error: {e}")
        else:
            logger.info(f"❌ Unknown command: {cmd}. Type 'help' for available commands.")
    
    async def cmd_help(self, args):
        """Show help information"""
        if args and args[0] in self.commands:
            # Show specific command help
            cmd = args[0]
            help_text = {
                'status': 'Show server status and statistics',
                'users': 'List connected users [online|all|<username>]',
                'kick': 'Kick a user: kick <username> [reason]',
                'ban': 'Ban a user: ban <username> [duration] [reason]',
                'unban': 'Unban a user: unban <username>',
                'broadcast': 'Broadcast message: broadcast <message>',
                'rooms': 'List rooms or manage: rooms [list|create|delete] [name]',
                'logs': 'View logs: logs [lines|tail|grep] [pattern]',
                'stats': 'Show detailed statistics',
                'db': 'Database operations with JSON: db [dump|insert|update|delete|stats] [parameters] {"json": "data"}',
                'debug': 'Debug commands: debug [level|toggle|dump]',
                'ssl': 'SSL certificate info: ssl [info|regenerate]',
                'config': 'Configuration: config [show|reload|set] [key] [value]',
                'shutdown': 'Shutdown server gracefully',
                'restart': 'Restart server',
                'backup': 'Create system backup',
                'clear': 'Clear console screen',
                'ping': 'Send ping to user: ping <username>',
                'message': 'Send admin message: message <username> <text>',
                'user': 'User information: user <username>',
                'export': 'Export data: export [users|messages|logs] [format]',
                'import': 'Import data: import <file> [type]'
            }
            logger.info(f"📖 {cmd}: {help_text.get(cmd, 'No help available')}")
            
            # Special detailed help for database commands
            if cmd == 'db':
                logger.info("\n🗄️  Database Command Examples:")
                logger.info("   db dump table-struct                    # Show all table structures")
                logger.info("   db dump table users                     # Show all users")
                logger.info("   db dump table row users {\"id\": 1}        # Find specific user")
                logger.info("   db insert table users {\"username\": \"x\"}  # Insert new user")
                logger.info("   db update table users {\"active\": true} {\"WHERE_id\": 1}  # Update user")
                logger.info("   db delete table users {\"id\": 999}        # Delete user (with confirmation)")
                logger.info("   db stats                                # Database statistics")
                logger.info("\n   � See DATABASE_CONSOLE_EXAMPLES.md for detailed examples")
        else:
            # Show all commands
            logger.info("�📚 Available Commands:")
            logger.info("System:")
            logger.info("  status     - Server status and uptime")
            logger.info("  stats      - Detailed server statistics")
            logger.info("  config     - View/modify configuration")
            logger.info("  shutdown   - Gracefully shutdown server")
            logger.info("  restart    - Restart server")
            logger.info("  backup     - Create system backup")
            logger.info("  clear      - Clear console")
            logger.info()
            logger.info("Database Operations:")
            logger.info("  db         - Advanced database operations with JSON parameters")
            logger.info("             Examples: db dump table users")
            logger.info("                      db insert table users {\"username\": \"test\"}")
            logger.info("                      db update table users {\"active\": true} {\"WHERE_id\": 1}")
            logger.info("             Use 'help db' for detailed database help")
            logger.info()
            logger.info("User Management:")
            logger.info("  users      - List users")
            logger.info("  user       - Get user details")
            logger.info("  kick       - Kick a user")
            logger.info("  ban/unban  - Ban/unban users")
            logger.info("  ping       - Send ping to user")
            logger.info("  message    - Send admin message")
            logger.info()
            logger.info("System:")
            logger.info("  rooms      - Manage chat rooms")
            logger.info("  broadcast  - Send server message")
            logger.info("  logs       - View server logs")
            logger.info("  debug      - Debug commands")
            logger.info("  ssl        - SSL certificate management")
            logger.info("  export     - Export data")
            logger.info("  import     - Import data")
            logger.info()
            logger.info("Use 'help <command>' for detailed help")
            logger.info("📖 For database examples, see DATABASE_CONSOLE_EXAMPLES.md")
    
    async def cmd_status(self, args):
        """Show server status"""
        uptime = time.time() - getattr(self.server, 'start_time', time.time())
        hours, remainder = divmod(uptime, 3600)
        minutes, seconds = divmod(remainder, 60)
        
        logger.info("🖥️  Server Status:")
        logger.info(f"   Uptime: {int(hours)}h {int(minutes)}m {int(seconds)}s")
        logger.info(f"   Connected Users: {len(self.server.connected_users)}")
        logger.info(f"   Active Rooms: {len(self.server.rooms)}")
        logger.info(f"   SSL Enabled: {self.server.use_ssl}")
        logger.info(f"   Host: {self.server.host}:{self.server.port}")
        logger.info(f"   Ping Interval: {self.server.ping_interval}s")
        logger.info(f"   Ping Timeout: {self.server.ping_timeout}s")
    
    async def cmd_users(self, args):
        """List connected users"""
        if not args:
            # List all online users
            logger.info(f"👥 Connected Users ({len(self.server.connected_users)}):")
            for username, user in self.server.connected_users.items():
                room = user.room or "None"
                last_active = time.time() - user.last_active
                logger.info(f"   • {username} (Room: {room}, Last Active: {last_active:.1f}s ago)")
        elif args[0] == "all":
            # List all users from database
            logger.info("👥 All Registered Users:")
            # TODO: Implement database query for all users
            logger.info("   (Database query not implemented yet)")
        else:
            # Show specific user info
            username = args[0]
            if username in self.server.connected_users:
                user = self.server.connected_users[username]
                logger.info(f"👤 User: {username}")
                logger.info(f"   Status: Online")
                logger.info(f"   Room: {user.room}")
                logger.info(f"   User ID: {user.user_id}")
                logger.info(f"   Last Active: {time.time() - user.last_active:.1f}s ago")
                logger.info(f"   Authenticated: {user.authenticated}")
            else:
                logger.info(f"❌ User '{username}' not found online")
    
    async def cmd_kick(self, args):
        """Kick a user"""
        if not args:
            logger.info("❌ Usage: kick <username> [reason]")
            return
        
        username = args[0]
        reason = " ".join(args[1:]) if len(args) > 1 else "Kicked by administrator"
        
        if username in self.server.connected_users:
            user = self.server.connected_users[username]
            
            # Send kick message
            kick_msg = {
                "type": "admin_message",
                "message": f"You have been kicked from the server. Reason: {reason}",
                "action": "kick"
            }
            await user.websocket.send(json.dumps(kick_msg))
            
            # Disconnect user
            await user.websocket.close()
            del self.server.connected_users[username]
            
            logger.info(f"✅ Kicked user '{username}'. Reason: {reason}")
            logger.info(f"Admin kicked user {username}. Reason: {reason}")
        else:
            logger.info(f"❌ User '{username}' not found online")
    
    async def cmd_ban(self, args):
        """Ban a user"""
        if not args:
            logger.info("❌ Usage: ban <username> [duration] [reason]")
            return
        
        # TODO: Implement user banning with database storage
        username = args[0]
        logger.info(f"⚠️  Ban functionality not implemented yet for user: {username}")
    
    async def cmd_unban(self, args):
        """Unban a user"""
        if not args:
            logger.info("❌ Usage: unban <username>")
            return
        
        # TODO: Implement user unbanning
        username = args[0]
        logger.info(f"⚠️  Unban functionality not implemented yet for user: {username}")
    
    async def cmd_broadcast(self, args):
        """Broadcast message to all users"""
        if not args:
            logger.info("❌ Usage: broadcast <message>")
            return
        
        message = " ".join(args)
        broadcast_msg = {
            "type": "admin_broadcast",
            "message": message,
            "timestamp": time.time(),
            "sender": "Server Administrator"
        }
        
        sent_count = 0
        for username, user in self.server.connected_users.items():
            try:
                await user.websocket.send(json.dumps(broadcast_msg))
                sent_count += 1
            except:
                pass
        
        logger.info(f"📢 Broadcast sent to {sent_count} users: {message}")
        logger.info(f"Admin broadcast to {sent_count} users: {message}")
    
    async def cmd_rooms(self, args):
        """Manage chat rooms"""
        if not args or args[0] == "list":
            logger.info(f"🏠 Chat Rooms ({len(self.server.rooms)}):")
            for room_name, room in self.server.rooms.items():
                user_count = len(room.users)
                room_type = "Private" if room.is_private else "Public"
                logger.info(f"   • {room_name} ({room_type}, {user_count} users)")
        else:
            logger.info("⚠️  Room management not fully implemented yet")
    
    async def cmd_logs(self, args):
        """View server logs"""
        if not args:
            # Show recent log entries
            logger.info("📋 Recent Log Entries:")
            # TODO: Implement log viewing
            logger.info("   (Log viewing not implemented yet)")
        else:
            logger.info("⚠️  Advanced log viewing not implemented yet")
    
    async def cmd_stats(self, args):
        """Show detailed statistics"""
        logger.info("📊 Server Statistics:")
        logger.info(f"   Connected Users: {len(self.server.connected_users)}")
        logger.info(f"   Total Rooms: {len(self.server.rooms)}")
        logger.info(f"   Messages in Memory: {len(self.server.message_history)}")
        # TODO: Add more detailed stats from database
    
    async def cmd_database(self, args):
        """Database operations"""
        if not args:
            logger.info("❌ Usage: db [dump|stats|insert|update|delete] [parameters]")
            logger.info("🗄️  Examples:")
            logger.info("     db dump table-struct")
            logger.info("     db dump table users")
            logger.info("     db dump table row users {\"id\": 1}")
            logger.info("     db insert table users {\"username\": \"john\", \"password_hash\": \"hash\"}")
            logger.info("     db update table users {\"username\": \"jane\"} {\"WHERE_id\": 1}")
            logger.info("     db delete table users {\"id\": 1}")
            logger.info("     db stats")
            return
        
        operation = args[0].lower()
        
        if operation == "dump":
            await self._handle_db_dump(args[1:])
        elif operation == "insert":
            await self._handle_db_insert(args[1:])
        elif operation == "update":
            await self._handle_db_update(args[1:])
        elif operation == "delete":
            await self._handle_db_delete(args[1:])
        elif operation == "stats":
            await self._handle_db_stats()
        else:
            logger.info(f"❌ Unknown database operation: {operation}")
    
    async def _handle_db_dump(self, args):
        """Handle database dump operations"""
        if not args:
            logger.info("❌ Usage: db dump [table-struct|table] [table_name] [row] [WHERE_conditions]")
            return
        
        if args[0] == "table-struct":
            # Dump all table structures
            logger.info("🗄️  Database Table Structures:")
            tables = await self.server.db_manager.get_table_names()
            for table_name in tables:
                structure = await self.server.db_manager.get_table_structure(table_name)
                logger.info(f"\n📋 Table: {table_name}")
                logger.info("   Columns:")
                for col in structure:
                    pk_marker = " (PK)" if col['primary_key'] else ""
                    not_null = " NOT NULL" if col['not_null'] else ""
                    default = f" DEFAULT {col['default_value']}" if col['default_value'] else ""
                    logger.info(f"     {col['name']}: {col['type']}{pk_marker}{not_null}{default}")
        
        elif args[0] == "table":
            if len(args) < 2:
                logger.info("❌ Usage: db dump table <table_name> [row] [WHERE_conditions]")
                return
            
            table_name = args[1]
            
            # Check if this is a row-specific dump
            if len(args) > 2 and args[2] == "row":
                # Parse JSON conditions
                remaining_args = args[3:] if len(args) > 3 else []
                command_args, json_data = self._parse_json_args(remaining_args)
                
                if json_data:
                    # Find specific rows
                    rows = await self.server.db_manager.find_rows(table_name, json_data)
                    if rows:
                        logger.info(f"🗄️  Rows from {table_name} matching {json_data}:")
                        for i, row in enumerate(rows, 1):
                            logger.info(f"   Row {i}:")
                            for key, value in row.items():
                                logger.info(f"     {key}: {value}")
                            logger.info()
                    else:
                        logger.info(f"❌ No rows found in {table_name} matching {json_data}")
                else:
                    logger.info("❌ No WHERE conditions provided for row dump")
            else:
                # Dump entire table
                rows = await self.server.db_manager.dump_table(table_name)
                if rows:
                    logger.info(f"🗄️  Table: {table_name} ({len(rows)} rows)")
                    for i, row in enumerate(rows, 1):
                        logger.info(f"   Row {i}:")
                        for key, value in row.items():
                            logger.info(f"     {key}: {value}")
                        logger.info()
                else:
                    logger.info(f"❌ Table {table_name} is empty or doesn't exist")
    
    async def _handle_db_insert(self, args):
        """Handle database insert operations"""
        if len(args) < 2:
            logger.info("❌ Usage: db insert table <table_name> {\"column\": \"value\", ...}")
            return
        
        if args[0] != "table":
            logger.info("❌ Usage: db insert table <table_name> {\"column\": \"value\", ...}")
            return
        
        table_name = args[1]
        command_args, json_data = self._parse_json_args(args[2:])
        
        if not json_data:
            logger.info("❌ No JSON data provided for insert")
            return
        
        success, message = await self.server.db_manager.insert_row(table_name, json_data)
        if success:
            logger.info(f"✅ {message}")
        else:
            logger.info(f"❌ {message}")
    
    async def _handle_db_update(self, args):
        """Handle database update operations"""
        if len(args) < 2:
            logger.info("❌ Usage: db update table <table_name> {\"column\": \"new_value\"} {\"WHERE_column\": \"value\"}")
            return
        
        if args[0] != "table":
            logger.info("❌ Usage: db update table <table_name> {\"column\": \"new_value\"} {\"WHERE_column\": \"value\"}")
            return
        
        table_name = args[1]
        remaining_args = args[2:]
        
        # We need to parse two JSON objects - update data and WHERE conditions
        full_arg_string = " ".join(remaining_args)
        
        # Find all JSON objects
        json_objects = []
        brace_level = 0
        current_json = ""
        in_json = False
        
        for char in full_arg_string:
            if char == '{':
                if brace_level == 0:
                    in_json = True
                    current_json = ""
                brace_level += 1
            
            if in_json:
                current_json += char
            
            if char == '}':
                brace_level -= 1
                if brace_level == 0 and in_json:
                    try:
                        json_objects.append(json.loads(current_json))
                    except json.JSONDecodeError:
                        logger.info(f"❌ Invalid JSON: {current_json}")
                        return
                    in_json = False
        
        if len(json_objects) != 2:
            logger.info("❌ Two JSON objects required: update data and WHERE conditions")
            logger.info("   Example: db update table users {\"username\": \"new_name\"} {\"WHERE_id\": 1}")
            return
        
        update_data = json_objects[0]
        where_conditions_raw = json_objects[1]
        
        # Process WHERE conditions (remove WHERE_ prefix)
        where_conditions = {}
        for key, value in where_conditions_raw.items():
            if key.startswith("WHERE_"):
                where_conditions[key[6:]] = value
            else:
                where_conditions[key] = value
        
        success, message, count = await self.server.db_manager.update_rows(table_name, update_data, where_conditions)
        if success:
            logger.info(f"✅ {message} (affected: {count} rows)")
        else:
            logger.info(f"❌ {message}")
    
    async def _handle_db_delete(self, args):
        """Handle database delete operations"""
        if len(args) < 2:
            logger.info("❌ Usage: db delete table <table_name> {\"WHERE_column\": \"value\"}")
            return
        
        if args[0] != "table":
            logger.info("❌ Usage: db delete table <table_name> {\"WHERE_column\": \"value\"}")
            return
        
        table_name = args[1]
        command_args, json_data = self._parse_json_args(args[2:])
        
        if not json_data:
            logger.info("❌ No WHERE conditions provided for delete (safety check)")
            return
        
        # Process WHERE conditions (remove WHERE_ prefix if present)
        where_conditions = {}
        for key, value in json_data.items():
            if key.startswith("WHERE_"):
                where_conditions[key[6:]] = value
            else:
                where_conditions[key] = value
        
        # Confirm dangerous operation
        logger.info(f"⚠️  About to delete rows from {table_name} where {where_conditions}")
        try:
            confirmation = input("Confirm delete? y/N")
            if confirmation != "Y".tolower():
                logger.info("❌ Deletion cancelled")
                return
        except:
            logger.info("❌ Deletion cancelled")
            return
        
        success, message, count = await self.server.db_manager.delete_rows(table_name, where_conditions)
        
        if success:
            if count == 0:
                logger.info(f"⚠️  No rows matched the conditions for deletion in {table_name}")
            else:
                logger.info(f"✅ {message} (deleted: {count} rows)")
        else:
            logger.info(f"❌ {message}")
    
    async def _handle_db_stats(self):
        """Handle database statistics"""
        logger.info("📊 Database Statistics:")
        tables = await self.server.db_manager.get_table_names()
        total_rows = 0
        
        for table_name in tables:
            stats = await self.server.db_manager.get_table_stats(table_name)
            if stats:
                logger.info(f"   📋 {table_name}: {stats['row_count']} rows, {stats['column_count']} columns")
                total_rows += stats['row_count']
        
        logger.info(f"   📊 Total rows across all tables: {total_rows}")
        logger.info(f"   🗄️  Database file: {self.server.db_manager.db_path}")
    
    async def cmd_debug(self, args):
        """Debug commands"""
        if not args:
            logger.info("🐛 Debug Information:")
            logger.info(f"   Debug Mode: {globals().get('debugMode', False)}")
            logger.info(f"   Logger Level: {logger.level}")
            logger.info(f"   Connected Websockets: {len(self.server.connected_users)}")
        else:
            logger.info("⚠️  Advanced debug commands not implemented yet")
    
    async def cmd_ssl(self, args):
        """SSL certificate information"""
        logger.info("🔒 SSL Configuration:")
        logger.info(f"   SSL Enabled: {self.server.use_ssl}")
        logger.info(f"   Certificate File: {self.server.cert_file}")
        logger.info(f"   Key File: {self.server.key_file}")
        if Path(self.server.cert_file).exists():
            stat = Path(self.server.cert_file).stat()
            logger.info(f"   Certificate Modified: {datetime.fromtimestamp(stat.st_mtime)}")
    
    async def cmd_config(self, args):
        """Configuration management"""
        if not args or args[0] == "show":
            logger.info("⚙️  Server Configuration:")
            logger.info(f"   Host: {self.server.host}")
            logger.info(f"   Port: {self.server.port}")
            logger.info(f"   SSL: {self.server.use_ssl}")
            logger.info(f"   Ping Interval: {self.server.ping_interval}s")
            logger.info(f"   Ping Timeout: {self.server.ping_timeout}s")
        else:
            logger.info("⚠️  Configuration modification not implemented yet")
    
    async def cmd_shutdown(self, args):
        """Shutdown server"""
        logger.info("🛑 Initiating server shutdown...")
        self.running = False
        # TODO: Implement graceful shutdown
        logger.info("   (Graceful shutdown not fully implemented)")
    
    async def cmd_restart(self, args):
        """Restart server"""
        logger.info("🔄 Server restart not implemented yet")
    
    async def cmd_backup(self, args):
        """Create system backup"""
        logger.info("💾 System backup not implemented yet")
    
    async def cmd_clear(self, args):
        """Clear console screen"""
        os.system('clear' if os.name == 'posix' else 'cls')
    
    async def cmd_ping(self, args):
        """Send ping to specific user"""
        if not args:
            logger.info("❌ Usage: ping <username>")
            return
        
        username = args[0]
        if username in self.server.connected_users:
            user = self.server.connected_users[username]
            await self.server.send_ping(user.websocket, username)
            logger.info(f"📡 Ping sent to {username}")
        else:
            logger.info(f"❌ User '{username}' not found online")
    
    async def cmd_send_message(self, args):
        """Send admin message to user"""
        if len(args) < 2:
            logger.info("❌ Usage: message <username> <message>")
            return
        
        username = args[0]
        message = " ".join(args[1:])
        
        if username in self.server.connected_users:
            user = self.server.connected_users[username]
            admin_msg = {
                "type": "admin_message",
                "message": message,
                "timestamp": time.time(),
                "sender": "Server Administrator"
            }
            await user.websocket.send(json.dumps(admin_msg))
            logger.info(f"✉️  Message sent to {username}: {message}")
        else:
            logger.info(f"❌ User '{username}' not found online")
    
    async def cmd_user_info(self, args):
        """Get detailed user information"""
        if not args:
            logger.info("❌ Usage: user <username>")
            return
        
        username = args[0]
        await self.cmd_users([username])  # Reuse users command logic
    
    async def cmd_export(self, args):
        """Export data"""
        logger.info("📤 Data export not implemented yet")
    
    async def cmd_import(self, args):
        """Import data"""
        logger.info("📥 Data import not implemented yet")

if __name__ == "__main__":
    async def start_server_with_console():
        """Start server and console together"""
        # Parse command line arguments
        parser = argparse.ArgumentParser(description='Secure Messenger Server')
        parser.add_argument('--console', action='store_true', help='Enable interactive server console', default=True)
        parser.add_argument('--debug-terminal', action='store_true', help='Enable debug output in separate terminal',)
        parser.add_argument('--host', type=str, help='Server host address')
        parser.add_argument('--port', type=int, help='Server port')
        parser.add_argument('--no-ssl', action='store_true', help='Disable SSL')
        
        args = parser.parse_args()
        
        # Check environment variable for debug terminal
        enable_debug_terminal = args.debug_terminal or os.getenv('DEBUG_TERMINAL', '').lower() == 'true'
        
        try:
            # Load configuration
            config_path = Path(CONFIG_FILE)
            if config_path.exists():
                with open(config_path, 'r') as f:
                    config = json.load(f)
                
                server_config = config.get("server", {})
                host = args.host or server_config.get("host", "0.0.0.0")
                port = args.port or server_config.get("port", 8100)
                use_ssl = not args.no_ssl and server_config.get("ssl_enabled", True)
                cert_file = server_config.get("ssl_cert_path", SERVER_CERTFILE)
                key_file = server_config.get("ssl_key_path", SERVER_CERTFILE)
                ping_interval = server_config.get("ping_interval", 30)
                ping_timeout = server_config.get("ping_timeout", 40)
                
                # Use certificate files from config if specified
                cert_file = cert_file if cert_file else SERVER_CERTFILE
                key_file = key_file if key_file else SERVER_CERTFILE
                
                logger.info(f"[CONFIG] Loaded server configuration:")
                logger.info(f"[CONFIG] Host: {host}")
                logger.info(f"[CONFIG] Port: {port}")
                logger.info(f"[CONFIG] SSL: {'Enabled' if use_ssl else 'Disabled'}")
                logger.info(f"[CONFIG] Console: {'Enabled' if args.console else 'Disabled'}")
                logger.info(f"[CONFIG] Debug Terminal: {'Enabled' if enable_debug_terminal else 'Disabled'}")
                logger.info(f"[CONFIG] Ping Interval: {ping_interval}s")
                logger.info(f"[CONFIG] Ping Timeout: {ping_timeout}s")
                if use_ssl:
                    logger.info(f"[CONFIG] Certificate: {cert_file}")
                    logger.info(f"[CONFIG] Private Key: {key_file}")
                
                # Initialize server with configuration
                server = SecureChatServer(
                    host=host, 
                    port=port, 
                    use_ssl=use_ssl,
                    cert_file=cert_file,
                    key_file=key_file,
                    ping_interval=ping_interval,
                    ping_timeout=ping_timeout,
                    enable_debug_terminal=enable_debug_terminal
                )
            else:
                logger.info("[CONFIG] No config file found, using defaults")
                # Initialize with defaults (SSL enabled)
                server = SecureChatServer(enable_debug_terminal=enable_debug_terminal)
            
            # Add start time for uptime calculation
            server.start_time = time.time()
            
            # Create console
            console = ServerConsole(server)
            
            if args.console:
                logger.info("🖥️  Starting server with interactive console...")
                logger.info("📝 Type 'help' in the console for available commands")
                if enable_debug_terminal:
                    logger.info("� Debug output will be shown in separate terminal")
                # Start server and console concurrently
                await asyncio.gather(
                    server.start_server(),
                    console.start()
                )
            else:
                logger.info("🖥️  Starting server (use --console for interactive mode)...")
                # Start only the server
                await server.start_server()
                
        except KeyboardInterrupt:
            logger.info("Server shutting down by user request")
            logger.info("\n👋 Server shutting down...")
        except Exception as e:
            logger.error(f"Server crashed: {str(e)}")
            logger.info(f"[ERROR] Server crashed: {str(e)}")
        finally:
            logger.info("Server shutdown complete")
            logger.info("Server shutdown complete")

    try:
        asyncio.run(start_server_with_console())
    except KeyboardInterrupt:
        logger.info("\n👋 Server shutting down...")
    except Exception as e:
        logger.info(f"❌ Fatal error: {e}")