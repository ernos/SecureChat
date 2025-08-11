"""
Database manager for the Secure Chat Server
Handles user registration, authentication, and message storage
"""

import aiosqlite
import bcrypt
import time
import json
from typing import Optional, Dict, List, Tuple
from datetime import datetime, timedelta
from pathlib import Path
from websockets.legacy.server import WebSocketServerProtocol

DATABASE_VERSION="0.0.1"

class DatabaseManager:
    """Manages SQLite database operations for the chat server"""
    def __init__(self, db_path: str = "data/chat_server.db", version: str = DATABASE_VERSION):
        self.db_path = db_path
        self.db = None
    
    async def initialize(self):
        """Initialize the database and create tables"""
        self.db = await aiosqlite.connect(self.db_path)
        await self._create_tables()
        print(f"Database initialized: {self.db_path}")
    
    async def close(self):
        """Close the database connection"""
        if self.db:
            await self.db.close()
    
    async def _create_tables(self):
        """Create necessary database tables"""
        

        # Users table
        await self.db.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                public_key TEXT NOT NULL,
                salt TEXT NOT NULL,
                created_at REAL NOT NULL,
                last_active REAL,
                total_messages_received INTEGER DEFAULT 0,
                unread_messages INTEGER DEFAULT 0,
                auto_delete_hours INTEGER DEFAULT 24,
                is_online BOOLEAN DEFAULT TRUE,
                accepts_unknown_friend_requests BOOLEAN DEFAULT TRUE,
                accepts_unknown_messages BOOLEAN DEFAULT TRUE,
                accepts_unknown_invites_to_chatrooms BOOLEAN DEFAULT TRUE
            )
        """)
        
        # Messages table for persistent storage
        await self.db.execute("""
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender_id INTEGER NOT NULL,
                recipient_id INTEGER,
                room_name TEXT,
                content TEXT NOT NULL,
                message_type TEXT NOT NULL,
                encrypted BOOLEAN DEFAULT FALSE,
                signature TEXT,
                created_at REAL NOT NULL,
                read_at REAL,
                expires_at REAL NOT NULL,
                is_deleted BOOLEAN DEFAULT FALSE,
                FOREIGN KEY (sender_id) REFERENCES users (id),
                FOREIGN KEY (recipient_id) REFERENCES users (id)
            )
        """)
        
        # Sessions table for active connections
        await self.db.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                session_token TEXT UNIQUE NOT NULL,
                created_at REAL NOT NULL,
                last_active REAL NOT NULL,
                expires_at REAL NOT NULL,
                ip_address TEXT,
                is_active BOOLEAN DEFAULT TRUE,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        """)
        
        # Friends table for friend relationships
        await self.db.execute("""
            CREATE TABLE IF NOT EXISTS friends (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                friend_id INTEGER NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                requested_at REAL NOT NULL,
                accepted_at REAL,
                is_online BOOLEAN DEFAULT TRUE,
                FOREIGN KEY (user_id) REFERENCES users (id),
                FOREIGN KEY (friend_id) REFERENCES users (id),
                UNIQUE(user_id, friend_id)
            )
        """)

        # Friends table for friend relationships
        await self.db.execute("""
            CREATE TABLE IF NOT EXISTS server_information (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                server_version FLOAT NOT NULL,
                database_version FLOAT NOT NULL,
                certificate_file TEXT NOT NULL DEFAULT 'pending',
                private_key TEXT NOT NULL,
                connections_today INTEGER NOT NULL DEFAULT 0,
                connections_all INTEGER NOT NULL DEFAULT 0
            )
        """)
    
        # Create indexes for better performance
        await self.db.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)")
        await self.db.execute("CREATE INDEX IF NOT EXISTS idx_messages_recipient ON messages(recipient_id)")
        await self.db.execute("CREATE INDEX IF NOT EXISTS idx_messages_expires ON messages(expires_at)")
        await self.db.execute("CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(session_token)")
        await self.db.execute("CREATE INDEX IF NOT EXISTS idx_friends_user ON friends(user_id)")
        await self.db.execute("CREATE INDEX IF NOT EXISTS idx_friends_friend ON friends(friend_id)")
        await self.db.execute("CREATE INDEX IF NOT EXISTS idx_friends_status ON friends(status)")
        
        await self.db.commit()
    
    async def register_user(self, username: str, password: str, public_key: str) -> Tuple[bool, str]:
        """Register a new user with encrypted password"""
        try:
            # Check if username already exists
            cursor = await self.db.execute(
                "SELECT id FROM users WHERE username = ?", (username,)
            )
            existing_user = await cursor.fetchone()
            if existing_user:
                return False, "Username already exists"
            
            # Generate salt and hash password
            salt = bcrypt.gensalt()
            password_hash = bcrypt.hashpw(password.encode('utf-8'), salt)
            
            # Insert new user
            current_time = time.time()
            await self.db.execute("""
                INSERT INTO users (username, password_hash, public_key, salt, created_at)
                VALUES (?, ?, ?, ?, ?)
            """, (username, password_hash.decode('utf-8'), public_key, salt.decode('utf-8'), current_time))
            
            await self.db.commit()
            return True, "User registered successfully"
            
        except Exception as e:
            return False, f"Registration failed: {str(e)}"
    
    async def authenticate_user(self, username: str, password: str) -> Tuple[bool, Optional[Dict]]:
        """Authenticate user credentials"""
        try:
            cursor = await self.db.execute("""
                SELECT id, username, password_hash, public_key, salt, is_online 
                FROM users WHERE username = ?
            """, (username,))
            user_data = await cursor.fetchone()
            
            if not user_data:
                return False, None
            
            user_id, db_username, stored_hash, public_key, salt, is_online = user_data
            
            if not is_online:
                return False, None
            
            # Verify password
            if bcrypt.checkpw(password.encode('utf-8'), stored_hash.encode('utf-8')):
                # Update last login time
                await self.db.execute(
                    "UPDATE users SET last_active = ? WHERE id = ?",
                    (time.time(), user_id)
                )
                await self.db.commit()
                
                return True, {
                    'id': user_id,
                    'username': db_username,
                    'public_key': public_key
                }
            
            return False, None
            
        except Exception as e:
            print(f"Authentication error: {e}")
            return False, None
    
    async def get_user_by_username(self, username: str) -> Optional[Dict]:
        """Get user information by username"""
        try:
            cursor = await self.db.execute("""
                SELECT id, username, public_key, total_messages_received, 
                    unread_messages, auto_delete_hours, created_at, last_active
                FROM users WHERE username = ?
            """, (username,))
            user_data = await cursor.fetchone()
            
            if user_data:
                return {
                    'id': user_data[0],
                    'username': user_data[1],
                    'public_key': user_data[2],
                    'total_messages_received': user_data[3],
                    'unread_messages': user_data[4],
                    'auto_delete_hours': user_data[5],
                    'created_at': user_data[6],
                    'last_active': user_data[7]
                }
            return None
            
        except Exception as e:
            print(f"Error getting user: {e}")
            return None
    
    async def store_message(self, sender_id: int, recipient_id: Optional[int], 
                            room_name: Optional[str], content: str, message_type: str,
                            encrypted: bool = False, signature: Optional[str] = None,
                            auto_delete_hours: int = 24) -> bool:
        """Store a message in the database"""
        try:
            current_time = time.time()
            expires_at = current_time + (auto_delete_hours * 3600)  # Convert hours to seconds
            
            await self.db.execute("""
                INSERT INTO messages (sender_id, recipient_id, room_name, content, 
                                    message_type, encrypted, signature, created_at, expires_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (sender_id, recipient_id, room_name, content, message_type, 
                encrypted, signature, current_time, expires_at))
            
            # Update recipient's message count if it's a private message
            if recipient_id:
                await self.db.execute("""
                    UPDATE users SET total_messages_received = total_messages_received + 1,
                    unread_messages = unread_messages + 1
                    WHERE id = ?
                """, (recipient_id,))
            
            await self.db.commit()
            return True
            
        except Exception as e:
            print(f"Error storing message: {e}")
            return False
    
    async def mark_message_read(self, message_id: int, user_id: int) -> bool:
        """Mark a message as read and update expiration"""
        try:
            current_time = time.time()
            # Get user's auto-delete setting
            cursor = await self.db.execute(
                "SELECT auto_delete_hours FROM users WHERE id = ?", (user_id,)
            )
            user_data = await cursor.fetchone()
            if not user_data:
                return False
            
            auto_delete_hours = user_data[0]
            new_expires_at = current_time + (auto_delete_hours * 3600)
            
            # Update message read time and new expiration
            await self.db.execute("""
                UPDATE messages SET read_at = ?, expires_at = ?
                WHERE id = ? AND recipient_id = ? AND read_at IS NULL
            """, (current_time, new_expires_at, message_id, user_id))
            
            # Decrease unread count
            await self.db.execute("""
                UPDATE users SET unread_messages = unread_messages - 1
                WHERE id = ? AND unread_messages > 0
            """, (user_id,))
            
            await self.db.commit()
            return True
            
        except Exception as e:
            print(f"Error marking message read: {e}")
            return False
    
    async def get_unread_messages(self, user_id: int) -> List[Dict]:
        """Get unread messages for a user"""
        try:
            cursor = await self.db.execute("""
                SELECT m.id, u.username as sender, m.content, m.message_type,
                    m.encrypted, m.signature, m.created_at
                FROM messages m
                JOIN users u ON m.sender_id = u.id
                WHERE m.recipient_id = ? AND m.read_at IS NULL 
                AND m.is_deleted = FALSE AND m.expires_at > ?
                ORDER BY m.created_at ASC
            """, (user_id, time.time()))
            
            messages = await cursor.fetchall()
            return [
                {
                    'id': msg[0],
                    'sender': msg[1],
                    'content': msg[2],
                    'message_type': msg[3],
                    'encrypted': bool(msg[4]),
                    'signature': msg[5],
                    'created_at': msg[6]
                }
                for msg in messages
            ]
            
        except Exception as e:
            print(f"Error getting unread messages: {e}")
            return []
    
    async def cleanup_expired_messages(self) -> int:
        """Remove expired messages from the database"""
        try:
            current_time = time.time()
            
            # Mark expired messages as deleted
            cursor = await self.db.execute("""
                UPDATE messages SET is_deleted = TRUE 
                WHERE expires_at < ? AND is_deleted = FALSE
            """, (current_time,))
            
            deleted_count = cursor.rowcount
            
            # Actually delete messages that have been marked as deleted for more than 24 hours
            deletion_threshold = current_time - (24 * 3600)
            await self.db.execute("""
                DELETE FROM messages 
                WHERE is_deleted = TRUE AND expires_at < ?
            """, (deletion_threshold,))
            
            await self.db.commit()
            return deleted_count
            
        except Exception as e:
            print(f"Error cleaning up messages: {e}")
            return 0
    
    async def get_user_stats(self, user_id: int) -> Dict:
        """Get user statistics"""
        try:
            cursor = await self.db.execute("""
                SELECT total_messages_received, unread_messages, auto_delete_hours
                FROM users WHERE id = ?
            """, (user_id,))
            stats = await cursor.fetchone()
            
            if stats:
                return {
                    'total_messages_received': stats[0],
                    'unread_messages': stats[1],
                    'auto_delete_hours': stats[2]
                }
            return {}
            
        except Exception as e:
            print(f"Error getting user stats: {e}")
            return {}
    
    async def update_auto_delete_setting(self, user_id: int, hours: int) -> bool:
        """Update user's auto-delete setting"""
        try:
            await self.db.execute("""
                UPDATE users SET auto_delete_hours = ? WHERE id = ?
            """, (hours, user_id))
            await self.db.commit()
            return True
            
        except Exception as e:
            print(f"Error updating auto-delete setting: {e}")
            return False
    
    async def debug_print_all_tables(self) -> None:
        """Debug function to print all columns and rows from all tables"""
        try:
            # Get all table names
            cursor = await self.db.execute("""
                SELECT name FROM sqlite_master 
                WHERE type='table' AND name NOT LIKE 'sqlite_%'
                ORDER BY name
            """)
            tables = await cursor.fetchall()
            
            print("\n" + "="*80)
            print("DATABASE DEBUG: ALL TABLES CONTENT")
            print("="*80)
            
            for table_tuple in tables:
                table_name = table_tuple[0]
                print(f"\n📋 TABLE: {table_name}")
                print("-" * 50)
                
                # Get column information
                cursor = await self.db.execute(f"PRAGMA table_info({table_name})")
                columns_info = await cursor.fetchall()
                
                # Extract column names and types
                columns = []
                print("COLUMNS:")
                for col_info in columns_info:
                    col_name = col_info[1]
                    col_type = col_info[2]
                    is_pk = " (PRIMARY KEY)" if col_info[5] else ""
                    not_null = " (NOT NULL)" if col_info[3] else ""
                    columns.append(col_name)
                    print(f"  - {col_name}: {col_type}{is_pk}{not_null}")
                
                # Get all rows
                cursor = await self.db.execute(f"SELECT * FROM {table_name}")
                rows = await cursor.fetchall()
                
                print(f"\nROWS ({len(rows)} total):")
                if rows:
                    # Print header
                    header = " | ".join(f"{col:15}" for col in columns)
                    print(f"  {header}")
                    print("  " + "-" * len(header))
                    
                    # Print each row
                    for i, row in enumerate(rows, 1):
                        row_data = []
                        for j, value in enumerate(row):
                            # Format different data types appropriately
                            if value is None:
                                formatted_value = "NULL"
                            elif isinstance(value, float) and columns[j].endswith('_at'):
                                # Convert timestamp to readable format
                                try:
                                    formatted_value = datetime.fromtimestamp(value).strftime('%Y-%m-%d %H:%M:%S')
                                except:
                                    formatted_value = str(value)
                            elif isinstance(value, str) and len(value) > 15:
                                # Truncate long strings
                                formatted_value = value[:12] + "..."
                            else:
                                formatted_value = str(value)
                            row_data.append(f"{formatted_value:15}")
                        
                        row_str = " | ".join(row_data)
                        print(f"  {row_str}")
                else:
                    print("  (No rows)")
                
                print()  # Empty line between tables
            
            print("="*80)
            print("END OF DATABASE DEBUG")
            print("="*80 + "\n")
            
        except Exception as e:
            print(f"Error in debug_print_all_tables: {e}")

    async def debug_table_summary(self) -> None:
        """Print a summary of all tables and their row counts"""
        try:
            cursor = await self.db.execute("""
                SELECT name FROM sqlite_master 
                WHERE type='table' AND name NOT LIKE 'sqlite_%'
                ORDER BY name
            """)
            tables = await cursor.fetchall()
            
            print("\n📊 DATABASE SUMMARY")
            print("-" * 30)
            
            for table_tuple in tables:
                table_name = table_tuple[0]
                cursor = await self.db.execute(f"SELECT COUNT(*) FROM {table_name}")
                count = await cursor.fetchone()
                print(f"{table_name:15}: {count[0]:5} rows")
            
            print("-" * 30 + "\n")
            
        except Exception as e:
            print(f"Error in debug_table_summary: {e}")
    
    # Friend Management Methods
    
    async def send_friend_request(self, user_id: int, friend_username: str) -> Tuple[bool, str]:
        """Send a friend request to another user"""
        try:
            # Get friend's user ID
            cursor = await self.db.execute(
                "SELECT id FROM users WHERE username = ?", 
                (friend_username,)
            )
            friend_row = await cursor.fetchone()
            
            if not friend_row:
                return False, "User not found"
            
            friend_id = friend_row[0]
            
            if user_id == friend_id:
                return False, "Cannot send friend request to yourself"
            
            # Check if friendship already exists
            cursor = await self.db.execute("""
                SELECT status FROM friends 
                WHERE (user_id = ? AND friend_id = ?) OR (user_id = ? AND friend_id = ?)
            """, (user_id, friend_id, friend_id, user_id))
            existing = await cursor.fetchone()
            
            if existing:
                status = existing[0]
                if status == 'accepted':
                    return False, "Already friends"
                elif status == 'pending':
                    return False, "Friend request already pending"
                elif status == 'blocked':
                    return False, "Cannot send friend request"
            
            # Send friend request
            await self.db.execute("""
                INSERT INTO friends (user_id, friend_id, status, requested_at)
                VALUES (?, ?, 'pending', ?)
            """, (user_id, friend_id, time.time()))
            
            await self.db.commit()
            return True, "Friend request sent"
            
        except Exception as e:
            print(f"Error sending friend request: {e}")
            return False, "Database error"
    
    async def accept_friend_request(self, user_id: int, friend_username: str) -> Tuple[bool, str]:
        """Accept a friend request"""
        try:
            # Get friend's user ID
            cursor = await self.db.execute(
                "SELECT id FROM users WHERE username = ?", 
                (friend_username,)
            )
            friend_row = await cursor.fetchone()
            
            if not friend_row:
                return False, "User not found"
            
            friend_id = friend_row[0]
            
            # Check if there's a pending request from the friend
            cursor = await self.db.execute("""
                SELECT id FROM friends 
                WHERE user_id = ? AND friend_id = ? AND status = 'pending'
            """, (friend_id, user_id))
            request = await cursor.fetchone()
            
            if not request:
                return False, "No pending friend request found"
            
            # Accept the request
            current_time = time.time()
            await self.db.execute("""
                UPDATE friends 
                SET status = 'accepted', accepted_at = ? 
                WHERE user_id = ? AND friend_id = ?
            """, (current_time, friend_id, user_id))
            
            # Create reciprocal friendship
            await self.db.execute("""
                INSERT OR REPLACE INTO friends (user_id, friend_id, status, requested_at, accepted_at)
                VALUES (?, ?, 'accepted', ?, ?)
            """, (user_id, friend_id, current_time, current_time))
            
            await self.db.commit()
            return True, "Friend request accepted"
            
        except Exception as e:
            print(f"Error accepting friend request: {e}")
            return False, "Database error"
        
    # The above code is a Python comment. Comments in Python start with a hash
    # symbol (#) and are used to provide explanations or notes within the
    # code. In this case, the comment consists of multiple hash symbols
    # followed by the text "    
    async def decline_friend_request(self, user_id: int, friend_username: str) -> Tuple[bool, str]:
        """Decline a friend request"""
        try:
            # Get friend's user ID
            cursor = await self.db.execute(
                "SELECT id FROM users WHERE username = ?", 
                (friend_username,)
            )
            friend_row = await cursor.fetchone()
            
            if not friend_row:
                return False, "User not found"
            
            friend_id = friend_row[0]
            
            # Delete the pending request
            cursor = await self.db.execute("""
                DELETE FROM friends 
                WHERE user_id = ? AND friend_id = ? AND status = 'pending'
            """, (friend_id, user_id))
            
            if cursor.rowcount == 0:
                return False, "No pending friend request found"
            
            await self.db.commit()
            return True, "Friend request declined"
            
        except Exception as e:
            print(f"Error declining friend request: {e}")
            return False, "Database error"
    
    async def remove_friend(self, user_id: int, friend_username: str) -> Tuple[bool, str]:
        """Remove a friend"""
        try:
            # Get friend's user ID
            cursor = await self.db.execute(
                "SELECT id FROM users WHERE username = ?",
                (friend_username,)
            )
            friend_row = await cursor.fetchone()
            
            if not friend_row:
                return False, "User not found"
            
            friend_id = friend_row[0]
            
            # Remove both directions of friendship
            await self.db.execute("""
                DELETE FROM friends 
                WHERE (user_id = ? AND friend_id = ?) OR (user_id = ? AND friend_id = ?)
                AND status = 'accepted'
            """, (user_id, friend_id, friend_id, user_id))
            
            await self.db.commit()
            return True, "Friend removed"
            
        except Exception as e:
            print(f"Error removing friend: {e}")
            return False, "Database error"
    
    async def get_friends_list(self, user_id: int) -> List[Dict]:
        """Get list of accepted friends for a user"""
        try:
            cursor = await self.db.execute("""
                SELECT u.id, u.username, u.last_active, u.public_key, f.accepted_at, u.is_online
                FROM friends f
                JOIN users u ON f.friend_id = u.id
                WHERE f.user_id = ? AND f.status = 'accepted'
                ORDER BY u.is_online DESC, u.username ASC
            """, (user_id,))
            
            friends = await cursor.fetchall()
            return [
                {
                    'id': friend[0],
                    'username': friend[1],
                    'last_active': friend[2],
                    'friends_since': friend[4],
                    'public_key': friend[3]
                }
                for friend in friends
            ]
            
        except Exception as e:
            print(f"Error getting friends list: {e}")
            return []
    
    async def get_friend_requests(self, user_id: int) -> List[Dict]:
        """Get pending friend requests for a user"""
        try:
            cursor = await self.db.execute("""
                SELECT u.id, u.username, f.requested_at
                FROM friends f
                JOIN users u ON f.user_id = u.id
                WHERE f.friend_id = ? AND f.status = 'pending'
                ORDER BY f.requested_at DESC
            """, (user_id,))
            
            requests = await cursor.fetchall()
            return [
                {
                    'id': request[0],
                    'username': request[1],
                    'requested_at': request[2]
                }
                for request in requests
            ]
            
        except Exception as e:
            print(f"Error getting friend requests: {e}")
            return []
    
    async def are_friends(self, user_id: int, other_user_id: int) -> bool:
        """Check if two users are friends"""
        try:
            cursor = await self.db.execute("""
                SELECT 1 FROM friends 
                WHERE user_id = ? AND friend_id = ? AND status = 'accepted'
            """, (user_id, other_user_id))
            
            result = await cursor.fetchone()
            return result is not None
            
        except Exception as e:
            print(f"Error checking friendship: {e}")
            return False
    
    async def is_friend_request_pending(self, user_id: int, other_friend_id: int) -> bool:
        """Check if a friend request is pending between two users"""
        try:
            cursor = await self.db.execute("""
                SELECT 1 FROM friends 
                WHERE user_id = ? AND friend_id = ? AND status = 'pending'
            """, (user_id, other_friend_id))

            result = await cursor.fetchone()
            return result is not None

        except Exception as e:
            print(f"Error checking friend has sent us request: {e}")
            return False
        
    
    async def get_user_id_by_username(self, username: str) -> Optional[int]:
        """Get user ID by username"""
        try:
            cursor = await self.db.execute(
                "SELECT id FROM users WHERE username = ?", 
                (username,)
            )
            result = await cursor.fetchone()
            return result[0] if result else None
            
        except Exception as e:
            print(f"Error getting user ID: {e}")
            return None

    # Debug and utility methods
            print(f"Error getting user ID: {e}")
            return None

    # Debug and utility methods
