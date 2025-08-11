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

class DatabaseManager:
    async def add_message(self, sender_id: int, content: str, encrypted: bool, expires_at: float):
        """Add a message to the messages table."""
        await self.db.execute(
            """
            INSERT INTO messages (sender_id, content, encrypted, expires_at)
            VALUES (?, ?, ?, ?)
            """,
            (sender_id, content, int(encrypted), expires_at)
        )
        await self.db.commit()

    async def delete_message(self, message_id: int):
        """Delete a message from the messages table by id."""
        await self.db.execute(
            "DELETE FROM messages WHERE id = ?",
            (message_id,)
        )
        await self.db.commit()

    async def read_message(self, message_id: int, crypto_utils) -> str:
        """Read a message by id. If encrypted, decrypt using crypto_utils and sender's public key."""
        cursor = await self.db.execute(
            """
            SELECT m.content, m.encrypted, f.public_key
            FROM messages m
            JOIN friends f ON m.sender_id = f.id
            WHERE m.id = ?
            """,
            (message_id,)
        )
        row = await cursor.fetchone()
        if not row:
            return None
        content, encrypted, public_key = row
        if encrypted:
            # crypto_utils should have a decrypt_message(content, public_key) method
            return await crypto_utils.decrypt_message(content, public_key)
        return content
    """Manages SQLite database operations for the chat server"""
    
    def __init__(self, username: str):
        self.db_path = f"client/data/client_{username}.db"
        self.db = None
        
    async def add_friend(self, user_id: int, username: str, last_login: float, public_key: str, is_online: bool = False, auto_delete_hours: int = 24):
        """                    friend.get('user_id'), 
                    friend.get('username'), 
                    friend.get('last_login'), 
                    friend.get('public_key'), 
                    friend.get('is_online', False)"""
        """Add a friend to the friends table."""
        await self.db.execute(
            """
            INSERT OR REPLACE INTO friends (user_id, username, public_key, last_login, is_online, auto_delete_hours)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (user_id, username, public_key, last_login, int(is_online), auto_delete_hours)
        )
        await self.db.commit()

    async def delete_friend(self, username: str):
        """Delete a friend from the friends table by username."""
        await self.db.execute(
            "DELETE FROM friends WHERE username = ?",
            (username,)
        )
        await self.db.commit()

    async def update_friend_last_login(self, username: str, last_login: float, is_online: bool):
        """Update a friend's last_login and is_online status by username."""
        await self.db.execute(
            "UPDATE friends SET last_login = ?, is_online = ? WHERE username = ?",
            (last_login, int(is_online), username)
        )
        await self.db.commit()
    
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
            CREATE TABLE IF NOT EXISTS friends (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                username TEXT UNIQUE NOT NULL,
                public_key TEXT NOT NULL,
                last_login REAL,
                is_online BOOLEAN DEFAULT FALSE,
                auto_delete_hours INTEGER DEFAULT 24
                
            )
        """)
        
        # Messages table for persistent storage
        await self.db.execute("""
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender_id INTEGER NOT NULL,
                content TEXT NOT NULL,
                encrypted BOOLEAN DEFAULT FALSE,
                read_at REAL DEFAULT NULL,
                expires_at REAL NOT NULL,
                FOREIGN KEY (sender_id) REFERENCES friends (id)
            )
        """)
        

    
        await self.db.commit()
    