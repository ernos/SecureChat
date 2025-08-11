
---
# CLIENT_DATABASE_HANDLING.md
This document describes the client database table structures, data manipulation, initial setup, and all manipulation functions for the client component of SafeMessenger.
---

## Client Database File (`client/data/client_<username>.db`)

### Tables
	---
	**friends**: Stores friend relationships and metadata.
	
		- `id` (PK, autoincrement)
		- `user_id` (int, NOT NULL): Unique user ID for the friend (from server)
		- `username` (text, UNIQUE, NOT NULL): Friend's username
		- `public_key` (text, NOT NULL): Friend's public key
		- `last_login` (real): Last login timestamp (float)
		- `is_online` (boolean, default FALSE): Online status
		- `auto_delete_hours` (int, default 24): Message auto-delete window
	**messages**: Stores all sent/received messages.
		- `id` (PK, autoincrement)
		- `sender_id` (int, NOT NULL): Sender's user ID (must match a friend)
		- `content` (text, NOT NULL): Message content (may be encrypted)
		- `encrypted` (boolean, default FALSE): Whether the message is encrypted
		- `read_at` (real, default NULL): Timestamp when message was read
		- `expires_at` (real, NOT NULL): Expiry timestamp
		- `FOREIGN KEY (sender_id)` references `friends(id)`
	---

## Client Database Management (`client/database_manager.py`)

### Key Functions
	**`__init__(username: str)`**: Initializes the database manager for a given username. Sets the database path to `client/data/client_<username>.db`.
	**`async def initialize(self)`**: Opens a connection to the SQLite database and creates tables if they do not exist.
		- Calls `self._create_tables()` to ensure schema is present.
	**`async def _create_tables(self)`**: Creates the `friends` and `messages` tables as described above.
	**`async def close(self)`**: Closes the database connection.
	**`async def add_friend(self, user_id: int, username: str, last_login: float, public_key: str, is_online: bool = False, auto_delete_hours: int = 24)`**: Adds or updates a friend in the `friends` table.
		- Uses `INSERT OR REPLACE` to ensure uniqueness by username.
		- Stores user ID, username, public key, last login, online status, and auto-delete window.
	**`async def delete_friend(self, username: str)`**: Deletes a friend from the `friends` table by username.
	**`async def update_friend_last_login(self, username: str, last_login: float, is_online: bool)`**: Updates a friend's last login timestamp and online status by username.
	**`async def add_message(self, sender_id: int, content: str, encrypted: bool, expires_at: float)`**: Adds a message to the `messages` table.
		- Stores sender ID, content, encryption status, and expiry timestamp.
	**`async def delete_message(self, message_id: int)`**: Deletes a message from the `messages` table by ID.
	**`async def read_message(self, message_id: int, crypto_utils) -> str`**: Reads a message by ID. If encrypted, decrypts using `crypto_utils` and the sender's public key.
		- Joins `messages` and `friends` to get the sender's public key.
		- If `encrypted` is true, calls `crypto_utils.decrypt_message(content, public_key)`.

---

## Usage Notes
	- All database operations are asynchronous and must be awaited.
	- The schema is auto-migrated/created on first use for each user.
	- The `friends` table is the authoritative source for friend metadata and public keys.
	- The `messages` table stores all messages, with encryption and expiry metadata.
	- For further details, see the implementation in `client/database_manager.py`.
