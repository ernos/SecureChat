>
# Copilot Instructions for SafeMessengerWorkspace
  ## 1.Formatting Style of instruction files. ##
    ** Indentation style **
      - Indent ## with one tab, ### with two tabs
      - Indent `**`, `***` or ` - \`` with two tabs + the indentations of the parent #, ##, ## or ** header
      - **Purpose:** Better human readability and understanding.

  ## 2.Project Overview
    **File Layout For all `*.md` include files**
    - management. SQLite is used for persistence. All communication is encrypted and authenticated.
  **Major Components:**
    - `server/`: Server logic, database, cryptography, admin console, and server-side workflows.
    - `client/`: Client logic, local database, cryptography, and user workflows.
    - `data/`: Configuration, SSL certificates, and database files.
    - `logs/`: Rotating log files for both server and client events.
  **Configuration Files:**
    - `client/config.json`: Client-specific configuration.
    - `data/server_config.json`: Server-specific configuration.

## 4.Architecture & Data Flow
  **Server python files:**
    - Entrypoint: `server/server.py` (WebSocket server, user/session/room management, admin console)
    - Database Manager: `server/database_manager.py` (async SQLite, all DB access via this class)
    - Crypto: `server/crypto_utils.py` (encryption, signatures, key management)
    - Admin: `ServerConsole` in `server.py` (extend with `cmd_<name>` methods)
  **Server data files**
    - Config loads from `data/server_config.json`
    - Database SQL File: `data/chat_server.db`
    - Certificate key: `data/server.crt`
    - Key file: `data/server.key`
  **Client Python Files:**
    - Main class: `ChatClient` (see `CLIENT_CLASS.md` for all methods)
      Handles client-side logic, networking, and composes with `CryptoHandler` for cryptography.
    - Entrypoint: `client/client.py` (config loading, server connection, message send/receive)
    - Database Manager: `client/database_manager.py` (async SQLite, friends/messages)
    - Crypto Handler: `client/crypto_handler.py` (`CryptoHandler` class, all key management and cryptographic operations)
    - Crypto Utils: `client/crypto_utils.py` (RSA/AES, password hashing)
  **Client data files**
    - Config loads from `data/client_config.json`
    - Database SQL File: `data/chat_server.db`
    - Certificate key: `data/server.crt`
    - Key file: `data/server.key`
  **Data Flow:**
    - Config loads from `data/config.json` (auto-generated if missing)
    - All DB/network operations are async/await
    - All messages are encrypted and signed (see `crypto_utils.py`)
    - Logs written to `logs/` (rotated)

## 5.Developer Workflows
  **Database inspection:**
    - Server: `python3 server/view_database.py [--debug|--summary]`
    - Client: `python3 client/view_database.py [--debug|--summary]`
  **Logs:** All logs are in `logs/` and per-component log files (e.g., `client.log`)

## 6.Run Configurations
  **Server:**
    - Use `Debug server in integrated terminal` run configuration to start the server.
  **Client:**
    - Preferred: `python3 client/client.py`
    - Environment: Run from project root or `client/` directory. Ensure config and keys exist in `client/data/` and `client/client_keys/`.
    - Logs: Output to `logs/client.log` and rotated log files.
  **Check Environment:**
    - Server: `python3 server/check_env.py`
    - Client: `python3 client/check_env.py`
  **General:**
    - Always run `bash killall python3` before starting new server/client instances to avoid port or DB lock issues.
    - For debugging, use `start_debug.sh` or VS Code debug configurations if available.


## 7.Database Table Structure & Functions
  ### Client Database Structure
  - Database File: `client/data/client_<username>.db`
  **Tables:**
    - `friends`: Stores friend relationships and metadata.
      - `id` (PK, autoincrement)
      - `user_id` (int, NOT NULL): Unique user ID for the friend (from server)
      - `username` (text, UNIQUE, NOT NULL): Friend's username
      - `public_key` (text, NOT NULL): Friend's public key
      - `last_login` (real): Last login timestamp (float)
      - `is_online` (boolean, default FALSE): Online status
      - `auto_delete_hours` (int, default 24): Message auto-delete window
    - `messages`: Stores all sent/received messages.
      - `id` (PK, autoincrement)
      - `sender_id` (int, NOT NULL): Sender's user ID (must match a friend)
      - `content` (text, NOT NULL): Message content (may be encrypted)
      - `encrypted` (boolean, default FALSE): Whether the message is encrypted
      - `read_at` (real, default NULL): Timestamp when message was read
      - `expires_at` (real, NOT NULL): Expiry timestamp
      - `FOREIGN KEY (sender_id)` references `friends(id)`

  ### Server Database Structure
  - Database File: `data/server_database.db`
  - Tables
    - `users`: Stores user credentials, public keys, and metadata.
      - `id` (INTEGER PRIMARY KEY)
      - `username` (TEXT UNIQUE NOT NULL)
      - `password_hash` (TEXT NOT NULL)
      - `public_key` (TEXT NOT NULL)
      - `salt` (TEXT NOT NULL)
      - `created_at` (REAL NOT NULL) — UNIX timestamp
      - `last_active` (REAL) — UNIX timestamp
      - `total_messages_received` (INTEGER DEFAULT 0)
      - `unread_messages` (INTEGER DEFAULT 0)
      - `auto_delete_hours` (INTEGER DEFAULT 24)
      - `is_online` (BOOLEAN DEFAULT FALSE)
      - `accepts_unknown_friend_requests` (BOOLEAN DEFAULT TRUE)
      - `accepts_unknown_messages` (BOOLEAN DEFAULT TRUE)
      - `accepts_unknown_invites_to_chatrooms` (BOOLEAN DEFAULT TRUE)
    - `messages`: Stores all messages (public/private).
      - `id` (INTEGER PRIMARY KEY)
      - `sender_id` (INTEGER NOT NULL)
      - `recipient_id` (INTEGER)
      - `room_name` (TEXT)
      - `content` (TEXT NOT NULL)
      - `message_type` (TEXT NOT NULL)
      - `encrypted` (BOOLEAN DEFAULT FALSE)
      - `signature` (TEXT)
      - `created_at` (REAL NOT NULL) — UNIX timestamp
      - `read_at` (REAL) — UNIX timestamp
      - `expires_at` (REAL NOT NULL)
      - `is_deleted` (BOOLEAN DEFAULT FALSE)
    - `sessions`: Tracks active user sessions.
      - `id` (INTEGER PRIMARY KEY)
      - `user_id` (INTEGER NOT NULL)
      - `session_token` (TEXT NOT NULL)
      - `created_at` (REAL NOT NULL)
      - `last_active` (REAL)
      - `expires_at` (REAL)
      - `ip_address` (TEXT)
      - `is_active` (BOOLEAN DEFAULT TRUE)
    - `friends`: Friend relationships and status.
      - `id` (INTEGER PRIMARY KEY)
      - `user_id` (INTEGER NOT NULL)
      - `friend_id` (INTEGER NOT NULL)
      - `status` (TEXT NOT NULL)
      - `requested_at` (REAL)
      - `accepted_at` (REAL)
      - `is_online` (BOOLEAN DEFAULT FALSE)
    - `server_information`: Server and DB versioning, stats.
      - `id` (INTEGER PRIMARY KEY)
      - `server_version` (TEXT)
      - `database_version` (TEXT)
      - `certificate_file` (TEXT)
      - `private_key` (TEXT)
      - `connections_today` (INTEGER DEFAULT 0)
      - `connections_all` (INTEGER DEFAULT 0)

  **Schema Evolution:**
    - Both server and client auto-migrate schemas on startup if needed.
    - For schema changes, update the relevant `database_manager.py` and migration logic.

  **Inspection:**
    - Use `view_database.py` in both `server/` and `client/` to inspect, debug, or summarize the database contents.

## 8.Server Message Processing
  - **Async/Await:** All DB and network operations are async. Use `asyncio` patterns throughout.
  - **Networking Protocol:** 
      Client to Server messages are parsed and handled in `process_message` in (`client/client.pt`)
      Server to Client messages are parsed and handled in `process_message` in (`server/server.pt`)
      It expects each message to be a JSON string matching the protocol envelope (see Networking Protocol section).
    - Client: See (`CLIENT_NETWORK.md`)[CLIENT_NETWORK.md`] and 
    - Server: See (`SERVER_NETWORK.md`)[SERVER_NETWORK.md`]
  - **Database:** Use `DatabaseManager` for all DB access. Avoid raw SQL outside this class.
  - **Admin Console:** Extend `ServerConsole` in `server.py` for new admin commands.
  - **Room/User Model:** See `@dataclass` definitions in `server.py` for `User`, `Room`, `Message`.
  - **Configuration:** All runtime settings in `data/config.json`. SSL cert/key paths are relative to `data/`.
  - **Security:** All messages are encrypted and signed. Use helpers in `crypto_utils.py`.
  - **Key Management:** Client keys in `client_keys/`, server keys in `data/`.
  - **Error Handling:** Print user-friendly errors, log details to file.

## 9.Networking Protocol  
  - **Client Network And Protocol Information**
    SafeMessenger uses a custom, end-to-end encrypted protocol over WebSockets (optionally SSL/TLS). All messages are JSON objects, encrypted and signed, with a handshake and session key exchange. The protocol covers:
    For full details, See [`NETWORK_PROTOCOL.md`](NETWORK_PROTOCOL.md).



## 10.Integration & Extension
  - **Add admin commands:** Extend `ServerConsole` in `server.py` with new `cmd_<name>` methods.
  - **Database schema changes:** Update `database_manager.py` and, if needed, `SQLite.sql` for migrations.
  - **Add client features:** Extend `client.py` and update the interactive shell. For new DB fields, update `database_manager.py` and migration logic. For cryptographic features, extend `CryptoHandler` in `crypto_handler.py`.
  - **External dependencies:** List in `requirements.txt` and install via the provided venv.

## 11.Examples
  - **Admin DB command:**
    ```
    db dump table users
    db insert table users {"username": "test"}
    db update table users {"active": true} {"WHERE_id": 1}
    ```
  - **Room join/leave:** See `handle_join_room` and `handle_leave_room` in `SecureChatServer` (`server.py`).
  - **Add a friend (client):** Use `DatabaseManager.add_friend()` (see `client/database_manager.py`).
  - **Encrypt a message:** Use `CryptoHandler` methods (see `crypto_handler.py`).

## 12.References
  - For admin/database command examples, see `ServerConsole.cmd_help` in `server/server.py`.
  - For database debug/summary, see `DatabaseManager.debug_print_all_tables` and `debug_table_summary`.
  - For short-term dev tasks, see `TODO.txt` in both `client/` and `server/`.

---