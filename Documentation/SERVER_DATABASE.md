# SERVER_DATABASE_HANDLING.md

This document describes the server database table structures, data manipulation, first initial setup, reading and schema and manipulation functions for both server and client components of SafeMessenger.
---

## Server Database File ( `data/server_database.db` )

  See 

### Tables

* **users**: Stores user credentials, public keys, and metadata.
  + `id` (PK),  `username` (unique),  `password_hash`,  `public_key`,  `salt`,  `created_at`,  `last_active`,  `total_messages_received`,  `unread_messages`,  `auto_delete_hours`,  `is_online`,  `accepts_unknown_friend_requests`,  `accepts_unknown_messages`,  `accepts_unknown_invites_to_chatrooms`
* **messages**: Stores all messages (public/private).
  + `id` (PK),  `sender_id`,  `recipient_id`,  `room_name`,  `content`,  `message_type`,  `encrypted`,  `signature`,  `created_at`,  `read_at`,  `expires_at`,  `is_deleted`
* **sessions**: Tracks active user sessions.
  + `id` (PK),  `user_id`,  `session_token`,  `created_at`,  `last_active`,  `expires_at`,  `ip_address`,  `is_active`
* **friends**: Friend relationships and status.
  + `id` (PK),  `user_id`,  `friend_id`,  `status`,  `requested_at`,  `accepted_at`,  `is_online`
* **server_information**: Server and DB versioning, stats.
  + `id` (PK),  `server_version`,  `database_version`,  `certificate_file`,  `private_key`,  `connections_today`,  `connections_all`

## Server Database Management ( `server/database_manager.py` )

### Key Functions
* `initialize()`: Connect and create tables if needed.
* `register_user(username, password, public_key)`: Register a new user (with password hashing and salt).
* `authenticate_user(username, password)`: Validate credentials and return user info.
* `get_user_by_username(username)`: Fetch user details.
* `store_message(sender_id, recipient_id, room_name, content, ...)`: Store a message (with expiry, encryption, signature).
* `mark_message_read(message_id, user_id)`: Mark a message as read and update expiration.
* `get_unread_messages(user_id)`: List unread messages for a user.
* `cleanup_expired_messages()`: Remove expired messages.
* `get_user_stats(user_id)`: Return user statistics.
* `update_auto_delete_setting(user_id, hours)`: Change message expiry for a user.
* `debug_print_all_tables()`,  `debug_table_summary()`: Print all tables/rows or summary.
* **Friend Management:**
  + `send_friend_request(user_id, friend_username)`,  `accept_friend_request(user_id, friend_username)`,  `decline_friend_request(user_id, friend_username)`,  `remove_friend(user_id, friend_username)`,  `get_friends_list(user_id)`,  `get_friend_requests(user_id)`,  `are_friends(user_id, other_user_id)`,  `is_friend_request_pending(user_id, other_friend_id)`
* `get_user_id_by_username(username)`: Get user ID from username.

---

For further details, see the implementation in `server/database_manager.py` and `client/database_manager.py` .
