# SafeMessenger Networking Protocol

 This document describes the wire protocol for communication between SafeMessenger clients and the server. It covers message formats, authentication, encryption, command structure, and error handling for both directions (client→server and server→client).
 ---

 ## 1. Transport Layer
 - **Protocol:** WebSocket (optionally over SSL/TLS)
 - **Port:** Configurable in `data/config.json` (default: 8765)
 - **Encoding:** All messages are UTF-8 encoded JSON objects
 - **Encryption:**
  - All payloads are encrypted end-to-end (see below)
  - Initial handshake uses RSA public key exchange
  - Subsequent messages use AES session keys

 ## 2. Authentication & Key Exchange
  1. **Client connects** to server WebSocket endpoint
  2. **Server sends** its public key (PEM format)
  3. **Client generates** ephemeral AES session key, encrypts it with server's public key, and sends it
  4. **Server decrypts** AES key and uses it for all further communication with this client
  5. **User authentication** (register/login) is performed over the encrypted channel

 ## 3. Message Envelope
  All application messages are JSON objects with the following structure:

  ```json
  {
    "type": "<command|event|response|error>",
    "action": "<action_name>",
    "payload": { ... },
    "nonce": "<unique_id>",
    "signature": "<base64>" // HMAC or RSA signature
  }
  ```

  - **type:**
   - `command`: Client→Server request
   - `event`: Server→Client push (e.g., new message, user joined)
   - `response`: Server→Client reply to a command
   - `error`: Error response
   - **action:** Name of the command/event (see below)
   - **payload:** Command-specific data (see examples)
   - **nonce:** Unique per-message identifier for replay protection
   - **signature:** Digital signature of the message (see crypto section)


 ## 4. Common Actions

  ### Client → Server

   - `register`: Create new user. 
    - payload: payload: `{ "username": str, "password": str, "public_key": str }`
   - `login`: Authenticate user
   - payload: `{ "username": str, "password": str }`
   - `public_message`: Send a public message to the current room
   - payload: `{ "content": str }`
   - `private_message`: Send a private message to another user
   - payload: `{ "recipient": str, "content": str, "encrypted": bool, "signature": str }`
   - `join_room`: Join a chat room
   - payload: `{ "room_name": str }`
   - `leave_room`: Leave the current chat room
   - payload: `{}`
   - `get_users`: Get the list of users in the current room
   - payload: `{}`
   - `get_unread_messages`: Get unread messages for the user
   - payload: `{}`
   - `mark_message_read`: Mark a message as read
   - payload: `{ "message_id": int }`
   - `send_friend_request`: Send a friend request
   - payload: `{ "friend_username": str }`
   - `accept_friend_request`: Accept a friend request
   - payload: `{ "friend_username": str }`
   - `decline_friend_request`: Decline a friend request
   - payload: `{ "friend_username": str }`
   - `remove_friend`: Remove a friend
   - payload: `{ "friend_username": str }`
   - `get_friends_list`: Get the user's friends list
   - payload: `{}`
   - `get_friend_requests`: Get incoming friend requests
   - payload: `{}`
  - `PONG`: Respond to server ping
   - payload: `{ "timestamp": float }`
 ### Server → Client

 - `PING`: Server heartbeat, client must reply with `PONG`
   - payload: `{ "username": str, "timestamp": float }`
 - `registration_success`: Registration succeeded
   - payload: `{ "username": str, "user_id": int, "assigned_room": str, ... }`
 - `login_success`: Login succeeded
   - payload: `{ "username": str, "user_id": int, "assigned_room": str, ... }`
 - `user_joined`: User joined a room
   - payload: `{ "username": str }`
 - `user_left`: User left a room
   - payload: `{ "username": str }`
 - `public_message`: Public message in a room
   - payload: `{ "sender": str, "content": str, "room": str, "timestamp": float }`
 - `private_message`: Private message to user
   - payload: `{ "sender": str, "content": str, "encrypted": bool, ... }`
 - `unread_messages`: List of unread messages
   - payload: `{ "messages": [ ... ] }`
 - `friend_request_response`: Friend request sent/failed
   - payload: `{ "success": bool, "friend_username": str, "message": str }`
 - `friend_request_accept_response`: Friend request accepted/failed
   - payload: `{ "success": bool, "friend_username": str, "message": str }`
 - `friends_list`: List of friends
   - payload: `{ "friends": [ ... ] }`
 - `friend_requests`: List of incoming friend requests
   - payload: `{ "requests": [ ... ] }`
 - `message_delivered`: Confirmation of message delivery
   - payload: `{ "recipient": str, "online": bool, "timestamp": float }`
 - `error`: Error message
   - payload: `{ "message": str }`
 ---

 ## 5. Encryption & Signatures
 - **Handshake:** RSA public key exchange, then AES session key
 - **Message encryption:** All payloads are encrypted with AES (CBC or GCM)
 - **Signatures:** Each message is signed (HMAC with session key or RSA private key)
 - **Replay protection:** Use `nonce` and reject duplicates

For full details on encryption functions and usage, see [ENNCRYPTION.md](./ENNCRYPTION.md).
---

 ## 6. Error Handling
 - All errors are sent as messages with `type: "error"`
 - `payload` includes a numeric `code` and human-readable `message`
 - Common error codes:
 - 1001: Invalid credentials
 - 1002: Not authorized
 - 1003: Invalid command
 - 1004: Malformed payload
 - 1005: Internal server error
 ---

 ## 7. Example Message Flows

 ### Registration

 1. Client connects, performs handshake
 2. Client sends:
   

```json
   { "type": "command", "action": "register", "payload": { "username": "alice", "password": "..." }, "nonce": "...", "signature": "..." }
   ```

 3. Server replies:
   

```json
   { "type": "response", "action": "register", "payload": { "success": true }, "nonce": "...", "signature": "..." }
   ```

 ### Sending a Message

 1. Client sends:
   

```json
   { "type": "command", "action": "send_message", "payload": { "room": "general", "content": "Hello!", "expires_at": 1754899200 }, "nonce": "...", "signature": "..." }
   ```

 2. Server broadcasts to all room members:
   

```json
   { "type": "event", "action": "event_message", "payload": { "room": "general", "from": "alice", "content": "Hello!", "timestamp": 1754899200 }, "nonce": "...", "signature": "..." }
   ```

 ---

 ## 8. Notes
 - All timestamps are UNIX epoch seconds (UTC)
 - All sensitive fields (passwords, keys) are never logged
 - For full command/event list, see `server.py` and `client.py`
 - For cryptographic details, see `crypto_utils.py`
 ---

 ---

 ## 9. Server Message Processing

 All client messages are handled by the server's `process_message` function ( `server/server.py` ). This function:

 - Expects each message to be a JSON string matching the envelope described above
 - Parses and validates the structure
 - Dispatches to the appropriate handler based on `type` and `action` fields (e.g., registration, login, message send, room join/leave, friend management)
 - Handles errors (malformed JSON, missing fields, unknown actions) by sending a structured error response
 - All client commands must be routed through this function for authentication, validation, and logging
 See the [copilot instructions](.github/copilot-instructions.md) and `server/server.py` for canonical routing and error handling patterns.
