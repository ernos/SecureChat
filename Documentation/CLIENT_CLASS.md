# CLIENT_CLASS.md

This document references all functions defined in `client/client.py` for the SafeMessenger client.

---

## Function Reference

### Utility Functions
- `prompt(message: str = "", *, default: str = "") -> str`

### Client Class Methods
- `__init__(self, config_file: str = "config.json")`
- `initialize_keys(self)`
- `generate_keys(self)`
- `save_keys(self)`
- `load_config(self, file=config_file) -> Dict[str, Any]`
- `create_default_config(self, config_file: str)`
- `log(self, message: str)`
- `ensure_connected(self)`
- `ensure_private_key(self)`
- `async send_message(self, message: Dict[str, Any])`
- `async connect(self, listen: bool = True, ssl_cert_path = SERVER_CERT_FILE)`
- `async register_or_login(self)`
- `async login(self)`
- `async handle_server_info(self, server_info: Dict[str, Any])`
- `async handle_ping(self, ping_message: Dict[str, Any])`
- `async register(self)`
- `async listen_for_messages(self)`
- `async handle_message(self, message: Dict[str, Any]) -> str`
- `encrypt_message(self, message: str, recipient_public_key: Any) -> str`
- `decrypt_message(self, encrypted_message: str) -> str`
- `async get_unread_messages(self)`
- `async send_public_message(self, content: str)`
- `async send_private_message(self, recipient: str, content: str, encrypt: Optional[bool] = None)`
- `async send_friend_request(self, friend_username: str)`
- `async accept_friend_request(self, friend_username: str)`
- `async decline_friend_request(self, friend_username: str)`
- `async get_friends_list(self)`
- `async get_friend_requests(self)`
- `async remove_friend(self, friend_username: str)`
- `async disconnect(self)`

### Top-level Async Functions
- `async interactive_shell(client)`
- `async main()`

---

For details on each function, see the implementation in `client/client.py`.
