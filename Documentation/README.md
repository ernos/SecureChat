
# SecureMessaging Project - Shared Virtual Environment

This project uses a shared virtual environment for both the server and client components.

## 🏗️ Project Structure

```
SecureMessaging/
├── venv/                    # Shared virtual environment
├── requirements.txt         # Shared dependencies
├── activate_env.sh         # Environment activation script
├── server/
│   ├── server.py
│   └── data/
└── client/
    ├── client.py
    └── data/
```

## 🚀 Quick Start

### 1. Activate the Virtual Environment

**Option A: Use the convenience script**
```bash
./activate_env.sh
```

**Option B: Manual activation**
```bash
source venv/bin/activate
```

### 2. Run the Applications

**Start the Server:**
```bash
cd server
python server.py
```

**Start the Client:**
```bash
cd client
python client.py
```

### 3. Deactivate When Done
```bash
deactivate
```

## 📦 Installed Packages

The shared environment includes these packages:
- `cryptography` - For encryption/decryption operations
- `websockets` - For WebSocket communication
- `pycryptodome` - Additional cryptographic utilities
- `aiofiles` - Asynchronous file operations
- `aiosqlite` - Asynchronous SQLite operations
- `bcrypt` - Password hashing

## 🔧 Managing Dependencies

### Adding New Dependencies
1. Add the package to `requirements.txt`
2. Install it: `pip install -r requirements.txt`

### Updating Dependencies
```bash
pip install --upgrade -r requirements.txt
```

### Viewing Installed Packages
```bash
pip list
```

## 💡 Development Tips

1. **Always activate the environment** before running either server or client
2. **Install new packages to requirements.txt** to keep dependencies synchronized
3. **Both server and client** share the same environment and dependencies
4. **Use absolute imports** when creating shared modules between server/client

## 🐛 Troubleshooting

### Virtual Environment Not Found
If you get "venv not found" errors:
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Missing Dependencies
If you get import errors:
```bash
source venv/bin/activate
pip install -r requirements.txt
```

### Permission Issues
Make sure the activation script is executable:
```bash
chmod +x activate_env.sh
```
