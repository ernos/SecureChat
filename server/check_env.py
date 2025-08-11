#!/usr/bin/env python3
"""
Environment check script for SafeMessenger Server
Verifies that all required dependencies are available
"""

import sys
import importlib
from pathlib import Path

def check_python_version():
    """Check if Python version is supported"""
    print(f"Python version: {sys.version}")
    if sys.version_info < (3, 8):
        print("❌ Python 3.8+ is required")
        return False
    print("✅ Python version is supported")
    return True

def check_module(module_name, friendly_name=None):
    """Check if a module can be imported"""
    if friendly_name is None:
        friendly_name = module_name
    
    try:
        importlib.import_module(module_name)
        print(f"✅ {friendly_name} is available")
        return True
    except ImportError:
        print(f"❌ {friendly_name} is not available")
        return False

def check_local_files():
    """Check if required local files exist"""
    files_to_check = [
        "server.py",
        "database_manager.py",
        "data/config.json"
    ]
    
    all_exist = True
    for file_path in files_to_check:
        if Path(file_path).exists():
            print(f"✅ {file_path} exists")
        else:
            print(f"❌ {file_path} is missing")
            all_exist = False
    
    return all_exist

def check_ssl_certificates():
    """Check if SSL certificates exist"""
    cert_files = [
        "data/serv-certificate.crt",
        "data/serv-private.key"
    ]
    
    all_exist = True
    for cert_file in cert_files:
        if Path(cert_file).exists():
            print(f"✅ {cert_file} exists")
        else:
            print(f"⚠️  {cert_file} is missing (will be auto-generated)")
            all_exist = False
    
    return all_exist

def main():
    """Main environment check"""
    print("🔍 SafeMessenger Server Environment Check")
    print("=" * 50)
    
    checks = [
        check_python_version(),
        check_module("asyncio"),
        check_module("websockets"),
        check_module("cryptography"),
        check_module("json"),
        check_module("ssl"),
        check_module("pathlib"),
        check_module("hashlib"),
        check_module("secrets"),
        check_local_files()
    ]
    
    print("\nSSL Certificate Check:")
    check_ssl_certificates()
    
    print("\n" + "=" * 50)
    if all(checks):
        print("✅ All required dependencies are available!")
        print("🚀 Server should be ready to run")
        return 0
    else:
        print("❌ Some dependencies are missing")
        print("📦 Run: pip install -r requirements.txt")
        return 1

if __name__ == "__main__":
    sys.exit(main())
