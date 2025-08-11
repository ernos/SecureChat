#!/usr/bin/env python3
"""
Debug Setup Script for Secure Messenger
Helps verify the environment is ready for debugging
"""

import sys
import os
import subprocess
from pathlib import Path

def check_python_environment():
    """Check if Python environment is properly set up"""
    print("🐍 Checking Python Environment...")
    
    venv_path = Path(".venv")
    if not venv_path.exists():
        print("❌ Virtual environment not found at .venv/")
        return False
    
    python_executable = venv_path / "bin" / "python"
    if not python_executable.exists():
        print("❌ Python executable not found in virtual environment")
        return False
    
    print(f"✅ Virtual environment found: {venv_path}")
    print(f"✅ Python executable: {python_executable}")
    
    # Check Python version
    try:
        result = subprocess.run([str(python_executable), "--version"], 
                              capture_output=True, text=True)
        print(f"✅ Python version: {result.stdout.strip()}")
    except Exception as e:
        print(f"❌ Error checking Python version: {e}")
        return False
    
    return True

def check_required_packages():
    """Check if required packages are installed"""
    print("\n📦 Checking Required Packages...")
    
    python_executable = Path(".venv/bin/python")
    required_packages = [
        "websockets",
        "cryptography", 
        "asyncio",
        "debugpy"
    ]
    
    missing_packages = []
    
    for package in required_packages:
        try:
            result = subprocess.run([str(python_executable), "-c", f"import {package}"], 
                                  capture_output=True, text=True)
            if result.returncode == 0:
                print(f"✅ {package}")
            else:
                print(f"❌ {package}")
                missing_packages.append(package)
        except Exception as e:
            print(f"❌ {package} - Error: {e}")
            missing_packages.append(package)
    
    if missing_packages:
        print(f"\n🔧 Missing packages: {', '.join(missing_packages)}")
        print("Run: .venv/bin/python -m pip install -r server/requirements.txt")
        return False
    
    return True

def check_ssl_certificates():
    """Check if SSL certificates exist"""
    print("\n🔒 Checking SSL Certificates...")
    
    cert_paths = [
        "server.crt",
        "server.key", 
        "server/data/serv-certificate.crt",
        "server/data/serv-private.key"
    ]
    
    found_certs = []
    for cert_path in cert_paths:
        if Path(cert_path).exists():
            print(f"✅ Found: {cert_path}")
            found_certs.append(cert_path)
        else:
            print(f"⚠️  Missing: {cert_path}")
    
    if not found_certs:
        print("❌ No SSL certificates found!")
        print("The server will generate self-signed certificates on first run.")
        return False
    
    return True

def check_config_files():
    """Check if configuration files exist"""
    print("\n⚙️  Checking Configuration Files...")
    
    config_files = [
        "server/data/config.json",
        "client/data/config.json"
    ]
    
    all_exist = True
    for config_file in config_files:
        if Path(config_file).exists():
            print(f"✅ Found: {config_file}")
        else:
            print(f"❌ Missing: {config_file}")
            all_exist = False
    
    return all_exist

def check_debug_configuration():
    """Check if VS Code debug configuration exists"""
    print("\n🐛 Checking Debug Configuration...")
    
    launch_json = Path(".vscode/launch.json")
    if launch_json.exists():
        print(f"✅ Found: {launch_json}")
        return True
    else:
        print(f"❌ Missing: {launch_json}")
        return False

def print_debug_instructions():
    """Print instructions for debugging"""
    print("\n🚀 Debug Instructions:")
    print("1. Open VS Code in this workspace")
    print("2. Go to Run and Debug view (Ctrl+Shift+D)")
    print("3. Select '🖥️ Debug Server' from the dropdown")
    print("4. Click the green play button to start the server")
    print("5. Wait for server to start, then select '👤 Debug Client (pebnop)'")
    print("6. Click the green play button to start the client")
    print("7. Or use '🚀 Debug Server + Client' compound configuration")
    print("\n💡 Tips:")
    print("- Set breakpoints by clicking in the gutter next to line numbers")
    print("- Use F10 to step over, F11 to step into, F5 to continue")
    print("- Check the Debug Console for output and to evaluate expressions")

def main():
    print("🔍 Secure Messenger Debug Setup Check")
    print("=" * 50)
    
    checks = [
        check_python_environment(),
        check_required_packages(),
        check_ssl_certificates(),
        check_config_files(),
        check_debug_configuration()
    ]
    
    print("\n" + "=" * 50)
    
    if all(checks):
        print("✅ All checks passed! Ready for debugging.")
        print_debug_instructions()
    else:
        print("❌ Some checks failed. Please fix the issues above before debugging.")
        
        print("\n🔧 Quick Fix Commands:")
        print("# Install missing packages:")
        print(".venv/bin/python -m pip install -r server/requirements.txt")
        print(".venv/bin/python -m pip install debugpy")
        
        print("\n# Start server manually to generate certificates:")
        print(".venv/bin/python server/server.py")

if __name__ == "__main__":
    main()
