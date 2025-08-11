#!/usr/bin/env python3
"""
Debug Terminal Logger
Redirects debug output to a separate terminal window for easier monitoring
"""

import os
import sys
import time
import subprocess
import logging
from pathlib import Path
from typing import Optional, TextIO
import threading
import queue

class DebugTerminalLogger:
    """Logger that pipes debug output to a separate terminal window"""
    
    def __init__(self, log_name: str = "SecureMessenger-Debug"):
        self.log_name = log_name
        self.debug_process: Optional[subprocess.Popen] = None
        self.debug_pipe: Optional[TextIO] = None
        self.message_queue = queue.Queue()
        self.running = False
        self.worker_thread: Optional[threading.Thread] = None
        
    def start_debug_terminal(self) -> bool:
        """Start a separate terminal window for debug output"""
        try:
            # Create a named pipe for communication
            pipe_path = f"/tmp/safemessenger_debug_{os.getpid()}"
            
            # Try different terminal emulators
            terminal_commands = [
                ["gnome-terminal", "--", "tail", "-f", pipe_path],
                ["xterm", "-e", "tail", "-f", pipe_path],
                ["konsole", "-e", "tail", "-f", pipe_path],
                ["terminator", "-e", f"tail -f {pipe_path}"],
                ["alacritty", "-e", "tail", "-f", pipe_path]
            ]
            
            # Create named pipe
            if os.path.exists(pipe_path):
                os.unlink(pipe_path)
            os.mkfifo(pipe_path)
            
            # Try to open a terminal
            for cmd in terminal_commands:
                try:
                    self.debug_process = subprocess.Popen(
                        cmd,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL
                    )
                    # Give the terminal time to start
                    time.sleep(0.5)
                    
                    # Test if the terminal is running
                    if self.debug_process.poll() is None:
                        print(f"✅ Debug terminal started with: {' '.join(cmd)}")
                        break
                    else:
                        self.debug_process = None
                except (subprocess.SubprocessError, FileNotFoundError):
                    continue
            
            if self.debug_process is None:
                print("⚠️  Could not start debug terminal, falling back to file logging")
                # Fallback to file
                debug_file = Path("logs") / f"debug_{int(time.time())}.log"
                debug_file.parent.mkdir(exist_ok=True)
                pipe_path = str(debug_file)
            
            # Open the pipe for writing
            self.debug_pipe = open(pipe_path, 'w')
            
            # Start worker thread
            self.running = True
            self.worker_thread = threading.Thread(target=self._worker, daemon=True)
            self.worker_thread.start()
            
            return True
            
        except Exception as e:
            print(f"❌ Failed to start debug terminal: {e}")
            return False
    
    def _worker(self):
        """Worker thread that writes messages to the debug terminal"""
        while self.running:
            try:
                # Get message with timeout
                message = self.message_queue.get(timeout=1.0)
                if message is None:  # Shutdown signal
                    break
                
                if self.debug_pipe:
                    self.debug_pipe.write(message)
                    self.debug_pipe.flush()
                    
            except queue.Empty:
                continue
            except Exception as e:
                print(f"Debug logger error: {e}")
                break
    
    def log(self, level: str, message: str, source: str = "SERVER"):
        """Send a log message to the debug terminal"""
        if not self.running:
            return
            
        timestamp = time.strftime("%H:%M:%S")
        formatted_message = f"[{timestamp}] [{level:>5}] [{source:>8}] {message}\n"
        
        try:
            self.message_queue.put(formatted_message, timeout=0.1)
        except queue.Full:
            pass  # Drop message if queue is full
    
    def debug(self, message: str, source: str = "SERVER"):
        """Log a debug message"""
        self.log("DEBUG", message, source)
    
    def info(self, message: str, source: str = "SERVER"):
        """Log an info message"""
        self.log("INFO", message, source)
    
    def warning(self, message: str, source: str = "SERVER"):
        """Log a warning message"""
        self.log("WARN", message, source)
    
    def error(self, message: str, source: str = "SERVER"):
        """Log an error message"""
        self.log("ERROR", message, source)
    
    def critical(self, message: str, source: str = "SERVER"):
        """Log a critical message"""
        self.log("CRIT", message, source)
    
    def stop(self):
        """Stop the debug terminal logger"""
        self.running = False
        
        # Signal worker to stop
        try:
            self.message_queue.put(None, timeout=0.1)
        except queue.Full:
            pass
        
        # Wait for worker to finish
        if self.worker_thread:
            self.worker_thread.join(timeout=2.0)
        
        # Close pipe
        if self.debug_pipe:
            self.debug_pipe.close()
        
        # Terminate debug terminal
        if self.debug_process:
            self.debug_process.terminate()
            try:
                self.debug_process.wait(timeout=2.0)
            except subprocess.TimeoutExpired:
                self.debug_process.kill()

# Custom logging handler that sends to debug terminal
class DebugTerminalHandler(logging.Handler):
    """Custom logging handler that sends logs to debug terminal"""
    
    def __init__(self, debug_logger: DebugTerminalLogger):
        super().__init__()
        self.debug_logger = debug_logger
    
    def emit(self, record):
        """Emit a log record to the debug terminal"""
        try:
            message = self.format(record)
            level = record.levelname
            source = record.name if hasattr(record, 'name') else "UNKNOWN"
            
            self.debug_logger.log(level, message, source)
        except Exception:
            pass  # Silently ignore errors in debug logging

def setup_debug_logging(enable_debug_terminal: bool = True) -> Optional[DebugTerminalLogger]:
    """Set up debug logging with optional separate terminal"""
    debug_logger = None
    
    if enable_debug_terminal and os.getenv('DEBUG_TERMINAL', '').lower() == 'true':
        debug_logger = DebugTerminalLogger()
        if debug_logger.start_debug_terminal():
            # Add custom handler to root logger
            root_logger = logging.getLogger()
            debug_handler = DebugTerminalHandler(debug_logger)
            debug_handler.setFormatter(
                logging.Formatter('%(name)s - %(message)s')
            )
            root_logger.addHandler(debug_handler)
            
            debug_logger.info("Debug terminal logging started", "SYSTEM")
        else:
            debug_logger = None
    
    return debug_logger

if __name__ == "__main__":
    # Test the debug terminal logger
    print("Testing Debug Terminal Logger...")
    
    debug_logger = DebugTerminalLogger()
    if debug_logger.start_debug_terminal():
        print("Debug terminal started successfully!")
        
        # Send test messages
        debug_logger.info("Debug terminal logger started")
        debug_logger.debug("This is a debug message")
        debug_logger.warning("This is a warning message")
        debug_logger.error("This is an error message")
        
        input("Press Enter to stop...")
        debug_logger.stop()
    else:
        print("Failed to start debug terminal")
