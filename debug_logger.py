#!/usr/bin/env python3
"""
Debug Log Redirector
Redirects debug messages to a separate terminal window
"""

import os
import sys
import logging
import time
import threading
from pathlib import Path
from datetime import datetime

class TerminalLogHandler(logging.Handler):
    """Custom logging handler that writes to a separate terminal"""
    
    def __init__(self, terminal_command="gnome-terminal", log_file=None):
        super().__init__()
        self.terminal_command = terminal_command
        self.log_file = log_file or f"/tmp/debug_log_{int(time.time())}.log"
        self.fifo_path = f"/tmp/debug_fifo_{int(time.time())}"
        self.terminal_process = None
        self.setup_terminal()
    
    def setup_terminal(self):
        """Set up the separate terminal window for debug output"""
        try:
            # Create a named pipe (FIFO) for real-time log streaming
            if not os.path.exists(self.fifo_path):
                os.mkfifo(self.fifo_path)
            
            # Command to open terminal and tail the log file
            if self.terminal_command == "gnome-terminal":
                cmd = f'gnome-terminal --title="🐛 Debug Log" --geometry=120x30 -- bash -c "echo \'🐛 Debug Log Stream - {datetime.now()}\'; echo \'─────────────────────────────────────────\'; tail -f {self.fifo_path}"'
            elif self.terminal_command == "xterm":
                cmd = f'xterm -title "Debug Log" -geometry 120x30 -e "tail -f {self.fifo_path}"'
            elif self.terminal_command == "konsole":
                cmd = f'konsole --title "Debug Log" -e "tail -f {self.fifo_path}"'
            else:
                # Fallback - just log to file
                print(f"⚠️  Unknown terminal: {self.terminal_command}, logging to file only")
                return
            
            # Start the terminal in background
            os.system(f"{cmd} &")
            
            # Open the FIFO for writing
            self.fifo_fd = os.open(self.fifo_path, os.O_WRONLY | os.O_NONBLOCK)
            
            print(f"✅ Debug terminal opened, logging to: {self.fifo_path}")
            
        except Exception as e:
            print(f"❌ Failed to setup debug terminal: {e}")
            self.fifo_fd = None
    
    def emit(self, record):
        """Emit a log record to the terminal"""
        try:
            if self.fifo_fd:
                msg = self.format(record)
                timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
                formatted_msg = f"[{timestamp}] {msg}\n"
                
                try:
                    os.write(self.fifo_fd, formatted_msg.encode())
                except (OSError, BrokenPipeError):
                    # Terminal might be closed, disable handler
                    self.close()
        except Exception as e:
            # Don't let logging errors crash the application
            pass
    
    def close(self):
        """Clean up resources"""
        if hasattr(self, 'fifo_fd') and self.fifo_fd:
            try:
                os.close(self.fifo_fd)
            except:
                pass
            self.fifo_fd = None
        
        if os.path.exists(self.fifo_path):
            try:
                os.unlink(self.fifo_path)
            except:
                pass
        
        super().close()

def setup_debug_logging(logger_name="server", terminal="auto", level=logging.DEBUG):
    """
    Set up debug logging to a separate terminal
    
    Args:
        logger_name: Name of the logger to configure
        terminal: Terminal program to use ("auto", "gnome-terminal", "xterm", "konsole")
        level: Logging level
    """
    
    # Auto-detect terminal if requested
    if terminal == "auto":
        if os.environ.get("DESKTOP_SESSION") == "gnome" or "gnome" in os.environ.get("XDG_CURRENT_DESKTOP", "").lower():
            terminal = "gnome-terminal"
        elif os.environ.get("DESKTOP_SESSION") == "kde" or "kde" in os.environ.get("XDG_CURRENT_DESKTOP", "").lower():
            terminal = "konsole"
        else:
            terminal = "xterm"
    
    # Get or create logger
    logger = logging.getLogger(logger_name)
    
    # Create debug handler for separate terminal
    debug_handler = TerminalLogHandler(terminal_command=terminal)
    debug_handler.setLevel(level)
    
    # Create formatter for debug messages
    debug_formatter = logging.Formatter(
        '%(levelname)-8s [%(name)s] %(funcName)s:%(lineno)d - %(message)s'
    )
    debug_handler.setFormatter(debug_formatter)
    
    # Add handler to logger
    logger.addHandler(debug_handler)
    logger.setLevel(level)
    
    print(f"🐛 Debug logging setup complete for '{logger_name}' logger")
    return debug_handler

def main():
    """Test the debug logging setup"""
    print("Testing debug log redirector...")
    
    # Setup debug logging
    handler = setup_debug_logging("test_logger")
    
    # Get logger and test it
    logger = logging.getLogger("test_logger")
    
    print("Sending test messages to debug terminal...")
    
    for i in range(10):
        logger.debug(f"Debug message {i+1}")
        logger.info(f"Info message {i+1}")
        logger.warning(f"Warning message {i+1}")
        logger.error(f"Error message {i+1}")
        time.sleep(1)
    
    print("Test complete. Close the debug terminal when done.")
    input("Press Enter to exit and cleanup...")
    
    handler.close()

if __name__ == "__main__":
    main()
