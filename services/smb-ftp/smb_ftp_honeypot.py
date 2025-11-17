#!/usr/bin/env python3
"""
SMB/FTP Honeypot Service
Simulates SMB and FTP servers to capture attacker interactions.
"""

import os
import json
import logging
import time
import socket
import threading
from datetime import datetime
from pathlib import Path

try:
    from pyftpdlib.authorizers import DummyAuthorizer
    from pyftpdlib.handlers import FTPHandler
    from pyftpdlib.servers import FTPServer
except ImportError:
    print("Error: pyftpdlib not installed. Run: pip install -r requirements.txt")
    import sys
    sys.exit(1)

# Setup logging
log_dir = Path("/var/log/honeypot")
log_dir.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(log_dir / "smb_ftp_honeypot.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Session storage
sessions_dir = Path("/sessions")
sessions_dir.mkdir(parents=True, exist_ok=True)


class SessionTracker:
    """Tracks FTP/SMB sessions"""
    
    def __init__(self, session_id, client_ip, protocol):
        self.session_id = session_id
        self.client_ip = client_ip
        self.protocol = protocol
        self.start_time = datetime.now()
        self.commands = []
        self.login_attempts = []
        
    def log_command(self, command, args=''):
        """Log a command"""
        self.commands.append({
            'timestamp': datetime.now().isoformat(),
            'command': command,
            'args': args
        })
        logger.info(f"Session {self.session_id}: {command} {args}")
        
    def log_login_attempt(self, username, password, success=False):
        """Log a login attempt"""
        self.login_attempts.append({
            'timestamp': datetime.now().isoformat(),
            'username': username,
            'password': password,
            'success': success
        })
        logger.warning(f"Session {self.session_id}: Login - user: {username}, success: {success}")
        
    def to_dict(self):
        """Convert session to dictionary"""
        return {
            'session_id': self.session_id,
            'client_ip': self.client_ip,
            'protocol': self.protocol,
            'start_time': self.start_time.isoformat(),
            'end_time': datetime.now().isoformat(),
            'commands': self.commands,
            'login_attempts': self.login_attempts
        }


class HoneypotFTPHandler(FTPHandler):
    """FTP handler that logs all interactions"""
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.session = None
        
    def on_connect(self):
        """Called when client connects"""
        session_counter = int(time.time() * 1000)
        session_id = f"ftp_{session_counter}_{self.remote_ip}"
        self.session = SessionTracker(session_id, self.remote_ip, 'ftp')
        logger.info(f"New FTP connection from {self.remote_ip}, session ID: {session_id}")
        
    def on_disconnect(self):
        """Called when client disconnects"""
        if self.session:
            self._save_session()
            
    def on_login(self, username, password):
        """Called on login attempt"""
        if self.session:
            self.session.log_login_attempt(username, password, success=True)
        logger.warning(f"FTP login: username={username}, password={password}")
        return True  # Always accept
        
    def on_file_received(self, file):
        """Called when file is uploaded"""
        if self.session:
            self.session.log_command('STOR', file)
        logger.warning(f"File upload attempt: {file}")
        
    def on_file_sent(self, file):
        """Called when file is downloaded"""
        if self.session:
            self.session.log_command('RETR', file)
        logger.warning(f"File download attempt: {file}")
        
    def ftp_DELE(self, path):
        """Handle DELETE command"""
        if self.session:
            self.session.log_command('DELE', path)
        logger.warning(f"Delete attempt: {path}")
        return "550 Permission denied"
        
    def ftp_RMD(self, path):
        """Handle RMDIR command"""
        if self.session:
            self.session.log_command('RMD', path)
        logger.warning(f"RMDIR attempt: {path}")
        return "550 Permission denied"
        
    def _save_session(self):
        """Save session data"""
        if not self.session:
            return
        session_file = sessions_dir / f"ftp_session_{self.session.session_id}.json"
        try:
            with open(session_file, 'w') as f:
                json.dump(self.session.to_dict(), f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save session: {e}")


class FTPHoneypot:
    """FTP honeypot server"""
    
    def __init__(self, port=21):
        self.port = port
        
    def start(self):
        """Start FTP honeypot"""
        # Create authorizer that accepts all logins
        authorizer = DummyAuthorizer()
        authorizer.add_user("admin", "password", "/tmp", perm="elradfmw")
        authorizer.add_anonymous("/tmp", perm="elr")
        
        # Create handler
        handler = HoneypotFTPHandler
        handler.authorizer = authorizer
        handler.banner = "220 Welcome to FTP Server"
        
        # Create server
        server = FTPServer(("0.0.0.0", self.port), handler)
        server.max_cons = 256
        server.max_cons_per_ip = 5
        
        logger.info(f"FTP Honeypot listening on port {self.port}")
        server.serve_forever()


class SMBHoneypot:
    """SMB protocol honeypot"""
    
    def __init__(self, port=445):
        self.port = port
        self.sessions = {}
        
    def handle_client(self, client_sock, addr):
        """Handle SMB client connection"""
        session_counter = int(time.time() * 1000)
        session_id = f"smb_{session_counter}_{addr[0]}"
        client_ip = addr[0]
        
        session = SessionTracker(session_id, client_ip, 'smb')
        self.sessions[session_id] = session
        
        logger.info(f"New SMB connection from {client_ip}, session ID: {session_id}")
        
        try:
            # SMB protocol negotiation
            # Read negotiation request
            data = client_sock.recv(4096)
            if data:
                logger.info(f"Session {session_id}: Received {len(data)} bytes")
                
                # Send SMB negotiation response
                # SMB2/3 negotiation response (simplified)
                response = b'\x00\x00\x00\x90'  # NetBIOS session header
                response += b'\xfeSMB'  # SMB2 signature
                response += b'\x00' * 60  # Header
                response += b'\x01\x00'  # Dialect
                response += b'\x00' * 100  # Padding
                
                client_sock.send(response)
                
                # Read session setup
                data = client_sock.recv(4096)
                if data:
                    # Try to extract authentication info
                    auth_data = data.decode('utf-8', errors='ignore')[:200]
                    session.log_command('SESSION_SETUP', auth_data)
                    
                    # Send session setup response (success)
                    setup_response = b'\x00\x00\x00\x40'
                    setup_response += b'\xfeSMB'
                    setup_response += b'\x00' * 50
                    client_sock.send(setup_response)
                    
                    # Continue reading commands
                    while True:
                        data = client_sock.recv(4096)
                        if not data:
                            break
                        cmd_data = data.decode('utf-8', errors='ignore')[:200]
                        session.log_command('SMB_COMMAND', cmd_data)
                        
        except Exception as e:
            logger.error(f"Error handling SMB client: {e}")
        finally:
            self._save_session(session)
            client_sock.close()
            
    def _save_session(self, session):
        """Save session data"""
        session_file = sessions_dir / f"smb_session_{session.session_id}.json"
        try:
            with open(session_file, 'w') as f:
                json.dump(session.to_dict(), f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save session: {e}")
            
    def start(self):
        """Start SMB honeypot"""
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind(('0.0.0.0', self.port))
        server_socket.listen(100)
        
        logger.info(f"SMB Honeypot listening on port {self.port}")
        
        while True:
            try:
                client_sock, addr = server_socket.accept()
                client_thread = threading.Thread(
                    target=self.handle_client,
                    args=(client_sock, addr),
                    daemon=True
                )
                client_thread.start()
            except Exception as e:
                logger.error(f"Error accepting connection: {e}")


def main():
    """Main entry point"""
    smb_port = int(os.getenv('SMB_PORT', 445))
    ftp_port = int(os.getenv('FTP_PORT', 21))
    
    logger.info("Starting SMB/FTP Honeypot")
    
    # Start SMB honeypot
    smb_honeypot = SMBHoneypot(smb_port)
    smb_thread = threading.Thread(target=smb_honeypot.start, daemon=True)
    smb_thread.start()
    
    # Start FTP honeypot
    ftp_honeypot = FTPHoneypot(ftp_port)
    ftp_thread = threading.Thread(target=ftp_honeypot.start, daemon=True)
    ftp_thread.start()
    
    # Keep main thread alive
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Shutting down SMB/FTP Honeypot")


if __name__ == '__main__':
    main()


