#!/usr/bin/env python3
"""
SSH Honeypot Service
Simulates an SSH server to capture attacker interactions.
"""

import os
import sys
import json
import logging
import time
import socket
import threading
from datetime import datetime
from pathlib import Path

try:
    import paramiko
    from paramiko import ServerInterface, OPEN_SUCCEEDED
    from paramiko.common import AUTH_SUCCESSFUL, AUTH_FAILED
except ImportError:
    print("Error: paramiko not installed. Run: pip install -r requirements.txt")
    sys.exit(1)

# Setup logging
log_dir = Path("/var/log/honeypot")
log_dir.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(log_dir / "ssh_honeypot.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Session storage
sessions_dir = Path("/sessions")
sessions_dir.mkdir(parents=True, exist_ok=True)


class HoneypotSession:
    """Tracks a single SSH session"""
    
    def __init__(self, session_id, client_ip):
        self.session_id = session_id
        self.client_ip = client_ip
        self.start_time = datetime.now()
        self.commands = []
        self.login_attempts = []
        self.logged_in = False
        self.username = None
        
    def log_command(self, command):
        """Log a command executed in the session"""
        self.commands.append({
            'timestamp': datetime.now().isoformat(),
            'command': command
        })
        logger.info(f"Session {self.session_id}: Command executed: {command}")
        
    def log_login_attempt(self, username, password, success=False):
        """Log a login attempt"""
        self.login_attempts.append({
            'timestamp': datetime.now().isoformat(),
            'username': username,
            'password': password,
            'success': success
        })
        logger.warning(f"Session {self.session_id}: Login attempt - user: {username}, success: {success}")
        
    def to_dict(self):
        """Convert session to dictionary for JSON export"""
        return {
            'session_id': self.session_id,
            'client_ip': self.client_ip,
            'start_time': self.start_time.isoformat(),
            'end_time': datetime.now().isoformat(),
            'logged_in': self.logged_in,
            'username': self.username,
            'commands': self.commands,
            'login_attempts': self.login_attempts
        }


class HoneypotSSHServer(ServerInterface):
    """SSH server that logs all interactions"""
    
    def __init__(self, session):
        self.session = session
        
    def check_auth_password(self, username, password):
        """Check password - always accept but log"""
        self.session.log_login_attempt(username, password, success=True)
        self.session.logged_in = True
        self.session.username = username
        logger.warning(f"Session {self.session.session_id}: Authentication accepted for {username}")
        return AUTH_SUCCESSFUL
        
    def check_auth_publickey(self, username, key):
        """Check public key auth - accept but log"""
        logger.info(f"Session {self.session.session_id}: Public key auth attempt for {username}")
        self.session.logged_in = True
        self.session.username = username
        return AUTH_SUCCESSFUL
        
    def check_channel_request(self, kind, chanid):
        """Check channel request"""
        if kind == 'session':
            return OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
        
    def get_allowed_auths(self, username):
        """Return allowed authentication methods"""
        return 'password,publickey'


class HoneypotChannelHandler:
    """Handles channel interactions"""
    
    def __init__(self, channel, session):
        self.channel = channel
        self.session = session
        
    def handle(self):
        """Handle channel interactions"""
        try:
            # Send welcome message
            welcome = "Welcome to the system.\n$ "
            self.channel.send(welcome)
            
            while True:
                if self.channel.recv_ready():
                    data = self.channel.recv(1024)
                    if not data:
                        break
                        
                    command = data.decode('utf-8', errors='ignore').strip()
                    if command:
                        self.session.log_command(command)
                        logger.info(f"Session {self.session.session_id}: Command: {command}")
                        
                        # Simulate command execution
                        if command.lower() in ['exit', 'quit', 'logout']:
                            self.channel.send("Goodbye.\n")
                            break
                        else:
                            # Fake command output
                            response = f"bash: {command}: command not found\n$ "
                            self.channel.send(response)
                            
        except Exception as e:
            logger.error(f"Error handling channel: {e}")
        finally:
            self._save_session()
            self.channel.close()
            
    def _save_session(self):
        """Save session data to file"""
        session_file = sessions_dir / f"ssh_session_{self.session.session_id}.json"
        try:
            with open(session_file, 'w') as f:
                json.dump(self.session.to_dict(), f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save session: {e}")


def handle_client(client_sock, addr):
    """Handle a new client connection"""
    session_counter = int(time.time() * 1000)
    session_id = f"{session_counter}_{addr[0]}"
    client_ip = addr[0]
    
    session = HoneypotSession(session_id, client_ip)
    logger.info(f"New SSH connection from {client_ip}, session ID: {session_id}")
    
    try:
        # Create transport
        transport = paramiko.Transport(client_sock)
        
        # Generate host key
        host_key = paramiko.RSAKey.generate(2048)
        transport.add_server_key(host_key)
        
        # Create server
        server = HoneypotSSHServer(session)
        
        # Start server
        transport.start_server(server=server)
        
        # Wait for channel
        channel = transport.accept(20)
        if channel is None:
            logger.warning(f"Session {session_id}: No channel opened")
            transport.close()
            return
            
        logger.info(f"Session {session_id}: Channel opened")
        
        # Handle channel
        handler = HoneypotChannelHandler(channel, session)
        handler.handle()
        
        transport.close()
        
    except Exception as e:
        logger.error(f"Error handling client {client_ip}: {e}")
        session.to_dict()  # Save partial session


def main():
    """Main entry point"""
    port = int(os.getenv('SSH_PORT', 2222))
    host = '0.0.0.0'
    
    logger.info(f"Starting SSH Honeypot on {host}:{port}")
    
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((host, port))
    server_socket.listen(100)
    
    logger.info(f"SSH Honeypot listening on {host}:{port}")
    
    try:
        while True:
            client_sock, addr = server_socket.accept()
            # Handle each client in a separate thread
            client_thread = threading.Thread(
                target=handle_client,
                args=(client_sock, addr),
                daemon=True
            )
            client_thread.start()
    except KeyboardInterrupt:
        logger.info("Shutting down SSH Honeypot")
    finally:
        server_socket.close()


if __name__ == '__main__':
    main()
