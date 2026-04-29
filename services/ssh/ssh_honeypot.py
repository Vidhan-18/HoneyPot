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
            'login_attempts': self.login_attempts,
            'tags': list(getattr(self, 'tags', []))
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

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        """Accept PTY requests"""
        logger.info(f"Session {self.session.session_id}: PTY requested")
        return True
    
    def check_channel_shell_request(self, channel):
        """Accept shell requests"""
        logger.info(f"Session {self.session.session_id}: Shell requested")
        return True
        
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
        from command_handler import CommandHandler
        
        logger.info(f"DEBUG: Channel established for session {self.session.session_id}")
        logger.info("DEBUG: Initializing CommandHandler")
        handler = CommandHandler(self.session.session_id)
        logger.info("DEBUG: CommandHandler initialized")
        
        try:
            # Send welcome message
            welcome = f"Welcome to Ubuntu 22.04.2 LTS (GNU/Linux 5.15.0-71-generic x86_64)\n\n * Documentation:  https://help.ubuntu.com\n * Management:     https://landscape.canonical.com\n * Support:        https://ubuntu.com/advantage\n\nLast login: {self.session.start_time.strftime('%a %b %d %H:%M:%S %Y')} from {self.session.client_ip}\n"
            self.channel.send(welcome.replace('\n', '\r\n'))
            
            logger.info("DEBUG: Sending initial prompt")
            prompt = handler.get_prompt()
            self.channel.send(prompt)
            
            cmd_buffer = ""
            in_escape = False
            
            while True:
                if self.channel.recv_ready():
                    data = self.channel.recv(1024)
                    if not data:
                        break
                        
                    char_data = data.decode('utf-8', errors='ignore')
                    
                    for char in char_data:
                        if in_escape:
                            if char.isalpha() or char == '~':
                                in_escape = False
                            continue
                            
                        if char == '\x1b':
                            in_escape = True
                            continue
                            
                        if char in ('\r', '\n'):
                            self.channel.send("\r\n")
                            command = cmd_buffer.strip()
                            cmd_buffer = ""
                            
                            if command:
                                self.session.log_command(command)
                                logger.info(f"Session {self.session.session_id}: Command: {command}")
                                
                                try:
                                    # Simulate command execution
                                    response = handler.handle_command(command)
                                    
                                    # Add any tags generated by the handler to the session
                                    if hasattr(self.session, 'tags'):
                                        self.session.tags.update(handler.tags)
                                    else:
                                        self.session.tags = set(handler.tags)
                                        
                                    if response == "LOGOUT":
                                        self.channel.send("logout\r\n")
                                        self._save_session()
                                        self.channel.close()
                                        return
                                    elif response:
                                        # Send output, ensuring it ends with a newline
                                        if not response.endswith('\n'):
                                            response += '\n'
                                        # Handle line endings for paramiko channel
                                        response = response.replace('\n', '\r\n')
                                        self.channel.send(response)
                                except Exception as cmd_e:
                                    logger.error(f"Handler crash processing command '{command}': {cmd_e}")
                                    self.channel.send("Internal error\r\n")
                            
                            # Send the dynamic prompt after processing command
                            prompt = handler.get_prompt()
                            self.channel.send(prompt)
                            
                        elif char in ('\x08', '\x7f'):
                            if len(cmd_buffer) > 0:
                                cmd_buffer = cmd_buffer[:-1]
                                self.channel.send('\x08 \x08')
                                
                        elif char == '\x03':  # Ctrl+C
                            self.channel.send("^C\r\n")
                            cmd_buffer = ""
                            prompt = handler.get_prompt()
                            self.channel.send(prompt)
                            
                        elif char == '\x04':  # Ctrl+D
                            if len(cmd_buffer) == 0:
                                self.channel.send("logout\r\n")
                                self._save_session()
                                self.channel.close()
                                return
                                
                        elif char.isprintable():
                            cmd_buffer += char
                            self.channel.send(char)
                else:
                    time.sleep(0.05)
                            
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
