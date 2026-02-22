#!/usr/bin/env python3
"""
Database API Honeypot Service
Simulates PostgreSQL and MySQL database servers to capture connection attempts.
"""

import os
import json
import logging
import time
import socket
import threading
from datetime import datetime
from pathlib import Path

# Setup logging
log_dir = Path("/var/log/honeypot")
log_dir.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(log_dir / "db_api_honeypot.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Session storage
sessions_dir = Path("/sessions")
sessions_dir.mkdir(parents=True, exist_ok=True)


class DatabaseSession:
    """Tracks a database connection session"""
    
    def __init__(self, session_id, client_ip, db_type):
        self.session_id = session_id
        self.client_ip = client_ip
        self.db_type = db_type
        self.start_time = datetime.now()
        self.queries = []
        self.login_attempts = []
        
    def log_query(self, query):
        """Log a database query"""
        self.queries.append({
            'timestamp': datetime.now().isoformat(),
            'query': query
        })
        logger.warning(f"Session {self.session_id}: Query: {query}")
        
    def log_login_attempt(self, username, password, database):
        """Log a login attempt"""
        self.login_attempts.append({
            'timestamp': datetime.now().isoformat(),
            'username': username,
            'password': password,
            'database': database
        })
        logger.warning(f"Session {self.session_id}: Login - user: {username}, db: {database}")
        
    def to_dict(self):
        """Convert session to dictionary"""
        return {
            'session_id': self.session_id,
            'client_ip': self.client_ip,
            'db_type': self.db_type,
            'start_time': self.start_time.isoformat(),
            'end_time': datetime.now().isoformat(),
            'queries': self.queries,
            'login_attempts': self.login_attempts
        }


class PostgreSQLHoneypot:
    """PostgreSQL protocol honeypot"""
    
    def __init__(self, port=5432):
        self.port = port
        self.sessions = {}
        
    def handle_client(self, client_sock, addr):
        """Handle PostgreSQL client connection"""
        session_counter = int(time.time() * 1000)
        session_id = f"postgres_{session_counter}_{addr[0]}"
        client_ip = addr[0]
        
        session = DatabaseSession(session_id, client_ip, 'postgresql')
        self.sessions[session_id] = session
        
        logger.info(f"New PostgreSQL connection from {client_ip}, session ID: {session_id}")
        
        try:
            # Send PostgreSQL startup message
            # PostgreSQL protocol: length (4 bytes) + version (4 bytes) + params
            version = b'\x00\x03\x00\x00'  # Protocol version 3.0
            client_sock.send(version)
            
            # Read startup packet
            data = client_sock.recv(1024)
            if data:
                # Try to parse login info (simplified)
                logger.info(f"Session {session_id}: Received {len(data)} bytes")
                
                # Simulate authentication
                # Send authentication OK
                auth_ok = b'\x52\x00\x00\x00\x08\x00\x00\x00\x00'
                client_sock.send(auth_ok)
                
                # Read more data (queries)
                while True:
                    data = client_sock.recv(1024)
                    if not data:
                        break
                    # Log as query attempt
                    query_str = data.decode('utf-8', errors='ignore')[:200]
                    session.log_query(query_str)
                    
        except Exception as e:
            logger.error(f"Error handling PostgreSQL client: {e}")
        finally:
            self._save_session(session)
            client_sock.close()
            
    def _save_session(self, session):
        """Save session data"""
        session_file = sessions_dir / f"postgres_session_{session.session_id}.json"
        try:
            with open(session_file, 'w') as f:
                json.dump(session.to_dict(), f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save session: {e}")
            
    def start(self):
        """Start PostgreSQL honeypot"""
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind(('0.0.0.0', self.port))
        server_socket.listen(100)
        
        logger.info(f"PostgreSQL Honeypot listening on port {self.port}")
        
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


class MySQLHoneypot:
    """MySQL protocol honeypot"""
    
    def __init__(self, port=3306):
        self.port = port
        self.sessions = {}
        
    def handle_client(self, client_sock, addr):
        """Handle MySQL client connection"""
        session_counter = int(time.time() * 1000)
        session_id = f"mysql_{session_counter}_{addr[0]}"
        client_ip = addr[0]
        
        session = DatabaseSession(session_id, client_ip, 'mysql')
        self.sessions[session_id] = session
        
        logger.info(f"New MySQL connection from {client_ip}, session ID: {session_id}")
        
        try:
            # Send MySQL handshake
            # MySQL protocol: packet length + sequence + handshake
            handshake = b'\x0a'  # Protocol version 10
            handshake += b'5.7.0\x00'  # Server version
            handshake += b'\x00' * 8  # Connection ID
            handshake += b'root\x00' * 8  # Auth plugin data
            handshake += b'\x00'  # Filler
            handshake += b'\xff\xf7'  # Capability flags
            handshake += b'\x08'  # Character set
            handshake += b'\x02\x00'  # Status flags
            handshake += b'\x00' * 13  # Reserved
            
            packet_len = len(handshake) + 4
            packet = bytes([packet_len & 0xff, (packet_len >> 8) & 0xff, (packet_len >> 16) & 0xff, 0]) + handshake
            client_sock.send(packet)
            
            # Read authentication packet
            data = client_sock.recv(1024)
            if data:
                logger.info(f"Session {session_id}: Received {len(data)} bytes")
                # Try to extract username/password (simplified)
                query_str = data.decode('utf-8', errors='ignore')[:200]
                session.log_query(query_str)
                
                # Send error response (simulate auth failure)
                error = b'\xff'  # Error packet
                error += b'\x15\x04'  # Error code
                error += b'Access denied\x00'
                packet_len = len(error) + 4
                packet = bytes([packet_len & 0xff, (packet_len >> 8) & 0xff, (packet_len >> 16) & 0xff, 1]) + error
                client_sock.send(packet)
                
        except Exception as e:
            logger.error(f"Error handling MySQL client: {e}")
        finally:
            self._save_session(session)
            client_sock.close()
            
    def _save_session(self, session):
        """Save session data"""
        session_file = sessions_dir / f"mysql_session_{session.session_id}.json"
        try:
            with open(session_file, 'w') as f:
                json.dump(session.to_dict(), f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save session: {e}")
            
    def start(self):
        """Start MySQL honeypot"""
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind(('0.0.0.0', self.port))
        server_socket.listen(100)
        
        logger.info(f"MySQL Honeypot listening on port {self.port}")
        
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
    postgres_port = int(os.getenv('POSTGRES_PORT', 5432))
    mysql_port = int(os.getenv('MYSQL_PORT', 3306))
    
    logger.info("Starting Database API Honeypot")
    
    # Start PostgreSQL honeypot
    postgres_honeypot = PostgreSQLHoneypot(postgres_port)
    postgres_thread = threading.Thread(target=postgres_honeypot.start, daemon=True)
    postgres_thread.start()
    
    # Start MySQL honeypot
    mysql_honeypot = MySQLHoneypot(mysql_port)
    mysql_thread = threading.Thread(target=mysql_honeypot.start, daemon=True)
    mysql_thread.start()
    
    # Keep main thread alive
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Shutting down Database API Honeypot")


if __name__ == '__main__':
    main()




