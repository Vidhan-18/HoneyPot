#!/usr/bin/env python3
"""
SSH Honeypot Service
Simulates an SSH server to capture attacker interactions.
"""

import os
import sys
import re
import json
import logging
import time
import socket
import threading
from datetime import datetime
from pathlib import Path
from typing import Dict, Any

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

# Session and payload storage
sessions_dir = Path("/sessions")
sessions_dir.mkdir(parents=True, exist_ok=True)

payloads_dir = Path("/payloads")
payloads_dir.mkdir(parents=True, exist_ok=True)

payloads_analysis_dir = Path("/payloads_analysis")
payloads_analysis_dir.mkdir(parents=True, exist_ok=True)

# ---------------------------------------------------------------------------
# Virtual filesystem (fully simulated, never touches real host filesystem)
# ---------------------------------------------------------------------------

FAKE_FILESYSTEM: Dict[str, Any] = {
    "/": ["bin", "boot", "dev", "etc", "home", "root", "tmp", "usr", "var"],
    "/bin": ["bash", "sh", "ls", "cat", "ps", "netstat", "ifconfig"],
    "/boot": [],
    "/dev": [],
    "/etc": ["passwd", "shadow", "hostname", "hosts"],
    "/home": ["root"],
    "/home/root": ["notes.txt", "projects", ".ssh"],
    "/root": ["secret.txt", ".bash_history"],
    "/tmp": [],
    "/usr": ["bin", "lib", "share"],
    "/usr/bin": [],
    "/var": ["log", "www", "tmp"],
    "/var/log": ["auth.log", "syslog"],
    "/var/www": ["html"],
    "/var/www/html": ["index.php"],
}


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
        # Virtual shell state
        self.cwd = "/home/root"
        self.env = {
            "USER": "root",
            "HOME": "/home/root",
            "SHELL": "/bin/bash",
            "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        }
        
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


def _ensure_text(s: Any) -> str:
    try:
        return str(s)
    except Exception:
        return repr(s)


def detect_and_capture_payload(command: str, session: HoneypotSession) -> None:
    """
    Detect potential payloads in a command and save them for offline analysis.
    This NEVER executes the payload; it only records and performs static analysis.
    """
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    base_id = f"{ts}_{session.session_id}"

    # Basic artifacts we care about
    artifacts: Dict[str, Any] = {
        "urls": [],
        "base64_blobs": [],
        "inline_code": [],
    }

    # Detect URLs
    url_pattern = re.compile(r"https?://[^\s'\"<>]+", re.IGNORECASE)
    artifacts["urls"] = url_pattern.findall(command)[:10]

    # Detect long base64-looking blobs
    b64_pattern = re.compile(r"[A-Za-z0-9+/=]{40,}")
    artifacts["base64_blobs"] = b64_pattern.findall(command)[:5]

    # Detect inline code for common interpreters
    inline_patterns = [
        r"python\s+-c\s+\"([^\"]+)\"",
        r"python\s+-c\s+'([^']+)'",
        r"perl\s+-e\s+\"([^\"]+)\"",
        r"perl\s+-e\s+'([^']+)'",
        r"php\s+-r\s+\"([^\"]+)\"",
        r"php\s+-r\s+'([^']+)'",
    ]
    inline_code = []
    for pat in inline_patterns:
        for m in re.findall(pat, command):
            inline_code.append(m)
    artifacts["inline_code"] = inline_code[:5]

    # If nothing suspicious, skip heavy logging
    if not (artifacts["urls"] or artifacts["base64_blobs"] or artifacts["inline_code"]):
        # Also look for obvious downloader/pipe patterns
        lowered = command.lower()
        if not any(
            kw in lowered
            for kw in ("wget ", "curl ", " nc ", " bash -i", "| bash", "| sh", "powershell", "certutil")
        ):
            return

    payload_record: Dict[str, Any] = {
        "payload_id": base_id,
        "session_id": session.session_id,
        "client_ip": session.client_ip,
        "username": session.username,
        "timestamp": datetime.now().isoformat(),
        "command": command,
        "artifacts": artifacts,
    }

    # Very simple static classification
    lowered = command.lower()
    tags = []
    if "wget " in lowered or "curl " in lowered:
        tags.append("downloader")

    if "| bash" in lowered or "| sh" in lowered:
        tags.append("pipe_to_shell")

    if " nc " in lowered or " netcat " in lowered:
        tags.append("reverse_shell_candidate")

    if "bash -i" in lowered or "/dev/tcp/" in lowered:
        tags.append("interactive_shell")

    if "base64" in lowered:
        tags.append("base64_payload")

    if "powershell" in lowered or "pwsh" in lowered:
        tags.append("powershell_payload")

    if "chmod +x" in lowered:
        tags.append("permission_change")

    if "sudo " in lowered or "su " in lowered:
        tags.append("privilege_escalation_attempt")

    if "../" in command or "/etc/passwd" in command or "/etc/shadow" in command:
        tags.append("sensitive_file_access")

    if "python -c" in lowered or "perl -e" in lowered or "php -r" in lowered:
        tags.append("inline_code_execution")

    if "nc -e" in lowered or "bash -c" in lowered:
        tags.append("reverse_shell_execution")

    payload_record["tags"] = tags

    # Save raw payload record
    payload_file = payloads_dir / f"payload_{base_id}.json"
    try:
        with open(payload_file, "w", encoding="utf-8") as f:
            json.dump(payload_record, f, indent=2)
    except Exception as e:
        logger.error(f"Failed to save payload record: {e}")

    # Basic analysis summary
    analysis: Dict[str, Any] = {
        "payload_id": base_id,
        "session_id": session.session_id,
        "summary": "",
        "severity": "medium",
        "indicators": {
            "domains": [],
            "ips": [],
            "paths": [],
        },
    }

    # Extract domains / IPs / paths from URLs
    for url in artifacts["urls"]:
        try:
            # crude domain extraction
            host = url.split("://", 1)[1].split("/", 1)[0]
            if re.match(r"^\d+\.\d+\.\d+\.\d+$", host):
                analysis["indicators"]["ips"].append(host)
            else:
                analysis["indicators"]["domains"].append(host)
        except Exception:
            continue

    # Common sensitive paths
    for p in ("/etc/passwd", "/etc/shadow", "/root", "/home", "/var/www", "c:\\windows", "c:/windows"):
        if p.lower() in lowered:
            analysis["indicators"]["paths"].append(p)

    # Severity heuristic
    if "reverse_shell_candidate" in tags or "pipe_to_shell" in tags:
        analysis["severity"] = "high"
    if "downloader" in tags and ("pipe_to_shell" in tags or "base64_payload" in tags):
        analysis["severity"] = "critical"

    analysis["summary"] = _ensure_text(
        f"Detected payload with tags={tags}, urls={artifacts['urls']}, "
        f"base64_blobs={len(artifacts['base64_blobs'])}, inline_code={len(artifacts['inline_code'])}"
    )

    analysis_file = payloads_analysis_dir / f"payload_analysis_{base_id}.json"
    try:
        with open(analysis_file, "w", encoding="utf-8") as f:
            json.dump(analysis, f, indent=2)
    except Exception as e:
        logger.error(f"Failed to save payload analysis: {e}")

    logger.warning(f"Captured potential payload for session {session.session_id}: {payload_file}")


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
        try:
            # Send welcome message with proper terminal formatting
            welcome = (
                "Welcome to the HPD system.\r\n"
                "Type 'help' to see available commands.\r\n"
            )
            prompt = f"{self.session.username}@hpd-server:{self.session.cwd}# "
            self.channel.send(welcome + prompt)
            
            buffer = ""
            while True:
                data = self.channel.recv(1)
                if not data:
                    break

                char = data.decode("utf-8", errors="ignore")

                # ENTER key
                if char in ("\r", "\n"):
                    command = buffer.strip()
                    buffer = ""

                    if command:
                        self.session.log_command(command)
                        logger.info(f"Session {self.session.session_id}: Command: {command}")

                        try:
                            detect_and_capture_payload(command, self.session)
                        except Exception as e:
                            logger.error(f"Payload detection failed: {e}")

                        if command.lower() in ["exit", "quit", "logout"]:
                            self.channel.send("\r\nlogout\r\nConnection closed.\r\n")
                            break

                        output = self._handle_virtual_command(command)

                        if not output.endswith("\n"):
                            output += "\n"

                        prompt = f"{self.session.username}@hpd-server:{self.session.cwd}# "
                        self.channel.send("\r\n" + output.rstrip() + "\r\n" + prompt)

                    else:
                        # empty command — just move to next line and redraw prompt
                        prompt = f"{self.session.username}@hpd-server:{self.session.cwd}# "
                        self.channel.send("\r\n" + prompt)

                    continue

                # BACKSPACE support
                if char in ("\x7f", "\b"):
                    if len(buffer) > 0:
                        buffer = buffer[:-1]
                        self.channel.send("\b \b")
                    continue

                # Ignore control characters
                if ord(char) < 32:
                    continue

                buffer += char
                self.channel.send(char)
        except Exception as e:
            logger.error(f"Error handling channel: {e}")
        finally:
            self._save_session()
            self.channel.close()

    def _build_prompt(self) -> str:
        """Return a realistic root shell prompt string."""
        cwd = self.session.cwd or "/"
        return f"root@hpd-server:{cwd}# "

    def _handle_virtual_command(self, command: str) -> str:
        """
        Handle a command in a safe, virtual shell environment.
        This never executes system commands; it only returns simulated output.
        """
        cmd = command.strip()

        # Empty command just re-prompts
        if not cmd:
            return ""

        # Simple parsing: split by spaces
        parts = cmd.split()
        base = parts[0]
        args = parts[1:]
        lowered = cmd.lower()

        # --- Built-in commands ---

        if base == "help":
            return (
                "Built-in commands:\n"
                "  help               - show this help\n"
                "  pwd                - print working directory\n"
                "  ls [path]          - list directory contents\n"
                "  cd <path>          - change directory\n"
                "  whoami             - show current user\n"
                "  uname -a           - show system information\n"
                "  id                 - show user identity\n"
                "  env                - show environment variables\n"
                "  cat <file>         - show file contents (virtual)\n"
                "  ps                 - show process list (simulated)\n"
                "  ifconfig           - show network interfaces (simulated)\n"
                "  netstat            - show network connections (simulated)\n"
                "  history            - show command history\n"
                "  exit/quit/logout   - close session\n"
            )

        # pwd
        if base == "pwd":
            return self.session.cwd

        # whoami
        if base == "whoami":
            return "root"

        # uname
        if base == "uname":
            if args and args[0] == "-a":
                return "Linux hpd-server 5.15.0-virtual-hpd #1 SMP x86_64 GNU/Linux"
            return "Linux"

        # id
        if base == "id":
            return "uid=0(root) gid=0(root) groups=0(root)"

        # env
        if base == "env":
            lines = [f"{k}={v}" for k, v in self.session.env.items()]
            lines.append(f"PWD={self.session.cwd}")
            return "\n".join(lines)

        # cd
        if base == "cd":
            target = args[0] if args else "~"

            def normalize(path: str) -> str:
                if not path.startswith("/"):
                    # relative path
                    if self.session.cwd.endswith("/"):
                        path = self.session.cwd + path
                    else:
                        path = self.session.cwd + "/" + path
                parts_norm = []
                for part in path.split("/"):
                    if part in ("", "."):
                        continue
                    if part == "..":
                        if parts_norm:
                            parts_norm.pop()
                        continue
                    parts_norm.append(part)
                return "/" + "/".join(parts_norm)

            if target in ("~", ""):
                self.session.cwd = self.session.env.get("HOME", "/home/root")
                return ""

            if target == "..":
                if self.session.cwd != "/":
                    parent = "/".join(self.session.cwd.rstrip("/").split("/")[:-1]) or "/"
                    self.session.cwd = parent
                return ""

            norm = normalize(target)

            if norm in FAKE_FILESYSTEM:
                self.session.cwd = norm
                return ""

            return f"bash: cd: {target}: No such file or directory"

        # ls
        if base == "ls":
            target = self.session.cwd
            if args:
                arg = args[0]
                if arg.startswith("/"):
                    target = arg
                elif arg == ".":
                    target = self.session.cwd
                elif arg == "..":
                    parent = "/".join(self.session.cwd.rstrip("/").split("/")[:-1]) or "/"
                    target = parent
                else:
                    if self.session.cwd.endswith("/"):
                        target = self.session.cwd + arg
                    else:
                        target = self.session.cwd + "/" + arg

            target = target.rstrip("/") or "/"

            if target not in FAKE_FILESYSTEM:
                return f"ls: cannot access '{args[0] if args else target}': No such file or directory"

            entries = sorted(FAKE_FILESYSTEM.get(target, []))
            return "  ".join(entries)

        # cat
        if base == "cat":
            if not args:
                return "bash: cat: missing file operand"
            path = args[0]
            if not path.startswith("/"):
                if self.session.cwd.endswith("/"):
                    path = self.session.cwd + path
                else:
                    path = self.session.cwd + "/" + path
            path = path.replace("//", "/")

            if path == "/etc/passwd":
                return (
                    "root:x:0:0:root:/root:/bin/bash\n"
                    "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
                    "bin:x:2:2:bin:/bin:/usr/sbin/nologin\n"
                    "sys:x:3:3:sys:/dev:/usr/sbin/nologin\n"
                    "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
                    "hpd:x:1000:1000:HPD User:/home/hpd:/bin/bash\n"
                )
            if path == "/etc/shadow":
                return (
                    "root:*:19632:0:99999:7:::\n"
                    "www-data:*:19632:0:99999:7:::\n"
                    "hpd:*:19632:0:99999:7:::\n"
                )
            if path in ("/home/root/notes.txt", "/root/notes.txt", "notes.txt"):
                return (
                    "TODO:\n"
                    "- rotate SSH keys\n"
                    "- review IDS alerts\n"
                    "- analyze latest honeypot payloads\n"
                )

            parent = "/".join(path.rstrip("/").split("/")[:-1]) or "/"
            fname = path.rstrip("/").split("/")[-1]
            if parent in FAKE_FILESYSTEM and fname in FAKE_FILESYSTEM[parent]:
                return f"[virtual contents of {path} captured for analysis]\n"

            return f"bash: cat: {args[0]}: No such file or directory"

        # ps
        if base == "ps":
            return (
                "  PID TTY          TIME CMD\n"
                "    1 ?        00:00:01 init\n"
                "  123 ?        00:00:00 sshd\n"
                "  456 pts/0    00:00:00 bash\n"
                "  789 pts/0    00:00:00 ps\n"
            )

        # ifconfig
        if base == "ifconfig":
            return (
                "eth0      Link encap:Ethernet  HWaddr 02:42:ac:11:00:02  \n"
                "          inet addr:172.17.0.2  Bcast:172.17.255.255  Mask:255.255.0.0\n"
                "          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1\n"
                "          RX packets:1024 errors:0 dropped:0 overruns:0 frame:0\n"
                "          TX packets:768 errors:0 dropped:0 overruns:0 carrier:0\n"
                "\n"
                "lo        Link encap:Local Loopback  \n"
                "          inet addr:127.0.0.1  Mask:255.0.0.0\n"
                "          UP LOOPBACK RUNNING  MTU:65536  Metric:1\n"
                "          RX packets:8 errors:0 dropped:0 overruns:0 frame:0\n"
                "          TX packets:8 errors:0 dropped:0 overruns:0 carrier:0\n"
            )

        # netstat
        if base == "netstat":
            return (
                "Active Internet connections (servers and established)\n"
                "Proto Recv-Q Send-Q Local Address           Foreign Address         State      \n"
                "tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN     \n"
                "tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN     \n"
                "tcp        0      0 172.17.0.2:22           203.0.113.10:54321      ESTABLISHED\n"
            )

        # history
        if base == "history":
            lines = []
            for idx, entry in enumerate(self.session.commands, start=1):
                cmd_str = entry.get("command", "") if isinstance(entry, dict) else str(entry)
                lines.append(f"{idx:4d}  {cmd_str}")
            return "\n".join(lines)

        # Unknown command: respond like a real shell would
        return f"bash: {command}: command not found"
            
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
