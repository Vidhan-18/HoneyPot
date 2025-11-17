# Attacker Tracking & Interaction Guide

## How Attackers Interact with the Honeypot

### Overview

When an attacker connects to your honeypot, **everything** is logged and tracked. The honeypot appears as a real service, but all interactions are captured for analysis.

## What Information is Captured

### 1. Connection Information

**For ALL Services:**
- ✅ **Source IP Address** - The attacker's IP address
- ✅ **Timestamp** - Exact time of connection
- ✅ **Session ID** - Unique identifier for each session
- ✅ **Protocol** - SSH, HTTP, Database, SMB, FTP
- ✅ **Connection Duration** - How long the session lasted

### 2. Authentication Attempts

**Captured Data:**
- ✅ **Username** - Every login attempt
- ✅ **Password** - Every password tried
- ✅ **Authentication Method** - Password, public key, etc.
- ✅ **Success/Failure** - Whether authentication was accepted
- ✅ **Database Name** - For database connections

### 3. Commands & Requests

**SSH Honeypot:**
- ✅ Every command executed
- ✅ Command timestamps
- ✅ Full command history
- ✅ Shell interactions

**HTTP Honeypot:**
- ✅ HTTP method (GET, POST, PUT, DELETE, etc.)
- ✅ Request path/URL
- ✅ Query parameters
- ✅ Request headers (all of them)
- ✅ Request body/data
- ✅ User-Agent string
- ✅ Referer header
- ✅ Cookies

**Database Honeypot:**
- ✅ SQL queries attempted
- ✅ Connection strings
- ✅ Database selection
- ✅ Query timestamps

**SMB/FTP Honeypot:**
- ✅ File operations (upload/download/delete)
- ✅ Directory operations
- ✅ File paths accessed
- ✅ FTP commands

### 4. Network Information

**Packet Capture:**
- ✅ Full packet captures (PCAP format)
- ✅ All network traffic
- ✅ Source and destination IPs
- ✅ Ports used
- ✅ Protocol details
- ✅ Payload data

## How Attackers See the Honeypot

### SSH Honeypot (Port 2222)

**What attackers see:**
```
$ ssh user@your-honeypot-ip -p 2222
Password: [they enter password]
Welcome to the system.
$ [they can type commands]
```

**What we capture:**
- Their IP address
- Username and password
- Every command they type
- Session duration

### HTTP Honeypot (Port 8080)

**What attackers see:**
- A normal-looking website
- Login pages
- Admin panels
- API endpoints
- Standard HTTP responses

**What we capture:**
- Their IP address
- User-Agent (browser/tool)
- All HTTP requests
- POST data (usernames, passwords, etc.)
- Headers (including X-Forwarded-For if behind proxy)

### Database Honeypot (Ports 5432, 3306)

**What attackers see:**
- PostgreSQL or MySQL connection prompt
- Database server version
- Connection acceptance

**What we capture:**
- Their IP address
- Connection credentials
- SQL queries
- Database names

### SMB/FTP Honeypot (Ports 445, 21)

**What attackers see:**
- FTP server welcome message
- SMB share access
- File listing capabilities

**What we capture:**
- Their IP address
- Login credentials
- File operations
- Directory browsing

## IP Address Tracking

### How IPs are Captured

1. **Direct Connection**: If attacker connects directly, we get their real IP
2. **Behind Proxy**: We capture the proxy IP (X-Forwarded-For header may contain real IP)
3. **VPN/Tor**: We capture the VPN/Tor exit node IP

### IP Information Stored

For each connection:
```json
{
  "client_ip": "192.168.1.100",
  "timestamp": "2024-01-15T10:30:00",
  "session_id": "ssh_1234567890_192.168.1.100",
  "protocol": "ssh"
}
```

## Viewing Attacker Activity

### 1. Web Dashboard

Access `http://localhost:5000` and:
- View all sessions with attacker IPs
- See detailed session information
- Filter by IP address
- View IOC detections

### 2. Session Files

All sessions are saved in `./data/sessions/`:
```bash
# SSH sessions
data/sessions/ssh_session_*.json

# HTTP sessions
data/sessions/http_session_*.json

# Database sessions
data/sessions/postgres_session_*.json
data/sessions/mysql_session_*.json

# SMB/FTP sessions
data/sessions/smb_session_*.json
data/sessions/ftp_session_*.json
```

### 3. Log Files

Service-specific logs in `./data/`:
```bash
data/ssh/ssh_honeypot.log
data/http/http_honeypot.log
data/db/db_api_honeypot.log
data/smb-ftp/smb_ftp_honeypot.log
```

### 4. Packet Captures

Full network traffic in `./data/pcaps/`:
```bash
# View with tcpdump
tcpdump -r data/pcaps/capture_*.pcap

# Or use Wireshark
wireshark data/pcaps/capture_*.pcap
```

## Example: Tracking an Attacker

### Scenario: SSH Brute Force Attack

1. **Attacker connects:**
   ```
   ssh root@your-ip -p 2222
   ```

2. **What we capture:**
   ```json
   {
     "session_id": "ssh_1705312345_203.0.113.45",
     "client_ip": "203.0.113.45",
     "start_time": "2024-01-15T10:30:00",
     "login_attempts": [
       {
         "timestamp": "2024-01-15T10:30:05",
         "username": "root",
         "password": "password123",
         "success": true
       }
     ],
     "commands": [
       {
         "timestamp": "2024-01-15T10:30:10",
         "command": "whoami"
       },
       {
         "timestamp": "2024-01-15T10:30:12",
         "command": "cat /etc/passwd"
       }
     ]
   }
   ```

3. **IOC Detection:**
   - Command injection pattern detected: `cat /etc/passwd`
   - Alert sent to configured channels

4. **Packet Capture:**
   - Full network traffic saved to PCAP file

## Advanced Tracking (Optional)

### GeoIP Lookup

You can add GeoIP lookup to identify attacker locations:

```python
# Example: Add to any honeypot service
import geoip2.database

reader = geoip2.database.Reader('/path/to/GeoLite2-City.mmdb')
response = reader.city(client_ip)
country = response.country.name
city = response.city.name
```

### Threat Intelligence

Compare captured IPs against threat intelligence feeds:
- AbuseIPDB
- VirusTotal
- Shodan
- AlienVault OTX

## Privacy & Legal Considerations

⚠️ **Important:**

1. **IP Addresses**: May be personal data under GDPR
2. **Logs**: May contain sensitive information
3. **Retention**: Implement data retention policies
4. **Sharing**: Be careful sharing attacker data publicly
5. **Legal Use**: Only use in authorized environments

## Best Practices

1. **Regular Review**: Check logs regularly for new attacks
2. **IP Blocking**: Consider blocking known malicious IPs
3. **Alerting**: Configure alerts for suspicious activity
4. **Backup**: Regularly backup collected data
5. **Analysis**: Use collected data for threat intelligence

## Example Attack Scenarios

### Scenario 1: Web Application Scanner

**Attacker Action:**
```
GET /admin HTTP/1.1
GET /wp-admin HTTP/1.1
GET /.env HTTP/1.1
POST /login HTTP/1.1 (with credentials)
```

**Captured:**
- IP: 198.51.100.42
- User-Agent: sqlmap/1.7.2
- All requests logged
- IOC: Path traversal detected

### Scenario 2: Database Brute Force

**Attacker Action:**
```
mysql -h your-ip -u root -p
[multiple password attempts]
```

**Captured:**
- IP: 203.0.113.78
- All login attempts
- Queries attempted
- IOC: SQL injection patterns

### Scenario 3: SSH Botnet

**Attacker Action:**
```
ssh root@your-ip -p 2222
[automated password attempts]
```

**Captured:**
- IP: 192.0.2.15
- All credentials tried
- Commands executed
- IOC: Malicious commands detected

## Summary

**Everything an attacker does is logged:**
- ✅ Their IP address
- ✅ What they try to access
- ✅ Credentials they use
- ✅ Commands they execute
- ✅ Files they access
- ✅ Full network traffic

**The honeypot appears real to attackers, but you see everything!**


