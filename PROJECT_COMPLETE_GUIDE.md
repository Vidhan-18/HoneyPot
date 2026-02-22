# Complete Honeypot Platform Guide

## Table of Contents
1. [Project Overview](#project-overview)
2. [Architecture](#architecture)
3. [Technology Stack](#technology-stack)
4. [Services & Components](#services--components)
5. [Data Flow](#data-flow)
6. [Security Features](#security-features)
7. [Installation & Deployment](#installation--deployment)
8. [Usage Guide](#usage-guide)
9. [API Reference](#api-reference)
10. [Troubleshooting](#troubleshooting)

---

## Project Overview

### What is This Project?

This is an **Advanced Dual-Mode Honeypot Platform** - a containerized security research tool that:
- **Attracts attackers** by simulating realistic services (SSH, HTTP, Databases, SMB/FTP)
- **Monitors everything** attackers do (commands, requests, credentials, network traffic)
- **Analyzes threats** with automatic attack classification and IOC detection
- **Alerts you** via webhooks, Slack, or Telegram when threats are detected

### Key Features

✅ **Multi-Protocol Honeypots**
- SSH server (port 2222)
- HTTP web server (port 8080)
- PostgreSQL & MySQL databases (ports 5432, 3306)
- SMB & FTP servers (ports 445, 21, 139)

✅ **Comprehensive Monitoring**
- Full packet captures (PCAP format)
- Session recordings (JSON format)
- Aggregated logs from all services
- Real-time statistics

✅ **Intelligent Analysis**
- Automatic attack classification (12 categories)
- IP geolocation (country, city, ISP)
- IOC (Indicators of Compromise) detection
- Severity-based threat scoring

✅ **Web Dashboard**
- Real-time monitoring interface
- Attacker tracking by IP
- Location visualization
- Attack type categorization
- Secure authentication

✅ **Alerting System**
- Webhook integration
- Slack notifications
- Telegram bot alerts
- Configurable thresholds

---

## Architecture

### System Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Docker Network                        │
│                  (Isolated Network)                      │
│                                                          │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐ │
│  │ SSH Honeypot │  │ HTTP Honeypot│  │  DB Honeypot │ │
│  │   Port 2222  │  │   Port 8080  │  │ Ports 5432/  │ │
│  │              │  │              │  │     3306     │ │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘ │
│         │                  │                  │         │
│  ┌──────┴──────────────────┴──────────────────┴───────┐ │
│  │         SMB/FTP Honeypot (Ports 445, 21)           │ │
│  └──────────────────────┬─────────────────────────────┘ │
│                         │                               │
│  ┌──────────────────────┴─────────────────────────────┐ │
│  │           Log Aggregator Service                    │ │
│  │         (Collects all service logs)                │ │
│  └──────────────────────┬─────────────────────────────┘ │
│                         │                               │
│  ┌──────────────────────┴─────────────────────────────┐ │
│  │         Packet Capture Service (tcpdump)            │ │
│  │         (Captures all network traffic)              │ │
│  └──────────────────────┬─────────────────────────────┘ │
│                         │                               │
│  ┌──────────────────────┴─────────────────────────────┐ │
│  │         IOC Detector & Alerting Service             │ │
│  │    (Detects threats, sends alerts via host network) │ │
│  └─────────────────────────────────────────────────────┘ │
│                                                          │
│  ┌─────────────────────────────────────────────────────┐ │
│  │         Web Dashboard (Port 5000)                    │ │
│  │    (Accessible from host network via port mapping)   │ │
│  └─────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────┘
         │
         │ (Port 5000 exposed)
         ▼
┌─────────────────────────────────────────────────────────┐
│              Windows Host / Other Devices               │
│         (Access dashboard via http://localhost:5000)     │
└─────────────────────────────────────────────────────────┘
```

### Network Isolation

- **Honeypot Network**: Internal Docker bridge network
  - No egress to external networks
  - Services can only communicate with each other
  - Complete isolation from host network

- **Host Network Access**: Only for:
  - Web Dashboard (port 5000) - for monitoring
  - IOC Detector - for sending alerts (webhook/Slack/Telegram)

---

## Technology Stack

### Core Technologies

#### **Containerization**
- **Docker**: Container runtime
- **Docker Compose**: Multi-container orchestration
- **Base Images**: Python 3.11-slim

#### **Programming Languages**
- **Python 3.11**: All services written in Python
- **JavaScript**: Frontend dashboard (vanilla JS)
- **HTML/CSS**: Web interface

### Libraries & Dependencies

#### **SSH Honeypot** (`services/ssh/`)
```python
paramiko==3.4.0          # SSH protocol implementation
pycryptodome==3.19.0     # Cryptographic operations
```

#### **HTTP Honeypot** (`services/http/`)
```python
flask==3.0.0             # Web framework
werkzeug==3.0.1          # WSGI utilities
```

#### **Database Honeypot** (`services/db-api/`)
```python
flask==3.0.0             # Web framework
psycopg2-binary==2.9.9  # PostgreSQL protocol
pymysql==1.1.0          # MySQL protocol
```

#### **SMB/FTP Honeypot** (`services/smb-ftp/`)
```python
pyftpdlib==1.5.9        # FTP server implementation
```

#### **Packet Capture** (`monitoring/packet-capture/`)
```python
scapy==2.5.0            # Network packet manipulation
# System tools: tcpdump, tshark
```

#### **Log Aggregator** (`monitoring/log-aggregator/`)
```python
watchdog==3.0.0         # File system monitoring
```

#### **IOC Detector** (`monitoring/ioc-detector/`)
```python
requests==2.31.0        # HTTP requests for alerts
watchdog==3.0.0         # File system monitoring
```

#### **Web Dashboard** (`monitoring/web-dashboard/`)
```python
flask==3.0.0            # Web framework
flask-socketio==5.3.6   # WebSocket support
python-socketio==5.10.0 # Socket.IO client
eventlet==0.33.3        # Async networking
requests==2.31.0        # HTTP requests (GeoIP)
```

### System Tools

- **tcpdump**: Packet capture
- **tshark**: Wireshark CLI (optional)
- **curl**: HTTP requests (for alerts)

---

## Services & Components

### 1. SSH Honeypot (`services/ssh/`)

**Purpose**: Simulates SSH server to capture login attempts and commands

**Technology**: 
- Paramiko library for SSH protocol
- Custom server implementation

**Features**:
- Accepts all login attempts (logs credentials)
- Records all commands executed
- Session recording with timestamps
- Supports password and public key authentication

**Port**: 2222

**Data Captured**:
- Client IP address
- Username and password attempts
- All commands executed
- Session duration
- Command timestamps

**Files**:
- `ssh_honeypot.py`: Main service
- `Dockerfile`: Container definition
- `requirements.txt`: Dependencies

---

### 2. HTTP Honeypot (`services/http/`)

**Purpose**: Simulates web server with fake endpoints

**Technology**:
- Flask web framework
- Custom HTML templates

**Features**:
- Realistic-looking corporate portal
- Multiple fake endpoints (admin, login, API)
- Logs all HTTP requests
- Captures POST data, headers, user agents

**Port**: 8080

**Endpoints**:
- `/` - Homepage
- `/login` - Login page
- `/admin` - Admin panel
- `/api` - API endpoint
- `/api/users` - Users API
- `/api/database` - Database API
- `/.env` - Fake environment file
- `/wp-admin` - Fake WordPress admin
- `/phpmyadmin` - Fake phpMyAdmin

**Data Captured**:
- Client IP address
- HTTP method, path, query string
- Request headers (including User-Agent)
- POST data (credentials, etc.)
- Referer header

**Files**:
- `http_honeypot.py`: Main service
- `Dockerfile`: Container definition
- `requirements.txt`: Dependencies

---

### 3. Database API Honeypot (`services/db-api/`)

**Purpose**: Simulates PostgreSQL and MySQL database servers

**Technology**:
- Custom protocol implementation
- Socket-based server

**Features**:
- PostgreSQL protocol simulation (port 5432)
- MySQL protocol simulation (port 3306)
- Logs connection attempts
- Records SQL queries

**Ports**: 5432 (PostgreSQL), 3306 (MySQL)

**Data Captured**:
- Client IP address
- Connection credentials
- SQL queries attempted
- Database names
- Connection timestamps

**Files**:
- `db_api_honeypot.py`: Main service
- `Dockerfile`: Container definition
- `requirements.txt`: Dependencies

---

### 4. SMB/FTP Honeypot (`services/smb-ftp/`)

**Purpose**: Simulates SMB and FTP file servers

**Technology**:
- pyftpdlib for FTP
- Custom SMB protocol implementation

**Features**:
- FTP server (port 21)
- SMB server (port 445)
- Logs file operations
- Records login attempts

**Ports**: 445 (SMB), 21 (FTP), 139 (NetBIOS)

**Data Captured**:
- Client IP address
- Login credentials
- File upload/download attempts
- Directory operations
- File paths accessed

**Files**:
- `smb_ftp_honeypot.py`: Main service
- `Dockerfile`: Container definition
- `requirements.txt`: Dependencies

---

### 5. Packet Capture Service (`monitoring/packet-capture/`)

**Purpose**: Captures all network traffic

**Technology**:
- tcpdump (system tool)
- Python wrapper

**Features**:
- Full packet capture (PCAP format)
- Automatic file rotation (100MB per file)
- Retains last 10 capture files
- Timestamped files

**Data Captured**:
- All network packets
- Source and destination IPs
- Ports used
- Protocol details
- Payload data

**Files**:
- `packet_capture.py`: Main service
- `Dockerfile`: Container definition
- `requirements.txt`: Dependencies

---

### 6. Log Aggregator (`monitoring/log-aggregator/`)

**Purpose**: Aggregates logs from all honeypot services

**Technology**:
- Watchdog for file monitoring
- JSON log format

**Features**:
- Real-time log aggregation
- Unified log format
- Source tracking
- Automatic rotation

**Data Processed**:
- SSH honeypot logs
- HTTP honeypot logs
- Database honeypot logs
- SMB/FTP honeypot logs

**Output**: `./data/logs/aggregated.log`

**Files**:
- `log_aggregator.py`: Main service
- `Dockerfile`: Container definition
- `requirements.txt`: Dependencies

---

### 7. IOC Detector (`monitoring/ioc-detector/`)

**Purpose**: Detects Indicators of Compromise and sends alerts

**Technology**:
- Pattern matching (regex)
- Watchdog for file monitoring
- HTTP requests for alerts

**Features**:
- Real-time IOC detection
- Multiple alert channels
- Configurable thresholds
- Pattern-based detection

**IOC Patterns Detected**:
- SQL Injection
- Command Injection
- Path Traversal
- XSS (Cross-Site Scripting)
- Malicious Commands
- Credential Harvesting

**Alert Channels**:
- Generic webhook
- Slack webhook
- Telegram bot

**Files**:
- `ioc_detector.py`: Main service
- `Dockerfile`: Container definition
- `requirements.txt`: Dependencies

---

### 8. Web Dashboard (`monitoring/web-dashboard/`)

**Purpose**: Web interface for monitoring and analysis

**Technology**:
- Flask web framework
- Flask-SocketIO for real-time updates
- JavaScript (vanilla)
- HTML/CSS

**Features**:
- Real-time statistics
- Session viewer
- IOC display
- Log viewer
- Service status
- Attacker tracking
- Location visualization
- Attack classification

**Authentication**:
- Session-based login
- Default: `admin` / `honeypot2024`
- SHA256 password hashing

**Port**: 5000

**Pages**:
- `/` - Main dashboard
- `/login` - Login page
- `/attackers` - Attacker tracking
- `/api/*` - REST API endpoints

**Files**:
- `web_dashboard.py`: Main Flask app
- `auth.py`: Authentication module
- `geoip_lookup.py`: IP geolocation
- `attack_classifier.py`: Attack classification
- `templates/dashboard.html`: Main dashboard
- `templates/login.html`: Login page
- `templates/attackers.html`: Attacker page
- `Dockerfile`: Container definition
- `requirements.txt`: Dependencies

---

## Data Flow

### 1. Attacker Interaction Flow

```
Attacker → Honeypot Service → Log File → Log Aggregator → IOC Detector → Alert
                ↓
         Session Recording → JSON File
                ↓
         Packet Capture → PCAP File
```

### 2. Dashboard Data Flow

```
Session Files → Web Dashboard API → Frontend Display
     ↓
GeoIP Lookup → Location Info
     ↓
Attack Classifier → Attack Types & Severity
```

### 3. Alert Flow

```
IOC Detector → Pattern Match → Alert Sender → Webhook/Slack/Telegram
```

---

## Security Features

### Network Isolation

1. **Internal Docker Network**
   - Honeypot services run in isolated network
   - No egress to external networks
   - Services can only communicate with each other

2. **Controlled Egress**
   - Only IOC detector can send alerts (via host network)
   - Dashboard accessible via port mapping only

### Data Protection

1. **No Real Exploits**
   - All services are simulated
   - No actual vulnerabilities
   - No execution of untrusted code

2. **Comprehensive Logging**
   - All interactions logged
   - Session recordings
   - Packet captures
   - Audit trail for forensics

### Authentication

1. **Dashboard Login**
   - Session-based authentication
   - Secure password hashing
   - Login attempt logging

2. **Default Credentials**
   - Username: `admin`
   - Password: `honeypot2024`
   - **MUST be changed in production**

---

## Installation & Deployment

### Prerequisites

- Docker Engine 20.10+
- Docker Compose 2.0+
- 4GB RAM minimum
- 10GB free disk space
- Linux-based host (or VM)

### Quick Start

#### 1. Clone/Extract Project
```bash
cd markII
```

#### 2. Run Setup Script
**Linux/Mac:**
```bash
chmod +x setup.sh
./setup.sh
```

**Windows:**
```powershell
.\setup.ps1
```

#### 3. Configure Alerts (Optional)
Edit `.env` file:
```bash
WEBHOOK_URL=https://your-webhook-url.com
SLACK_WEBHOOK=https://hooks.slack.com/services/YOUR/WEBHOOK
TELEGRAM_BOT_TOKEN=your_bot_token
TELEGRAM_CHAT_ID=your_chat_id
```

#### 4. Start Platform
```bash
docker-compose up -d
```

#### 5. Access Dashboard
Open browser: `http://localhost:5000`
- Login: `admin` / `honeypot2024`

### VM Deployment

#### Step 1: Create Linux VM
- Install Ubuntu/Debian
- Allocate: 4GB RAM, 20GB disk, 2 CPUs
- Network: NAT or Internal Network

#### Step 2: Install Docker
```bash
# Ubuntu/Debian
curl -fsSL https://get.docker.com -o get-docker.sh
sh get-docker.sh
sudo usermod -aG docker $USER

# Install Docker Compose
sudo apt-get install docker-compose-plugin
```

#### Step 3: Copy Project
```bash
# From Windows, copy project to VM
scp -r markII/ user@vm-ip:/home/user/
```

#### Step 4: Run Setup
```bash
cd markII
./setup.sh
docker-compose up -d
```

#### Step 5: Access from Windows
**Option A: SSH Tunnel (Recommended)**
```powershell
ssh -L 5000:localhost:5000 user@vm-ip
# Then open http://localhost:5000 in browser
```

**Option B: Port Forwarding**
- Configure VM network to bridge mode
- Access via VM's IP: `http://vm-ip:5000`

---

## Usage Guide

### Accessing Services

#### Web Dashboard
- URL: `http://localhost:5000`
- Login: `admin` / `honeypot2024`
- Features:
  - View all sessions
  - See detected IOCs
  - Monitor attacker activity
  - View logs
  - Check service status

#### Honeypot Services
- **SSH**: `ssh user@localhost -p 2222`
- **HTTP**: `http://localhost:8080`
- **PostgreSQL**: `psql -h localhost -p 5432`
- **MySQL**: `mysql -h localhost -P 3306`
- **FTP**: `ftp localhost 21`
- **SMB**: `smbclient //localhost/share`

### Viewing Data

#### Sessions
```bash
# List all sessions
ls -lh data/sessions/

# View a session
cat data/sessions/ssh_session_*.json | jq .
```

#### Logs
```bash
# Aggregated logs
cat data/logs/aggregated.log

# Service-specific logs
cat data/ssh/ssh_honeypot.log
cat data/http/http_honeypot.log
```

#### Packet Captures
```bash
# List PCAPs
ls -lh data/pcaps/

# Analyze with tcpdump
tcpdump -r data/pcaps/capture_*.pcap

# Or use Wireshark
wireshark data/pcaps/capture_*.pcap
```

#### IOCs
```bash
# List detected IOCs
ls -lh data/iocs/

# View an IOC
cat data/iocs/ioc_*.json | jq .
```

### Monitoring

#### Check Service Status
```bash
docker-compose ps
```

#### View Logs
```bash
# All services
docker-compose logs -f

# Specific service
docker-compose logs -f web-dashboard
docker-compose logs -f ssh-honeypot
```

#### Restart Services
```bash
# Restart all
docker-compose restart

# Restart specific service
docker-compose restart web-dashboard
```

---

## API Reference

### Dashboard API Endpoints

All endpoints require authentication (login first).

#### Statistics
```
GET /api/stats
Returns: Platform statistics (sessions, IOCs, PCAPs, activity)
```

#### Sessions
```
GET /api/sessions?limit=50
Returns: List of sessions with location and attack classification

GET /api/session/<filename>
Returns: Specific session details
```

#### IOCs
```
GET /api/iocs?limit=50
Returns: List of detected IOCs

GET /api/ioc/<filename>
Returns: Specific IOC details
```

#### Logs
```
GET /api/logs?limit=100&service=http
Returns: Recent log entries
```

#### Packet Captures
```
GET /api/pcaps
Returns: List of PCAP files
```

#### Services
```
GET /api/services
Returns: Service status information
```

#### Attack Categories
```
GET /api/attack-categories
Returns: All attack category definitions
```

#### Attackers Summary
```
GET /api/attackers-summary
Returns: Summary of all attackers with location and attack types
```

---

## Attack Classification

### Attack Categories

#### Critical Severity
1. **SQL Injection** 💉
   - Patterns: `UNION SELECT`, `'; --`, `OR 1=1`, `DROP TABLE`
   
2. **Command Injection** ⚡
   - Patterns: `; cat /etc/passwd`, `| bash`, `` `whoami` ``, `$(id)`
   
3. **Malware Deployment** 🦠
   - Patterns: `wget http://...`, `curl | bash`, `powershell download`
   
4. **Data Exfiltration** 📤
   - Patterns: `cat /etc/passwd`, `type config`, `download file`

#### High Severity
5. **Brute Force** 🔨
   - Detection: 3+ login attempts or failed authentications
   
6. **Path Traversal** 📁
   - Patterns: `../`, `../../`, `/etc/passwd`, `c:\windows\system32`
   
7. **XSS** 🎯
   - Patterns: `<script>`, `javascript:`, `onerror=`, `alert(`
   
8. **Credential Harvesting** 🎣
   - Patterns: Password extraction, credential collection
   
9. **Privilege Escalation** ⬆️
   - Patterns: `sudo`, `su root`, `chmod 777`
   
10. **Denial of Service** 💥
    - Patterns: Fork bombs, infinite loops, flooding

#### Medium Severity
11. **Reconnaissance** 🔍
    - Patterns: `whoami`, `uname`, `ifconfig`, `netstat`
    
12. **Unauthorized Access** 🚫
    - Patterns: Admin panel access, root login attempts

---

## GeoIP Location

### Location Data

For each IP address, the system retrieves:
- **Country**: Country name and code
- **City**: City name
- **ISP**: Internet Service Provider
- **Region**: State/Province
- **Coordinates**: Latitude/Longitude (if available)

### Data Sources

Uses multiple free GeoIP services:
1. **ip-api.com** (primary)
2. **ipapi.co** (fallback)
3. **geojs.io** (fallback)

### Privacy

- Local/private IPs marked as "Local Network"
- Results cached to reduce API calls
- No personal data stored beyond IP addresses

---

## File Structure

```
markII/
├── docker-compose.yml          # Main orchestration
├── README.md                   # Project overview
├── DEPLOYMENT.md              # Deployment guide
├── SAFETY.md                  # Legal/ethical guidelines
├── ATTACKER_TRACKING.md       # Attacker tracking guide
├── ATTACK_CLASSIFICATION.md   # Attack classification docs
├── DASHBOARD_AUTH.md          # Authentication guide
├── PROJECT_COMPLETE_GUIDE.md  # This file
│
├── services/                   # Honeypot services
│   ├── ssh/
│   │   ├── ssh_honeypot.py
│   │   ├── Dockerfile
│   │   └── requirements.txt
│   ├── http/
│   │   ├── http_honeypot.py
│   │   ├── Dockerfile
│   │   └── requirements.txt
│   ├── db-api/
│   │   ├── db_api_honeypot.py
│   │   ├── Dockerfile
│   │   └── requirements.txt
│   └── smb-ftp/
│       ├── smb_ftp_honeypot.py
│       ├── Dockerfile
│       └── requirements.txt
│
├── monitoring/                 # Monitoring services
│   ├── packet-capture/
│   │   ├── packet_capture.py
│   │   ├── Dockerfile
│   │   └── requirements.txt
│   ├── log-aggregator/
│   │   ├── log_aggregator.py
│   │   ├── Dockerfile
│   │   └── requirements.txt
│   ├── ioc-detector/
│   │   ├── ioc_detector.py
│   │   ├── Dockerfile
│   │   └── requirements.txt
│   └── web-dashboard/
│       ├── web_dashboard.py
│       ├── auth.py
│       ├── geoip_lookup.py
│       ├── attack_classifier.py
│       ├── Dockerfile
│       ├── requirements.txt
│       └── templates/
│           ├── dashboard.html
│           ├── login.html
│           └── attackers.html
│
├── data/                      # Data directory (created at runtime)
│   ├── pcaps/                 # Packet captures
│   ├── logs/                  # Aggregated logs
│   ├── sessions/              # Session recordings
│   ├── iocs/                  # Detected IOCs
│   ├── ssh/                   # SSH logs
│   ├── http/                  # HTTP logs
│   ├── db/                    # Database logs
│   └── smb-ftp/               # SMB/FTP logs
│
├── setup.sh                   # Linux/Mac setup
└── setup.ps1                  # Windows setup
```

---

## Troubleshooting

### Dashboard Not Loading

**Problem**: Can't access `http://localhost:5000`

**Solutions**:
1. Check container status:
   ```bash
   docker-compose ps web-dashboard
   ```

2. View logs:
   ```bash
   docker-compose logs web-dashboard
   ```

3. Rebuild container:
   ```bash
   docker-compose build web-dashboard
   docker-compose up -d web-dashboard
   ```

4. Check port availability:
   ```bash
   netstat -an | grep 5000
   ```

### Services Not Starting

**Problem**: Services fail to start

**Solutions**:
1. Check Docker logs:
   ```bash
   docker-compose logs <service-name>
   ```

2. Verify ports not in use:
   ```bash
   netstat -tulpn | grep -E '2222|8080|5432|3306|445|21'
   ```

3. Check disk space:
   ```bash
   df -h
   ```

### No Data Showing

**Problem**: Dashboard shows no sessions/IOCs

**Solutions**:
1. Wait for services to generate data
2. Check if services are running:
   ```bash
   docker-compose ps
   ```

3. Verify data directories:
   ```bash
   ls -la data/
   ```

4. Check log aggregator:
   ```bash
   docker-compose logs log-aggregator
   ```

### GeoIP Not Working

**Problem**: Location shows "Unknown"

**Solutions**:
1. Check internet connection (VM needs internet for GeoIP)
2. Check logs:
   ```bash
   docker-compose logs web-dashboard | grep -i geoip
   ```

3. Verify requests library installed

### Alerts Not Sending

**Problem**: No alerts received

**Solutions**:
1. Check `.env` configuration
2. Verify webhook URLs are correct
3. Test webhook manually:
   ```bash
   curl -X POST $WEBHOOK_URL -d '{"test": true}'
   ```

4. Check IOC detector logs:
   ```bash
   docker-compose logs ioc-detector
   ```

---

## Best Practices

### Security

1. **Change Default Credentials**
   - Dashboard: Change `admin`/`honeypot2024`
   - See `DASHBOARD_AUTH.md`

2. **Network Isolation**
   - Use isolated VM or network
   - Never deploy on production networks
   - Use SSH tunnels for access

3. **Data Protection**
   - Encrypt stored data
   - Limit access to data directories
   - Regular backups

### Performance

1. **Disk Management**
   - Monitor `./data/` directory size
   - Rotate logs regularly
   - Limit PCAP file retention

2. **Resource Limits**
   - Set Docker resource limits
   - Monitor container resource usage

### Maintenance

1. **Regular Updates**
   - Keep Docker updated
   - Update Python packages
   - Review security patches

2. **Monitoring**
   - Check logs regularly
   - Monitor disk usage
   - Review alerts

---

## Legal & Ethical Use

⚠️ **CRITICAL WARNINGS**

### Legal Requirements

- **Only use in authorized environments**
- **Never deploy on production networks**
- **Comply with all applicable laws**
- **Obtain written permission before deployment**

### Ethical Guidelines

- Use for security research and education only
- Do not use for illegal activities
- Respect privacy and data protection laws
- Report incidents appropriately

See `SAFETY.md` for complete legal and ethical guidelines.

---

## Support & Resources

### Documentation Files

- `README.md` - Quick overview
- `DEPLOYMENT.md` - Detailed deployment guide
- `SAFETY.md` - Legal and ethical guidelines
- `ATTACKER_TRACKING.md` - Attacker tracking guide
- `ATTACK_CLASSIFICATION.md` - Attack classification details
- `DASHBOARD_AUTH.md` - Authentication configuration
- `PROJECT_COMPLETE_GUIDE.md` - This comprehensive guide

### Quick Commands

```bash
# Start platform
docker-compose up -d

# Stop platform
docker-compose down

# View logs
docker-compose logs -f

# Restart service
docker-compose restart <service-name>

# Rebuild service
docker-compose build <service-name>
docker-compose up -d <service-name>

# Check status
docker-compose ps

# Remove all data
docker-compose down -v
rm -rf data/
```

---

## Summary

This honeypot platform provides:

✅ **Complete Honeypot Solution**
- Multiple protocol support
- Realistic service simulation
- Comprehensive data collection

✅ **Advanced Monitoring**
- Real-time dashboard
- Attack classification
- Location tracking
- IOC detection

✅ **Security & Isolation**
- Network isolation
- No real exploits
- Safe for research

✅ **Easy Deployment**
- Docker-based
- Simple setup
- VM-ready

✅ **Professional Interface**
- Modern web dashboard
- Secure authentication
- Real-time updates

**Perfect for**: Security research, threat intelligence, education, authorized security testing.

---

**Remember**: Always use responsibly and legally. See `SAFETY.md` for complete guidelines.
