# Project Structure

```
markII/
├── docker-compose.yml          # Main orchestration file
├── README.md                   # Project overview
├── QUICKSTART.md              # Quick start guide
├── DEPLOYMENT.md              # Detailed deployment guide
├── SAFETY.md                  # Safety and legal guidelines
├── LICENSE                    # License file
├── setup.sh                   # Linux/Mac setup script
├── setup.ps1                  # Windows setup script
├── .gitignore                 # Git ignore rules
│
├── services/                  # Honeypot services
│   ├── ssh/
│   │   ├── Dockerfile
│   │   ├── requirements.txt
│   │   └── ssh_honeypot.py    # SSH honeypot implementation
│   │
│   ├── http/
│   │   ├── Dockerfile
│   │   ├── requirements.txt
│   │   └── http_honeypot.py   # HTTP honeypot implementation
│   │
│   ├── db-api/
│   │   ├── Dockerfile
│   │   ├── requirements.txt
│   │   └── db_api_honeypot.py # Database API honeypot (PostgreSQL/MySQL)
│   │
│   └── smb-ftp/
│       ├── Dockerfile
│       ├── requirements.txt
│       └── smb_ftp_honeypot.py # SMB/FTP honeypot implementation
│
├── monitoring/                # Monitoring and analysis services
│   ├── packet-capture/
│   │   ├── Dockerfile
│   │   ├── requirements.txt
│   │   └── packet_capture.py  # Packet capture service (tcpdump)
│   │
│   ├── log-aggregator/
│   │   ├── Dockerfile
│   │   ├── requirements.txt
│   │   └── log_aggregator.py  # Log aggregation service
│   │
│   └── ioc-detector/
│       ├── Dockerfile
│       ├── requirements.txt
│       └── ioc_detector.py     # IOC detection and alerting
│
└── data/                      # Data directory (created at runtime)
    ├── pcaps/                 # Packet captures
    ├── logs/                  # Aggregated logs
    ├── sessions/               # Session recordings
    ├── iocs/                  # Detected IOCs
    ├── ssh/                   # SSH honeypot logs
    ├── http/                  # HTTP honeypot logs
    ├── db/                    # Database honeypot logs
    └── smb-ftp/               # SMB/FTP honeypot logs
```

## Service Overview

### Honeypot Services

1. **SSH Honeypot** (`services/ssh/`)
   - Simulates SSH server
   - Logs all login attempts and commands
   - Port: 2222

2. **HTTP Honeypot** (`services/http/`)
   - Simulates web server with fake endpoints
   - Logs all HTTP requests
   - Port: 8080

3. **Database API Honeypot** (`services/db-api/`)
   - Simulates PostgreSQL and MySQL servers
   - Logs connection attempts and queries
   - Ports: 5432 (PostgreSQL), 3306 (MySQL)

4. **SMB/FTP Honeypot** (`services/smb-ftp/`)
   - Simulates SMB and FTP servers
   - Logs file operations and login attempts
   - Ports: 445 (SMB), 21 (FTP), 139 (NetBIOS)

### Monitoring Services

1. **Packet Capture** (`monitoring/packet-capture/`)
   - Captures all network traffic
   - Uses tcpdump for packet capture
   - Stores PCAP files in `data/pcaps/`

2. **Log Aggregator** (`monitoring/log-aggregator/`)
   - Aggregates logs from all honeypot services
   - Creates unified log file
   - Watches log directories for changes

3. **IOC Detector** (`monitoring/ioc-detector/`)
   - Detects indicators of compromise
   - Sends alerts via webhook/Slack/Telegram
   - Stores detected IOCs in `data/iocs/`

## Data Flow

```
Attacker → Honeypot Services → Logs → Log Aggregator → IOC Detector → Alerts
                ↓
         Packet Capture → PCAP Files
                ↓
         Session Recording → JSON Files
```

## Network Architecture

- **Honeypot Network**: Isolated Docker bridge network
- **Host Network**: Used only for IOC detector (alerting)
- **No Egress**: Honeypot services cannot access external networks
- **Controlled Egress**: IOC detector can send alerts via host network

## Security Features

1. **Network Isolation**: Services run in isolated Docker network
2. **No Real Exploits**: All services are simulated, no actual vulnerabilities
3. **Comprehensive Logging**: All interactions are logged
4. **Session Recording**: Full session recordings in JSON format
5. **IOC Detection**: Automatic detection of malicious patterns
6. **Alerting**: Real-time alerts via multiple channels


