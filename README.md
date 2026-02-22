<<<<<<< HEAD
# Advanced Dual-Mode Honeypot Platform

**⚠️ LEGAL AND ETHICAL WARNING ⚠️**

This honeypot platform is designed **EXCLUSIVELY** for:
- Security research and education
- Authorized security testing in controlled environments
- Academic study of attack patterns and threat intelligence

**DO NOT:**
- Deploy on production networks without explicit authorization
- Use on networks you do not own or have written permission to test
- Deploy without proper network isolation and monitoring
- Use for any illegal activities or unauthorized access attempts

**By using this software, you acknowledge that:**
- You are solely responsible for compliance with all applicable laws
- The authors and contributors are not liable for misuse
- You have proper authorization to deploy and operate this system
- All attacker interactions are logged and may be used for legal purposes

---

## Overview

> 📖 **For complete technical documentation, see [PROJECT_COMPLETE_GUIDE.md](PROJECT_COMPLETE_GUIDE.md)**

## Overview

This is a containerized honeypot platform that simulates realistic services (SSH, HTTP, Database APIs, SMB/FTP) to attract and monitor attacker behavior. The system captures:

- Full packet captures (PCAP)
- Session recordings
- Detailed logs of all interactions
- Indicators of Compromise (IOCs)
- Automated alerts via webhook/Slack/Telegram

## Architecture

- **Isolated Network**: All services run in an isolated Docker network with no external egress
- **Multiple Honeypot Services**: SSH, HTTP, Database API, SMB/FTP
- **Comprehensive Monitoring**: Packet capture, log aggregation, IOC detection
- **Alerting**: Real-time alerts via multiple channels

## Quick Start

### Prerequisites

- Docker and Docker Compose
- At least 4GB RAM
- 10GB free disk space

### Configuration

1. Copy `.env.example` to `.env` and configure alerting:

```bash
cp .env.example .env
# Edit .env with your webhook/Slack/Telegram credentials
```

2. Start the platform:

```bash
docker-compose up -d
```

3. Check logs:

```bash
docker-compose logs -f
```

### Services

- **SSH Honeypot**: Port 2222
- **HTTP Honeypot**: Port 8080
- **Database API**: Ports 5432 (PostgreSQL), 3306 (MySQL)
- **SMB/FTP Honeypot**: Ports 445 (SMB), 21 (FTP), 139 (NetBIOS)
- **Web Dashboard**: Port 5000 (http://localhost:5000)
  - **Login Required**: Default credentials: `admin` / `honeypot2024`
  - See `DASHBOARD_AUTH.md` for authentication details

## Attacker Tracking

**Everything attackers do is logged:**
- ✅ **IP Addresses** - Source IP of every connection
- ✅ **Authentication** - All usernames and passwords tried
- ✅ **Commands** - Every command executed
- ✅ **Requests** - All HTTP requests with headers
- ✅ **Queries** - SQL queries attempted
- ✅ **File Operations** - Uploads, downloads, deletions
- ✅ **Full Packet Captures** - Complete network traffic

**View attackers in the dashboard:**
- Open `http://localhost:5000/attackers`
- See all attackers grouped by IP address
- View their sessions, commands, and activities
- **Location information** - Country, city, ISP for each IP
- **Attack classification** - Automatic categorization of attack types
- **Severity indicators** - Color-coded by attack severity
- Filter by IP or protocol

**Attack Classification:**
- 12 attack categories (SQL Injection, Command Injection, Brute Force, etc.)
- Severity levels (Critical, High, Medium, Low)
- Automatic pattern detection
- Visual attack badges in dashboard

See `ATTACKER_TRACKING.md`, `HOW_ATTACKERS_CONNECT.md`, and `ATTACK_CLASSIFICATION.md` for detailed information.

## Data Collection

All data is stored in the `./data` directory:

- `./data/pcaps/` - Packet captures
- `./data/logs/` - Aggregated logs
- `./data/sessions/` - Session recordings
- `./data/iocs/` - Detected IOCs
- `./data/ssh/`, `./data/http/`, etc. - Service-specific logs

## Alerting Configuration

Configure alerts in `.env`:

- `WEBHOOK_URL` - Generic webhook endpoint
- `SLACK_WEBHOOK` - Slack webhook URL
- `TELEGRAM_BOT_TOKEN` - Telegram bot token
- `TELEGRAM_CHAT_ID` - Telegram chat ID

## Safety Features

1. **Network Isolation**: Internal Docker network prevents egress
2. **Container Isolation**: Each service runs in its own container
3. **No Real Exploits**: All services are simulated, no actual vulnerabilities
4. **Comprehensive Logging**: All interactions are logged for analysis

## Stopping the Platform

```bash
docker-compose down
```

To remove all data:

```bash
docker-compose down -v
rm -rf ./data
```

## License

This project is provided for educational and research purposes only. See LICENSE file for details.

## Support

For issues, questions, or contributions, please open an issue on the project repository.

---

**Remember: Only deploy in authorized, isolated environments. Unauthorized use may violate laws in your jurisdiction.**

=======
# HoneyPot
>>>>>>> 1c9d9618ae17653bebe01ead81a9a422f9ab7d70
