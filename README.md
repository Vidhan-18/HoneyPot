# 🛡️ Honeypot Defense Platform

[![Docker](https://img.shields.io/badge/Docker-Ready-blue?logo=docker)](https://docker.com)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.9+-blue?logo=python)](https://python.org)

A production-ready, multi-service honeypot platform designed to detect, analyze, and alert on cyber attacks in real-time. Features an interactive world map, comprehensive alerting system, and beautiful dark-themed dashboard.

![Dashboard Preview](https://via.placeholder.com/800x400/1a1429/7c3aed?text=Honeypot+Dashboard+Preview)

## ✨ Features

### 🎯 Honeypot Services
- **HTTP Honeypot** - Fake corporate portal with login page
- **SSH Honeypot** - Emulated SSH server capturing brute force attempts
- **FTP Honeypot** - File transfer protocol honeypot
- **SMB Honeypot** - Windows file sharing service emulation
- **Database Honeypot** - MySQL-like database service

### 🗺️ Interactive Threat Map
- Real-time world map with attack visualization
- Heatmap overlay showing attack intensity
- Country-specific threat intelligence
- Click-to-explore detailed attack data
- Time range and attack type filters

### 🚨 Alerting System
- **Telegram Bot** - Instant mobile notifications
- **Slack Integration** - Team collaboration alerts
- **Webhook Support** - Custom integrations (Discord, Teams, etc.)
- **IOC Detection** - Automatic indicator of compromise identification
- **Retry Logic** - Reliable delivery with exponential backoff

### 📊 Monitoring & Analytics
- Real-time session tracking
- Attack classification and categorization
- Geographic IP lookup
- Packet capture (PCAP) support
- Comprehensive logging

### 🎨 Premium UI
- Dark theme with glassmorphism design
- Aurora violet and coral accent colors
- Responsive layout for all devices
- Smooth animations and micro-interactions
- Modern typography (Inter + Space Grotesk)

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        ATTACKERS                            │
└──────────────────────┬──────────────────────────────────────┘
                       │
       ┌───────────────┼───────────────┐
       │               │               │
       ▼               ▼               ▼
┌────────────┐  ┌────────────┐  ┌────────────┐
│   HTTP     │  │    SSH     │  │    FTP     │
│  :8080     │  │   :2222    │  │   :2121    │
└─────┬──────┘  └─────┬──────┘  └─────┬──────┘
      │               │               │
      └───────────────┼───────────────┘
                      │
                      ▼
┌─────────────────────────────────────────┐
│         LOG AGGREGATOR                  │
│    (Collects & normalizes logs)         │
└─────────────────┬───────────────────────┘
                  │
      ┌───────────┼───────────┐
      │           │           │
      ▼           ▼           ▼
┌─────────┐ ┌─────────┐ ┌─────────┐
│  IOC    │ │  PCAP   │ │   WEB   │
│ DETECTOR│ │ CAPTURE │ │DASHBOARD│
└────┬────┘ └─────────┘ └────┬────┘
     │                        │
     ▼                        ▼
┌─────────┐            ┌─────────────┐
│Telegram │            │  Interactive│
│  Bot    │            │    Map      │
└─────────┘            └─────────────┘
```

## 🚀 Quick Start

### Prerequisites
- [Docker](https://docs.docker.com/get-docker/)
- [Docker Compose](https://docs.docker.com/compose/install/)

### Installation

1. **Clone the repository:**
```bash
git clone https://github.com/yourusername/honeypot-platform.git
cd honeypot-platform
```

2. **Configure environment:**
```bash
cp .env.example .env
# Edit .env with your settings (see Configuration section)
```

3. **Start the platform:**
```bash
docker-compose up -d
```

4. **Access the dashboard:**
- Dashboard: http://localhost:5000
- Default credentials: `admin` / `honeypot2024`
- Change credentials in `.env` for production!

### Telegram Bot Setup (Optional but Recommended)

1. Message [@BotFather](https://t.me/botfather) on Telegram
2. Create a new bot with `/newbot`
3. Copy the bot token to your `.env` file
4. Get your chat ID by messaging the bot and visiting:
   ```
   https://api.telegram.org/bot<YOUR_TOKEN>/getUpdates
   ```
5. Add both to `.env`:
   ```
   TELEGRAM_BOT_TOKEN=your_token_here
   TELEGRAM_CHAT_ID=your_chat_id_here
   ```

## ⚙️ Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `TELEGRAM_BOT_TOKEN` | Telegram bot token from @BotFather | - |
| `TELEGRAM_CHAT_ID` | Your Telegram chat ID | - |
| `SLACK_WEBHOOK` | Slack incoming webhook URL | - |
| `WEBHOOK_URL` | Generic webhook endpoint | - |
| `ADMIN_USERNAME` | Dashboard admin username | admin |
| `ADMIN_PASSWORD` | Dashboard admin password | honeypot2024 |
| `ALERT_THRESHOLD` | Events before alerting | 5 |

See `.env.example` for complete configuration options.

### Port Configuration

| Service | Port | Description |
|---------|------|-------------|
| Dashboard | 5000 | Web UI and API |
| HTTP Honeypot | 8080 | Fake corporate portal |
| SSH Honeypot | 2222 | SSH emulation |
| FTP Honeypot | 2121 | FTP service |
| SMB Honeypot | 445 | Windows file sharing |
| DB Honeypot | 3306 | Database service |

## 📁 Project Structure

```
honeypot-platform/
├── .github/
│   └── workflows/
│       └── ci.yml              # CI/CD pipeline
├── data/                       # Data storage (gitignored)
│   ├── logs/
│   ├── sessions/
│   ├── pcaps/
│   └── iocs/
├── monitoring/
│   ├── ioc-detector/          # IOC detection & alerting
│   │   ├── alert_manager.py   # Centralized alerting
│   │   ├── ioc_detector.py    # Pattern detection
│   │   ├── Dockerfile
│   │   └── requirements.txt
│   ├── log-aggregator/        # Log collection
│   ├── packet-capture/        # Network capture
│   └── web-dashboard/         # Web UI
│       ├── templates/
│       │   ├── dashboard.html # Main dashboard
│       │   └── login.html     # Admin login
│       ├── web_dashboard.py   # Flask backend
│       ├── attack_classifier.py
│       ├── geoip_lookup.py
│       └── auth.py
├── services/
│   ├── http/                  # HTTP honeypot
│   ├── ssh/                   # SSH honeypot
│   ├── smb-ftp/              # SMB/FTP honeypot
│   └── db-api/               # Database honeypot
├── .env.example              # Environment template
├── .gitignore               # Git ignore rules
├── docker-compose.yml       # Docker orchestration
├── LICENSE                  # MIT License
└── README.md               # This file
```

## 🔧 Development

### Running Locally (without Docker)

1. **Create virtual environment:**
```bash
python -m venv venv
source venv/bin/activate  # Linux/Mac
# or
venv\Scripts\activate     # Windows
```

2. **Install dependencies:**
```bash
pip install -r monitoring/web-dashboard/requirements.txt
pip install -r monitoring/ioc-detector/requirements.txt
```

3. **Run services:**
```bash
# Terminal 1 - Dashboard
python monitoring/web-dashboard/web_dashboard.py

# Terminal 2 - IOC Detector
python monitoring/ioc-detector/ioc_detector.py
```

### Testing Alerts

```bash
cd monitoring/ioc-detector
python alert_manager.py
```

This will test all configured alert channels.

## 🔒 Security Considerations

⚠️ **IMPORTANT**: This is a honeypot system designed to attract attackers. Follow these guidelines:

1. **Network Isolation**: Run in an isolated network segment
2. **Change Defaults**: Update all default passwords in production
3. **Legal Compliance**: Ensure deployment complies with local laws
4. **Data Retention**: Configure log rotation to manage disk space
5. **Access Control**: Limit dashboard access to authorized personnel

## 📝 API Documentation

### REST Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/sessions` | GET | List all sessions |
| `/api/session/<id>` | GET | Get session details |
| `/api/stats` | GET | Get statistics |
| `/api/country/<code>` | GET | Get country threat data |
| `/api/iocs` | GET | List detected IOCs |

### WebSocket Events

| Event | Description |
|-------|-------------|
| `connect` | Client connected |
| `disconnect` | Client disconnected |
| `new_session` | New attack session |
| `session_update` | Session data updated |

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [Leaflet.js](https://leafletjs.com/) - Interactive maps
- [Chart.js](https://www.chartjs.org/) - Data visualization
- [Flask](https://flask.palletsprojects.com/) - Web framework
- [Socket.IO](https://socket.io/) - Real-time communication

## 📞 Support

- 📧 Email: support@example.com
- 💬 Telegram: [@YourSupportBot](https://t.me/yoursupportbot)
- 🐛 Issues: [GitHub Issues](https://github.com/yourusername/honeypot-platform/issues)

---

<p align="center">
  Made with ❤️ for the cybersecurity community
</p>
