# Deployment Guide

## Prerequisites

- Docker Engine 20.10+
- Docker Compose 2.0+
- At least 4GB RAM
- 10GB free disk space
- Linux-based host (recommended) or Windows with WSL2

## Quick Start

### 1. Clone and Configure

```bash
# Clone or extract the project
cd markII

# Copy environment file
cp .env.example .env

# Edit .env with your alerting configuration (optional)
nano .env
```

### 2. Configure Alerting (Optional)

Edit `.env` file:

```bash
# Generic webhook
WEBHOOK_URL=https://your-webhook-url.com/endpoint

# Slack webhook
SLACK_WEBHOOK=https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK

# Telegram (get bot token from @BotFather)
TELEGRAM_BOT_TOKEN=your_bot_token
TELEGRAM_CHAT_ID=your_chat_id
```

### 3. Start the Platform

```bash
# Build and start all services
docker-compose up -d

# View logs
docker-compose logs -f

# View specific service logs
docker-compose logs -f ssh-honeypot
```

### 4. Verify Services

Check that all services are running:

```bash
docker-compose ps
```

You should see all services in "Up" state:
- ssh-honeypot
- http-honeypot
- db-api-honeypot
- smb-ftp-honeypot
- packet-capture
- log-aggregator
- ioc-detector

### 5. Test Access

The honeypot services are exposed on:
- SSH: `localhost:2222`
- HTTP: `http://localhost:8080`
- PostgreSQL: `localhost:5432`
- MySQL: `localhost:3306`
- SMB: `localhost:445`
- FTP: `localhost:21`
- **Web Dashboard**: `http://localhost:5000` ⭐

**⚠️ WARNING:** Only expose these ports in isolated test environments!

### Access Web Dashboard

After starting the platform, open your browser and navigate to:
```
http://localhost:5000
```

The dashboard provides:
- Real-time statistics
- Session viewer with details
- IOC detection alerts
- Live log viewer
- Service status monitoring

## Network Isolation

The Docker Compose configuration uses an **internal network** by default, which prevents egress. However, for additional security:

### Option 1: Use Docker Internal Network (Default)

The `docker-compose.yml` already configures:
```yaml
networks:
  honeypot-network:
    driver: bridge
    internal: true  # No external access
```

### Option 2: Additional Firewall Rules

On the host system, add firewall rules:

```bash
# Block all outbound traffic from honeypot containers
iptables -A DOCKER-USER -s <honeypot-network> -j DROP

# Or use UFW
ufw deny from <honeypot-network>
```

### Option 3: Isolated VLAN

Deploy on a dedicated VLAN with no routing to other networks.

## Data Collection

All data is stored in the `./data` directory:

```
data/
├── pcaps/          # Packet captures (.pcap files)
├── logs/           # Aggregated logs
├── sessions/       # Session recordings (JSON)
├── iocs/           # Detected IOCs
├── ssh/            # SSH honeypot logs
├── http/           # HTTP honeypot logs
├── db/             # Database honeypot logs
└── smb-ftp/        # SMB/FTP honeypot logs
```

## Monitoring

### View Real-time Logs

```bash
# All services
docker-compose logs -f

# Specific service
docker-compose logs -f ioc-detector
```

### Check Detected IOCs

```bash
# List detected IOCs
ls -lh data/iocs/

# View an IOC
cat data/iocs/ioc_*.json
```

### View Packet Captures

```bash
# List PCAP files
ls -lh data/pcaps/

# Analyze with tcpdump
tcpdump -r data/pcaps/capture_*.pcap

# Or use Wireshark
wireshark data/pcaps/capture_*.pcap
```

### View Session Recordings

```bash
# List sessions
ls -lh data/sessions/

# View a session
cat data/sessions/ssh_session_*.json | jq .
```

## Stopping the Platform

```bash
# Stop all services
docker-compose down

# Stop and remove volumes (deletes all data)
docker-compose down -v
```

## Troubleshooting

### Services Not Starting

1. Check Docker logs:
   ```bash
   docker-compose logs <service-name>
   ```

2. Verify ports are not in use:
   ```bash
   netstat -tulpn | grep -E '2222|8080|5432|3306|445|21'
   ```

3. Check disk space:
   ```bash
   df -h
   ```

### No Alerts Received

1. Verify environment variables:
   ```bash
   docker-compose exec ioc-detector env | grep -E 'WEBHOOK|SLACK|TELEGRAM'
   ```

2. Check IOC detector logs:
   ```bash
   docker-compose logs ioc-detector
   ```

3. Test webhook manually:
   ```bash
   curl -X POST $WEBHOOK_URL -d '{"test": true}'
   ```

### Packet Capture Not Working

1. Ensure privileged mode is enabled (already in docker-compose.yml)
2. Check if tcpdump is installed in container:
   ```bash
   docker-compose exec packet-capture which tcpdump
   ```

3. Verify network interface:
   ```bash
   docker-compose exec packet-capture ip addr
   ```

## Security Best Practices

1. **Never deploy on production networks**
2. **Use isolated network/VLAN**
3. **Restrict physical access to the host**
4. **Encrypt stored data**
5. **Regularly rotate log files**
6. **Monitor disk usage**
7. **Keep Docker and system updated**
8. **Use strong authentication for alerting endpoints**

## Performance Tuning

### Reduce Log Volume

Edit service environment variables:
```yaml
environment:
  - LOG_LEVEL=WARNING  # Reduce verbosity
```

### Limit Packet Capture Size

Edit `monitoring/packet-capture/packet_capture.py`:
```python
'-C', '50',  # Rotate at 50MB instead of 100MB
'-W', '5',   # Keep 5 files instead of 10
```

### Adjust Alert Threshold

Edit `.env`:
```bash
ALERT_THRESHOLD=10  # Only alert after 10 IOCs
```

## Backup and Recovery

### Backup Data

```bash
# Create backup
tar -czf honeypot-backup-$(date +%Y%m%d).tar.gz data/

# Restore
tar -xzf honeypot-backup-YYYYMMDD.tar.gz
```

### Export Logs

```bash
# Export all logs
docker-compose exec log-aggregator cat /logs/aggregated.log > exported-logs.txt
```

## Support

For issues or questions:
1. Check the logs first
2. Review this deployment guide
3. Check SAFETY.md for legal requirements
4. Open an issue on the project repository

---

**Remember: Always deploy in isolated, authorized environments only!**

