# Quick Start Guide

## Windows Setup

1. **Run the setup script:**
   ```powershell
   .\setup.ps1
   ```

2. **Configure alerts (optional):**
   Edit `.env` file with your webhook/Slack/Telegram credentials

3. **Start the platform:**
   ```powershell
   docker-compose up -d
   ```

4. **View logs:**
   ```powershell
   docker-compose logs -f
   ```

## Linux/Mac Setup

1. **Run the setup script:**
   ```bash
   chmod +x setup.sh
   ./setup.sh
   ```

2. **Configure alerts (optional):**
   Edit `.env` file with your webhook/Slack/Telegram credentials

3. **Start the platform:**
   ```bash
   docker-compose up -d
   ```

4. **View logs:**
   ```bash
   docker-compose logs -f
   ```

## Service Ports

- **SSH**: `localhost:2222`
- **HTTP**: `http://localhost:8080`
- **PostgreSQL**: `localhost:5432`
- **MySQL**: `localhost:3306`
- **SMB**: `localhost:445`
- **FTP**: `localhost:21`
- **Web Dashboard**: `http://localhost:5000` ⭐
- **Attacker Tracking**: `http://localhost:5000/attackers` 🎯

## Data Location

All collected data is stored in `./data/`:
- `data/pcaps/` - Packet captures
- `data/logs/` - Aggregated logs
- `data/sessions/` - Session recordings
- `data/iocs/` - Detected IOCs

## Important Notes

⚠️ **CRITICAL**: 
- Only deploy in isolated, authorized environments
- Never deploy on production networks
- Read SAFETY.md before deployment
- All attacker interactions are logged

## Troubleshooting

**Services not starting?**
```bash
docker-compose logs <service-name>
```

**No alerts?**
- Check `.env` configuration
- Verify webhook URLs are correct
- Check IOC detector logs: `docker-compose logs ioc-detector`

**Need help?**
- See DEPLOYMENT.md for detailed guide
- See README.md for overview
- See SAFETY.md for legal requirements

