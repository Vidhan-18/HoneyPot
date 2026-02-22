# 🚀 Start Here - Quick Setup Guide

## Step 1: Run Setup Script

**Windows:**
```powershell
.\setup.ps1
```

**Linux/Mac:**
```bash
chmod +x setup.sh
./setup.sh
```

This will:
- Create necessary data directories
- Create `.env` file for configuration

## Step 2: Configure Alerts (Optional)

Edit `.env` file to add your alerting credentials:
```bash
WEBHOOK_URL=https://your-webhook-url.com
SLACK_WEBHOOK=https://hooks.slack.com/services/YOUR/WEBHOOK
TELEGRAM_BOT_TOKEN=your_bot_token
TELEGRAM_CHAT_ID=your_chat_id
```

## Step 3: Start the Platform

```bash
docker-compose up -d
```

This starts all services:
- SSH Honeypot (port 2222)
- HTTP Honeypot (port 8080)
- Database API Honeypot (ports 5432, 3306)
- SMB/FTP Honeypot (ports 445, 21)
- Packet Capture
- Log Aggregator
- IOC Detector
- **Web Dashboard (port 5000)** ⭐

## Step 4: Access Web Dashboard

Open your browser and go to:

```
http://localhost:5000
```

## Step 5: Monitor Activity

The dashboard shows:
- ✅ Real-time statistics
- ✅ All captured sessions
- ✅ Detected IOCs
- ✅ Live logs
- ✅ Service status

## What's Next?

1. **View Logs**: Check `docker-compose logs -f` for detailed logs
2. **Test Honeypots**: Try connecting to the services
3. **View Data**: All data is stored in `./data/` directory
4. **Read Documentation**: 
   - `README.md` - Overview
   - `DEPLOYMENT.md` - Detailed guide
   - `WEB_DASHBOARD.md` - Dashboard guide
   - `SAFETY.md` - Legal requirements

## Important Reminders

⚠️ **CRITICAL:**
- Only deploy in isolated, authorized environments
- Never deploy on production networks
- Read SAFETY.md before deployment
- All interactions are logged

## Troubleshooting

**Services not starting?**
```bash
docker-compose logs <service-name>
```

**Dashboard not loading?**
- Check if port 5000 is available
- Verify web-dashboard container is running: `docker-compose ps`
- Check logs: `docker-compose logs web-dashboard`

**No data showing?**
- Wait a few minutes for services to generate data
- Check if other services are running
- Verify data directories exist: `ls -la data/`

## Stop the Platform

```bash
docker-compose down
```

To remove all data:
```bash
docker-compose down -v
rm -rf data/
```

---

**Ready to go! Open http://localhost:5000 to start monitoring! 🎉**




