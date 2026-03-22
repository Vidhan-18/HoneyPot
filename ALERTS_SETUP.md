# Alert System Setup Guide

This guide covers setting up the Telegram Bot, Slack, and webhook alerting system for the Honeypot Platform.

## Features

- **Telegram Bot Alerts**: Real-time mobile notifications with rich formatting
- **Slack Integration**: Team collaboration alerts
- **Webhook Support**: Custom integrations (Discord, Teams, etc.)
- **Retry Logic**: Automatic retries with exponential backoff
- **Structured Alerts**: Severity levels, metadata, and source tracking

## Quick Start

### 1. Configure Environment Variables

Copy the example file and fill in your values:

```bash
cp .env.example .env
```

Edit `.env` with your preferred editor:

```bash
# Telegram (Recommended)
TELEGRAM_BOT_TOKEN=your_bot_token_here
TELEGRAM_CHAT_ID=your_chat_id_here

# Slack (Optional)
SLACK_WEBHOOK=https://hooks.slack.com/services/YOUR/WEBHOOK/URL

# Generic Webhook (Optional)
WEBHOOK_URL=https://your-webhook-endpoint.com/alerts
```

### 2. Telegram Bot Setup

1. **Create a Bot**:
   - Open Telegram and search for `@BotFather`
   - Send `/newbot` and follow instructions
   - Save the bot token (looks like: `123456789:ABCdefGHIjklMNOpqrsTUVwxyz`)

2. **Get Your Chat ID**:
   - Message your new bot
   - Visit: `https://api.telegram.org/bot<YOUR_BOT_TOKEN>/getUpdates`
   - Look for `"chat":{"id":123456789` - that's your chat ID

3. **Test the Bot**:
   ```bash
   cd monitoring/ioc-detector
   python alert_manager.py
   ```

### 3. Slack Setup (Optional)

1. Go to [Slack API Apps](https://api.slack.com/apps)
2. Create New App → From Scratch
3. Enable "Incoming Webhooks"
4. Add New Webhook to Workspace
5. Copy the Webhook URL to your `.env` file

## Alert Severity Levels

| Severity | Emoji | Use Case |
|----------|-------|----------|
| Critical | 🔴 | SQL injection, command injection |
| High | 🚨 | Malicious commands, path traversal |
| Medium | ⚠️ | XSS attempts, suspicious activity |
| Low | ℹ️ | Informational events |

## Testing Alerts

### Manual Test

```python
from alert_manager import send_alert

# Send a test alert
send_alert(
    title="Test Alert",
    message="This is a test from the honeypot system",
    severity="low",
    metadata={"test": True, "source": "manual"}
)
```

### Startup Test

The IOC detector automatically sends a test alert on startup if any channel is configured. Check the logs:

```bash
docker-compose logs -f ioc-detector
```

## API Usage

### Basic Alert

```python
from alert_manager import send_alert

send_alert(
    title="Brute Force Detected",
    message="50 failed login attempts from 192.168.1.100",
    severity="high",
    metadata={
        "ip": "192.168.1.100",
        "attempts": 50,
        "service": "ssh"
    }
)
```

### Advanced Usage

```python
from alert_manager import get_alert_manager, AlertMessage, AlertChannel
from datetime import datetime

# Create custom alert
alert = AlertMessage(
    title="Custom Event",
    message="Detailed description here",
    severity="critical",
    source="custom_module",
    timestamp=datetime.utcnow(),
    metadata={"key": "value"}
)

# Send to specific channels only
manager = get_alert_manager()
results = manager.send_alert(
    alert,
    channels=[AlertChannel.TELEGRAM, AlertChannel.SLACK]
)

# Check results
for channel, success in results.items():
    print(f"{channel}: {'✓' if success else '✗'}")
```

## Troubleshooting

### Telegram Bot Not Working

1. **Check Token**: Ensure token format is correct
2. **Chat ID**: Must be numeric (include the `-` for groups)
3. **Bot Started**: Message `/start` to your bot
4. **Privacy Mode**: Disable in BotFather if needed

### Slack Not Receiving

1. **Webhook URL**: Must start with `https://hooks.slack.com/`
2. **Channel Access**: Ensure bot has access to the channel
3. **Rate Limits**: Slack has rate limits (1 msg/sec)

### View Logs

```bash
# IOC Detector logs
docker-compose logs -f ioc-detector

# All service logs
docker-compose logs -f
```

### Test Connections

```bash
cd monitoring/ioc-detector
python -c "from alert_manager import get_alert_manager; get_alert_manager().test_connections()"
```

## Architecture

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│   Log Files     │────▶│  IOC Detector    │────▶│  Alert Manager  │
└─────────────────┘     └──────────────────┘     └────────┬────────┘
                                                          │
                              ┌───────────────────────────┼───────────┐
                              │                           │           │
                              ▼                           ▼           ▼
                        ┌─────────┐                ┌──────────┐  ┌─────────┐
                        │Telegram │                │  Slack   │  │ Webhook │
                        └─────────┘                └──────────┘  └─────────┘
```

## Environment Variables Reference

| Variable | Required | Description |
|----------|----------|-------------|
| `TELEGRAM_BOT_TOKEN` | No* | Bot token from @BotFather |
| `TELEGRAM_CHAT_ID` | No* | Your Telegram chat ID |
| `SLACK_WEBHOOK` | No | Slack incoming webhook URL |
| `WEBHOOK_URL` | No | Generic webhook endpoint |
| `ALERT_THRESHOLD` | No | Min events before alert (default: 5) |

*At least one alerting channel is recommended
