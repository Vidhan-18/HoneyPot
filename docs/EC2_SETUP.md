# AWS EC2 Setup Guide

Production target for this repo:

- `Vercel` hosts the dashboard
- `Supabase` stores sessions/logs/IOCs metadata
- `AWS EC2` runs honeypot services + `supabase-sync`

## 1) Launch EC2 Instance

- **AMI:** Ubuntu Server 22.04 LTS
- **Instance type:** `t3.large` (minimum practical) or higher
- **Storage:** 60-100 GB gp3 (pcap/log growth can be high)
- **Public IP:** enabled
- **IAM role:** optional now (required later if you add S3/CloudWatch integrations)

## 2) Security Group (Inbound)

Apply least privilege. Suggested inbound rules:

- `22/tcp` SSH: only your office/home IP (never `0.0.0.0/0`)
- `2222/tcp` SSH honeypot: `0.0.0.0/0` (if intentionally exposed)
- `8080/tcp` HTTP honeypot: `0.0.0.0/0` (if intentionally exposed)
- `21/tcp` FTP honeypot: `0.0.0.0/0` (if intentionally exposed)
- `445/tcp` SMB honeypot: `0.0.0.0/0` (only if legally/safely allowed)
- `139/tcp` SMB honeypot: `0.0.0.0/0` (only if needed)
- `3306/tcp` DB honeypot: `0.0.0.0/0` (only if intentionally exposed)
- `5432/tcp` DB honeypot: `0.0.0.0/0` (only if intentionally exposed)

Outbound can remain default allow, because `supabase-sync` and alerting must reach the internet.

## 3) Base OS Hardening

Run once after SSH login:

```bash
sudo apt update && sudo apt -y upgrade
sudo timedatectl set-timezone Asia/Kolkata
sudo adduser deploy
sudo usermod -aG sudo deploy
```

Optional but recommended:

```bash
sudo apt install -y ufw fail2ban
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow from <YOUR_IP>/32 to any port 22 proto tcp
sudo ufw allow 2222/tcp
sudo ufw allow 8080/tcp
sudo ufw allow 21/tcp
sudo ufw allow 445/tcp
sudo ufw allow 139/tcp
sudo ufw allow 3306/tcp
sudo ufw allow 5432/tcp
sudo ufw --force enable
```

If UFW is used, keep it aligned with Security Group rules.

## 4) Install Docker + Compose

```bash
sudo apt install -y ca-certificates curl gnupg
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
  $(. /etc/os-release && echo $VERSION_CODENAME) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt update
sudo apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
sudo usermod -aG docker $USER
newgrp docker
docker --version
docker compose version
```

## 5) Deploy Honeypot Stack

```bash
git clone <YOUR_REPO_URL>
cd HoneyPot-main
cp .env.example .env
```

Edit `.env` with real values:

- `ENVIRONMENT=production`
- `ADMIN_USERNAME`, `ADMIN_PASSWORD`
- `SECRET_KEY`
- `SUPABASE_URL`
- `SUPABASE_SERVICE_ROLE_KEY`
- `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID` (if using alerts)
- `SLACK_WEBHOOK`/`WEBHOOK_URL` (optional)

Start services:

```bash
docker compose up -d
docker compose --profile supabase up -d supabase-sync
docker compose ps
```

## 6) Auto-start on Reboot (systemd)

Create `/etc/systemd/system/honeypot-compose.service`:

```ini
[Unit]
Description=HoneyPot Docker Compose Stack
Requires=docker.service
After=docker.service network-online.target

[Service]
Type=oneshot
WorkingDirectory=/home/ubuntu/HoneyPot-main
ExecStart=/usr/bin/docker compose up -d
ExecStop=/usr/bin/docker compose down
RemainAfterExit=yes
TimeoutStartSec=0

[Install]
WantedBy=multi-user.target
```

Enable it:

```bash
sudo systemctl daemon-reload
sudo systemctl enable honeypot-compose
sudo systemctl start honeypot-compose
sudo systemctl status honeypot-compose
```

## 7) Verification Checklist

- `docker compose ps` shows all required containers healthy/running
- `supabase-sync` logs show sync events:

```bash
docker logs -f supabase-sync
```

- Supabase table `honeypot_sessions` receives rows
- Vercel dashboard shows live/polling updates
- Alerting channels receive a test alert

## 8) Basic Operations

Update and restart:

```bash
git pull
docker compose up -d --build
docker compose --profile supabase up -d --build supabase-sync
```

Check logs:

```bash
docker compose logs --tail=200 web-dashboard
docker compose logs --tail=200 log-aggregator
docker compose logs --tail=200 ioc-detector
docker compose logs --tail=200 supabase-sync
```

## 9) Cost + Reliability Notes

- Keep EBS monitoring enabled (CloudWatch default metrics).
- Add snapshot policy for EBS volume (daily minimum).
- If this becomes high-traffic, move to:
  - dedicated ingestion API,
  - S3 for pcap archival,
  - private subnets + NLB for selected ports.

## 10) Safety Reminder

Run honeypots only on infrastructure/accounts you own and are authorized to monitor. Keep this environment isolated from production workloads and personal data.
