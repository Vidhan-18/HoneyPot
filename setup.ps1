# Setup script for Honeypot Platform (PowerShell)

Write-Host "=========================================="
Write-Host "Honeypot Platform Setup"
Write-Host "=========================================="
Write-Host ""
Write-Host "⚠️  WARNING: This honeypot is for authorized use only!" -ForegroundColor Yellow
Write-Host "   See SAFETY.md for legal and ethical guidelines."
Write-Host ""

$acknowledge = Read-Host "Do you acknowledge and agree to use this software responsibly? (yes/no)"

if ($acknowledge -ne "yes") {
    Write-Host "Setup cancelled. Please read SAFETY.md before proceeding." -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "Creating data directories..."
New-Item -ItemType Directory -Force -Path "data\pcaps" | Out-Null
New-Item -ItemType Directory -Force -Path "data\logs" | Out-Null
New-Item -ItemType Directory -Force -Path "data\sessions" | Out-Null
New-Item -ItemType Directory -Force -Path "data\iocs" | Out-Null
New-Item -ItemType Directory -Force -Path "data\ssh" | Out-Null
New-Item -ItemType Directory -Force -Path "data\http" | Out-Null
New-Item -ItemType Directory -Force -Path "data\db" | Out-Null
New-Item -ItemType Directory -Force -Path "data\smb-ftp" | Out-Null

Write-Host "Creating .env file if it doesn't exist..."
if (-not (Test-Path ".env")) {
    @"
# Alerting Configuration
WEBHOOK_URL=
SLACK_WEBHOOK=
TELEGRAM_BOT_TOKEN=
TELEGRAM_CHAT_ID=
"@ | Out-File -FilePath ".env" -Encoding UTF8
    Write-Host "Created .env file. Please edit it to configure alerting (optional)."
} else {
    Write-Host ".env file already exists."
}

Write-Host ""
Write-Host "Setup complete!" -ForegroundColor Green
Write-Host ""
Write-Host "Next steps:"
Write-Host "1. Edit .env file to configure alerting (optional)"
Write-Host "2. Run: docker-compose up -d"
Write-Host "3. Check logs: docker-compose logs -f"
Write-Host ""
Write-Host "For more information, see:"
Write-Host "  - README.md for overview"
Write-Host "  - DEPLOYMENT.md for deployment guide"
Write-Host "  - SAFETY.md for legal requirements"
Write-Host ""

