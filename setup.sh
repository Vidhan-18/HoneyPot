#!/bin/bash
# Setup script for Honeypot Platform

set -e

echo "=========================================="
echo "Honeypot Platform Setup"
echo "=========================================="
echo ""
echo "⚠️  WARNING: This honeypot is for authorized use only!"
echo "   See SAFETY.md for legal and ethical guidelines."
echo ""
read -p "Do you acknowledge and agree to use this software responsibly? (yes/no): " acknowledge

if [ "$acknowledge" != "yes" ]; then
    echo "Setup cancelled. Please read SAFETY.md before proceeding."
    exit 1
fi

echo ""
echo "Creating data directories..."
mkdir -p data/{pcaps,logs,sessions,iocs,ssh,http,db,smb-ftp}

echo "Creating .env file if it doesn't exist..."
if [ ! -f .env ]; then
    cat > .env << EOF
# Alerting Configuration
WEBHOOK_URL=
SLACK_WEBHOOK=
TELEGRAM_BOT_TOKEN=
TELEGRAM_CHAT_ID=
EOF
    echo "Created .env file. Please edit it to configure alerting (optional)."
else
    echo ".env file already exists."
fi

echo ""
echo "Setup complete!"
echo ""
echo "Next steps:"
echo "1. Edit .env file to configure alerting (optional)"
echo "2. Run: docker-compose up -d"
echo "3. Check logs: docker-compose logs -f"
echo ""
echo "For more information, see:"
echo "  - README.md for overview"
echo "  - DEPLOYMENT.md for deployment guide"
echo "  - SAFETY.md for legal requirements"
echo ""

