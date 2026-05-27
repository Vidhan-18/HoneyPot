# HoneyPot Defense Platform

[![Docker](https://img.shields.io/badge/Docker-Ready-blue?logo=docker)](https://docker.com)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.11+-blue?logo=python)](https://python.org)

A multi-service honeypot platform for capturing hostile traffic, classifying attacks, and visualizing activity through a dashboard.

## Production Architecture

This repository is configured for:

- **AWS EC2** for honeypot services and background workers
- **Supabase** for centralized storage and realtime updates
- **Vercel** for hosting the dashboard/API surface

```text
Attackers -> EC2 Honeypot Services -> log/session files -> supabase-sync -> Supabase
                                                           -> Vercel dashboard reads + realtime
```

## Core Components

- `services/http` - HTTP trap service
- `services/ssh` - SSH trap service
- `services/smb-ftp` - SMB/FTP trap service
- `services/db-api` - database protocol trap service
- `monitoring/log-aggregator` - collects and normalizes logs
- `monitoring/ioc-detector` - IOC detection and alerting
- `monitoring/packet-capture` - packet capture process
- `monitoring/web-dashboard` - Flask dashboard and APIs
- `monitoring/supabase-sync` - syncs EC2 file outputs to Supabase

## Documentation

- Deployment guide: [`docs/VERCEL_SUPABASE_SETUP.md`](docs/VERCEL_SUPABASE_SETUP.md)
- EC2 runbook: [`docs/EC2_SETUP.md`](docs/EC2_SETUP.md)
- Alerts setup: [`ALERTS_SETUP.md`](ALERTS_SETUP.md)
- Safety guidance: [`SAFETY.md`](SAFETY.md)
- Quick bootstrap: [`QUICKSTART.md`](QUICKSTART.md)

## Quick Start (Local Docker)

### Prerequisites

- Docker
- Docker Compose plugin

### Setup

1. Clone and enter repository:

```bash
git clone <your-repo-url>
cd HoneyPot-main
```

2. Configure environment:

```bash
cp .env.example .env
# edit .env
```

3. Start core stack:

```bash
docker compose up -d
```

4. Optional: start Supabase sync profile:

```bash
docker compose --profile supabase up -d supabase-sync
```

5. Open dashboard:

- `http://localhost:5000`

## Environment and Secrets

Use `.env.example` as the source of truth.

Minimum production variables:

- `ENVIRONMENT=production`
- `SECRET_KEY`
- `ADMIN_USERNAME`
- `ADMIN_PASSWORD` or `DASHBOARD_PASSWORD_HASH`
- `SUPABASE_URL`
- `SUPABASE_SERVICE_ROLE_KEY`
- `SUPABASE_ANON_KEY`

Optional alerting variables:

- `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID`
- `SLACK_WEBHOOK`
- `WEBHOOK_URL`

## Security Notes

This platform intentionally attracts malicious traffic. Operate it as a controlled, isolated system.

- Do not deploy in the same network segment as production workloads.
- Restrict SSH admin access by source IP.
- Rotate credentials and secrets regularly.
- Keep host OS and container images patched.
- Review legal requirements before internet exposure.

## Operations

Useful commands:

```bash
# service state
docker compose ps

# follow sync logs
docker logs -f supabase-sync

# follow full stack logs
docker compose logs -f

# rebuild and restart
docker compose up -d --build
docker compose --profile supabase up -d --build supabase-sync
```

## API Surface

Main read APIs:

- `GET /api/stats`
- `GET /api/sessions`
- `GET /api/session/<id-or-file>`
- `GET /api/iocs`
- `GET /api/logs`
- `GET /api/threat-map`
- `GET /api/country/<country_code>`

Main write APIs:

- `POST /api/block-ip`
- `POST /api/watchlist-add`

## CI/CD

GitHub Actions workflow in `.github/workflows/ci.yml` handles linting, tests, scanning, and Docker image build workflows.

## Contributing

1. Create a feature branch
2. Make focused changes with tests where possible
3. Open a PR with deployment/testing notes

## License

MIT. See [`LICENSE`](LICENSE).
