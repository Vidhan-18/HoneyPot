# Web Dashboard Guide

## Overview

The Web Dashboard provides a user-friendly interface to monitor and interact with your honeypot platform in real-time.

## Access

After starting the platform with `docker-compose up -d`, access the dashboard at:

```
http://localhost:5000
```

## Features

### 1. Real-Time Statistics

The dashboard displays live statistics at the top:
- **Total Sessions**: Number of captured sessions
- **Detected IOCs**: Number of indicators of compromise detected
- **Packet Captures**: Number of PCAP files
- **Recent Activity**: Activity in the last hour

Statistics update automatically every 5 seconds via WebSocket.

### 2. Sessions Tab

View all captured sessions from honeypot services:
- SSH sessions with commands and login attempts
- HTTP sessions with requests and responses
- Database sessions with queries
- SMB/FTP sessions with file operations

**Features:**
- Click any session to view detailed JSON data
- See client IP addresses
- View timestamps and command history
- Filter by protocol type

### 3. IOCs Tab

View all detected Indicators of Compromise:
- SQL Injection attempts
- Command Injection attempts
- Path Traversal attempts
- XSS attempts
- Malicious commands
- Credential harvesting attempts

**Features:**
- Color-coded severity (yellow for warnings, red for critical)
- Pattern matching details
- Timestamp information
- Click to view full IOC details

### 4. Logs Tab

View aggregated logs from all services:
- Real-time log streaming
- Service-specific logs
- Timestamped entries
- Formatted JSON log entries

**Features:**
- Auto-scrolling to latest logs
- Monospace font for readability
- Color-coded by log level

### 5. Services Tab

Monitor service status:
- SSH Honeypot (port 2222)
- HTTP Honeypot (port 8080)
- Database API Honeypot (ports 5432, 3306)
- SMB/FTP Honeypot (ports 445, 21, 139)
- Packet Capture service
- Log Aggregator
- IOC Detector

**Features:**
- Service status indicators
- Port information
- Real-time status updates

## API Endpoints

The dashboard also exposes REST API endpoints:

- `GET /api/stats` - Get platform statistics
- `GET /api/sessions` - List all sessions (limit parameter)
- `GET /api/session/<filename>` - Get specific session details
- `GET /api/iocs` - List all IOCs (limit parameter)
- `GET /api/ioc/<filename>` - Get specific IOC details
- `GET /api/logs` - Get recent logs (limit, service parameters)
- `GET /api/pcaps` - List packet capture files
- `GET /api/services` - Get service status

## WebSocket Events

The dashboard uses WebSocket for real-time updates:

- `stats_update` - Statistics update event (every 5 seconds)
- `connect` - Client connection event
- `disconnect` - Client disconnection event

## Usage Tips

1. **Auto-Refresh**: The dashboard automatically refreshes data every 10 seconds
2. **Modal Details**: Click on any session or IOC to view detailed JSON
3. **Tab Navigation**: Switch between tabs to view different data types
4. **Connection Status**: Check the top-right for WebSocket connection status

## Troubleshooting

### Dashboard Not Loading

1. Check if the container is running:
   ```bash
   docker-compose ps web-dashboard
   ```

2. Check logs:
   ```bash
   docker-compose logs web-dashboard
   ```

3. Verify port 5000 is not in use:
   ```bash
   netstat -an | grep 5000
   ```

### No Data Showing

1. Ensure other services are running and generating data
2. Check if data directories are mounted correctly
3. Verify log aggregator is running
4. Check browser console for JavaScript errors

### WebSocket Connection Issues

1. Check firewall settings
2. Verify Docker networking is configured correctly
3. Check browser console for connection errors

## Security Notes

⚠️ **Important Security Considerations:**

- The dashboard is exposed on port 5000
- Default secret key should be changed in production
- Consider adding authentication for production use
- Use HTTPS in production environments
- Restrict access to authorized IPs only

## Customization

To customize the dashboard:

1. Edit `monitoring/web-dashboard/templates/dashboard.html` for UI changes
2. Edit `monitoring/web-dashboard/web_dashboard.py` for API changes
3. Modify CSS in the HTML template for styling
4. Add new API endpoints as needed

## Future Enhancements

Potential improvements:
- User authentication
- Export functionality
- Advanced filtering and search
- Charts and graphs
- Alert configuration UI
- Real-time packet capture viewer




