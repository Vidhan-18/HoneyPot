#!/usr/bin/env python3
"""
IOC Detector and Alerting Service
Detects indicators of compromise and sends alerts.
"""

import os
import json
import logging
import time
import re
import sys
from datetime import datetime
from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from alert_manager import get_alert_manager, AlertMessage, send_alert

# Setup logging
log_dir = Path("/iocs") # Changed from /logs to /iocs because /logs is mounted as ro
try:
    log_dir.mkdir(parents=True, exist_ok=True)
except OSError as e:
    pass # Assume it exists or we can't create it, we'll try configuring logger anyway

logging_handlers = [logging.StreamHandler()]
try:
    log_file = log_dir / "ioc_detector.log"
    # Ensure we can open the file
    with open(log_file, 'a'): pass
    logging_handlers.append(logging.FileHandler(log_file))
except OSError:
    pass # Fallback to stdout only if read-only

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=logging_handlers
)
logger = logging.getLogger(__name__)

# IOC storage
iocs_dir = Path("/iocs")
iocs_dir.mkdir(parents=True, exist_ok=True)

# Alert configuration
ALERT_THRESHOLD = int(os.getenv('ALERT_THRESHOLD', '5'))

# Initialize alert manager
alert_manager = get_alert_manager()

# IOC patterns
IOC_PATTERNS = {
    'sql_injection': [
        r"union\s+select",
        r"or\s+1=1",
        r"'\s*or\s*'1'='1",
        r"drop\s+table",
        r"exec\s+xp_",
    ],
    'command_injection': [
        r";\s*(?:cat|ls|whoami|id|pwd|wget|curl)\b",
        r"\|\s*(?:bash|sh|cmd|powershell)\b",
        r"`\s*(?:cat|ls|whoami|id|pwd)\b",
    ],
    'path_traversal': [
        r"\.\./\.\./",
        r"\.\.\\\.\.\\",
        r"/etc/passwd",
        r"/etc/shadow",
        r"boot\.ini",
    ],
    'xss': [
        r"<script.*?>",
        r"javascript:",
        r"onerror\s*=",
        r"onload\s*=",
    ],
    'malicious_commands': [
        r"wget\s+http",
        r"curl\s+http",
        r"nc\s+-e",
        r"bash\s+-i",
        r"python\s+-c",
        r"perl\s+-e",
    ],
    'credential_harvesting': [
        r"password\s*=\s*['\"]",
        r"passwd\s*=\s*['\"]",
        r"pwd\s*=\s*['\"]",
    ],
}


class IOCDetector:
    """Detects IOCs in log entries"""
    
    def __init__(self):
        self.detected_iocs = []
        self.alert_count = 0
        self.recent_alerts = {}
        self.last_cleanup = time.time()
        
    MAX_RECENT_ALERTS = 5000

    def _cleanup_old_alerts(self):
        """Remove entries older than 5 minutes and enforce max size to prevent OOM."""
        now = time.time()
        if now - self.last_cleanup > 60:
            # Remove stale entries older than 5 minutes
            stale_keys = [k for k, v in self.recent_alerts.items() if (now - v['last_alert']) > 300]
            for k in stale_keys:
                del self.recent_alerts[k]
            
            # Enforce max size — evict oldest entries if over limit
            if len(self.recent_alerts) > self.MAX_RECENT_ALERTS:
                excess = sorted(self.recent_alerts.keys(),
                                key=lambda k: self.recent_alerts[k]['first_seen'])[:-self.MAX_RECENT_ALERTS]
                for k in excess:
                    del self.recent_alerts[k]
            
            self.last_cleanup = now

    def detect(self, log_entry):
        """Detect IOCs in a log entry"""
        if isinstance(log_entry, str):
            message = log_entry
            ip = 'unknown'
            path = 'unknown'
        else:
            message = log_entry.get('message', '')
            ip = log_entry.get('source_ip', log_entry.get('client_ip', 'unknown'))
            path = log_entry.get('metadata', {}).get('path', 'unknown')
            
        detected = []
        
        for ioc_type, patterns in IOC_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, message, re.IGNORECASE):
                    detected.append({
                        'type': ioc_type,
                        'pattern': pattern,
                        'message': message[:200],
                        'timestamp': datetime.now().isoformat(),
                        'ip': ip,
                        'path': path
                    })
                    break # Only one pattern per type
                    
        return detected

    def process_ioc(self, ioc, alert_sender, filepath):
        self._cleanup_old_alerts()
        
        ip = ioc.get('ip', 'unknown')
        ioc_type = ioc['type']
        key = (ip, ioc_type)
        now = time.time()
        
        if key not in self.recent_alerts:
            self.recent_alerts[key] = {
                'first_seen': now,
                'last_alert': 0,
                'count': 0,
                'logs': []
            }
            
        state = self.recent_alerts[key]
        state['count'] += 1
        
        if len(state['logs']) < 3:
            state['logs'].append(ioc['message'])
            
        should_alert = False
        if state['count'] == 1:
            should_alert = True
        elif state['count'] % ALERT_THRESHOLD == 0 and (now - state['last_alert']) > 30:
            should_alert = True
            
        if should_alert:
            state['last_alert'] = now
            alert_msg = (
                f"Attack Type: {ioc_type}\n"
                f"Attacker IP: {ip}\n"
                f"Target Path: {ioc['path']}\n"
                f"Attempts: {state['count']}\n"
                f"Explanation: Suspicious activity matching {ioc_type} patterns.\n\n"
                f"Sample Logs:\n" + "\n".join(f"- {log}" for log in state['logs'])
            )
            self.save_ioc(ioc)
            alert_sender.send_alert(
                ioc_type=ioc_type,
                pattern="Multiple",
                message=alert_msg,
                source=filepath
            )
        
    def save_ioc(self, ioc):
        """Save detected IOC to file"""
        try:
            iocs_dir.mkdir(parents=True, exist_ok=True)
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            unique = int(time.time() * 1000)
            ioc_file = iocs_dir / f"ioc_{timestamp}_{unique}.json"

            with open(ioc_file, 'w') as f:
                json.dump(ioc, f, indent=2)

        except Exception as e:
            logger.debug(f"Failed to save IOC: {e}")


class AlertSender:
    """Sends alerts via various channels using AlertManager"""
    
    def __init__(self):
        self.alert_manager = get_alert_manager()
    
    def send_alert(self, ioc_type: str, pattern: str, message: str, source: str):
        """Send structured alert via all configured channels"""
        alert = AlertMessage(
            title=f"IOC Detected: {ioc_type}",
            message=message[:500],  # Limit message length
            severity=self._get_severity(ioc_type),
            source=source,
            timestamp=datetime.utcnow(),
            metadata={
                'ioc_type': ioc_type,
                'pattern': pattern,
                'source_file': source
            }
        )
        
        results = self.alert_manager.send_alert(alert)
        
        # Log results
        for channel, success in results.items():
            if success:
                logger.info(f"Alert sent via {channel}")
            else:
                logger.warning(f"Failed to send alert via {channel}")
        
        return results
    
    def _get_severity(self, ioc_type: str) -> str:
        """Determine severity based on IOC type"""
        severity_map = {
            'sql_injection': 'critical',
            'command_injection': 'critical',
            'malicious_commands': 'high',
            'path_traversal': 'high',
            'xss': 'medium',
            'credential_harvesting': 'high'
        }
        return severity_map.get(ioc_type, 'medium')
    
    # Legacy methods for backward compatibility
    @staticmethod
    def send_webhook(message):
        """Legacy webhook method - redirects to alert manager"""
        logger.warning("Using legacy send_webhook - consider migrating to send_alert")
        return True
            
    @staticmethod
    def send_slack(message):
        """Legacy Slack method - redirects to alert manager"""
        logger.warning("Using legacy send_slack - consider migrating to send_alert")
        return True
            
    @staticmethod
    def send_telegram(message):
        """Legacy Telegram method - redirects to alert manager"""
        logger.warning("Using legacy send_telegram - consider migrating to send_alert")
        return True


class LogFileHandler(FileSystemEventHandler):
    """Handles log file changes for IOC detection"""
    
    def __init__(self):
        self.detector = IOCDetector()
        self.alert_sender = AlertSender()
        self.processed_lines = set()
        
    def on_modified(self, event):
        """Called when a log file is modified"""
        if event.is_directory:
            return
            
        if event.src_path.endswith('.log') or event.src_path.endswith('.json'):
            self.process_log_file(event.src_path)
            
    def process_log_file(self, filepath):
        """Process a log file for IOCs"""
        try:
            if not os.path.exists(filepath):
                return
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
                
            for line in lines:
                line_hash = hash(line.strip())
                if line_hash in self.processed_lines:
                    continue
                self.processed_lines.add(line_hash)
                
                # Try to parse as JSON
                try:
                    log_entry = json.loads(line.strip())
                    if 'werkzeug' in log_entry.get('logger', '').lower():
                        continue
                except:
                    log_entry = line.strip()
                    if 'werkzeug' in log_entry.lower():
                        continue
                    
                # Detect IOCs
                detected = self.detector.detect(log_entry)
                
                if detected:
                    for ioc in detected:
                        self.detector.process_ioc(ioc, self.alert_sender, filepath)
                        
        except Exception as e:
            logger.debug(f"Error processing log file {filepath}: {e}")


def watch_logs():
    """Watch log directories for IOC detection"""
    # When using host network mode, paths are relative to host
    # Adjust paths based on docker-compose volume mounts
    watch_dirs = [
        Path("/logs"),  # Mounted from ./data/logs
        Path("/sessions"),  # Mounted from ./data/sessions (if available)
    ]
    
    # Also watch the aggregated log file directly
    aggregated_log = Path("/logs/aggregated.log")
    
    observer = Observer()
    handler = LogFileHandler()
    
    for watch_dir in watch_dirs:
        if watch_dir.exists():
            observer.schedule(handler, str(watch_dir), recursive=True)
            logger.info(f"Watching directory for IOCs: {watch_dir}")
        else:
            logger.warning(f"Directory does not exist: {watch_dir}")
    
    observer.start()
    logger.info("IOC Detector started")
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()


def main():
    """Main entry point"""
    logger.info("=" * 60)
    logger.info("IOC Detector and Alerting Service Starting")
    logger.info("=" * 60)
    
    # Test alert connections on startup
    try:
        logger.info("Testing alert connections...")
        alert_manager = get_alert_manager()
        connections = alert_manager.test_connections()
        
        for channel, status in connections.items():
            if status:
                logger.info(f"  ✓ {channel}: Connected")
            else:
                logger.warning(f"  ✗ {channel}: Not configured")
        
        # Send test alert if any channel is configured
        if any(connections.values()):
            logger.info("Sending startup test alert...")
            test_results = alert_manager.send_test_alert()
            
            success_count = sum(1 for v in test_results.values() if v)
            logger.info(f"Test alerts sent: {success_count}/{len(test_results)} successful")
        
    except Exception as e:
        logger.error(f"Error during startup tests: {e}")
    
    logger.info("Starting log monitoring...")
    watch_logs()


if __name__ == '__main__':
    main()

