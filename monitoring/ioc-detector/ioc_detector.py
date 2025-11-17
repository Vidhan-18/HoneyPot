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
import requests
from datetime import datetime
from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Setup logging
log_dir = Path("/logs")
log_dir.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(log_dir / "ioc_detector.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# IOC storage
iocs_dir = Path("/iocs")
iocs_dir.mkdir(parents=True, exist_ok=True)

# Alert configuration
WEBHOOK_URL = os.getenv('WEBHOOK_URL', '')
SLACK_WEBHOOK = os.getenv('SLACK_WEBHOOK', '')
TELEGRAM_BOT_TOKEN = os.getenv('TELEGRAM_BOT_TOKEN', '')
TELEGRAM_CHAT_ID = os.getenv('TELEGRAM_CHAT_ID', '')
ALERT_THRESHOLD = int(os.getenv('ALERT_THRESHOLD', 5))

# IOC patterns
IOC_PATTERNS = {
    'sql_injection': [
        r"union.*select",
        r"';.*--",
        r"or.*1=1",
        r"drop.*table",
        r"exec.*xp_",
    ],
    'command_injection': [
        r";.*cat.*\/etc\/passwd",
        r"\|.*bash",
        r"`.*whoami",
        r"\$\(.*id\)",
        r"cmd\.exe",
    ],
    'path_traversal': [
        r"\.\.\/",
        r"\.\.\\",
        r"\/etc\/passwd",
        r"\/etc\/shadow",
        r"c:\\windows\\system32",
    ],
    'xss': [
        r"<script>",
        r"javascript:",
        r"onerror=",
        r"onload=",
    ],
    'malicious_commands': [
        r"wget.*http",
        r"curl.*http",
        r"nc.*-e",
        r"bash.*-i",
        r"python.*-c",
        r"perl.*-e",
    ],
    'credential_harvesting': [
        r"password.*=.*['\"]",
        r"passwd.*=.*['\"]",
        r"pwd.*=.*['\"]",
    ],
}


class IOCDetector:
    """Detects IOCs in log entries"""
    
    def __init__(self):
        self.detected_iocs = []
        self.alert_count = 0
        
    def detect(self, log_entry):
        """Detect IOCs in a log entry"""
        if isinstance(log_entry, str):
            message = log_entry
        else:
            message = log_entry.get('message', '')
            
        detected = []
        
        for ioc_type, patterns in IOC_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, message, re.IGNORECASE):
                    detected.append({
                        'type': ioc_type,
                        'pattern': pattern,
                        'message': message[:200],
                        'timestamp': datetime.now().isoformat()
                    })
                    logger.warning(f"Detected IOC: {ioc_type} - {pattern}")
                    
        return detected
        
    def save_ioc(self, ioc):
        """Save detected IOC to file"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        ioc_file = iocs_dir / f"ioc_{timestamp}.json"
        try:
            with open(ioc_file, 'w') as f:
                json.dump(ioc, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save IOC: {e}")


class AlertSender:
    """Sends alerts via various channels"""
    
    @staticmethod
    def send_webhook(message):
        """Send alert via webhook"""
        if not WEBHOOK_URL:
            return False
            
        try:
            payload = {
                'timestamp': datetime.now().isoformat(),
                'message': message,
                'source': 'honeypot'
            }
            response = requests.post(WEBHOOK_URL, json=payload, timeout=5)
            return response.status_code == 200
        except Exception as e:
            logger.error(f"Webhook alert failed: {e}")
            return False
            
    @staticmethod
    def send_slack(message):
        """Send alert via Slack"""
        if not SLACK_WEBHOOK:
            return False
            
        try:
            payload = {
                'text': f"🚨 Honeypot Alert\n{message}",
                'username': 'Honeypot Monitor'
            }
            response = requests.post(SLACK_WEBHOOK, json=payload, timeout=5)
            return response.status_code == 200
        except Exception as e:
            logger.error(f"Slack alert failed: {e}")
            return False
            
    @staticmethod
    def send_telegram(message):
        """Send alert via Telegram"""
        if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
            return False
            
        try:
            url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
            payload = {
                'chat_id': TELEGRAM_CHAT_ID,
                'text': f"🚨 Honeypot Alert\n{message}",
                'parse_mode': 'HTML'
            }
            response = requests.post(url, json=payload, timeout=5)
            return response.status_code == 200
        except Exception as e:
            logger.error(f"Telegram alert failed: {e}")
            return False


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
                    message = log_entry.get('message', '')
                except:
                    message = line.strip()
                    
                # Detect IOCs
                detected = self.detector.detect(message)
                
                if detected:
                    for ioc in detected:
                        self.detector.save_ioc(ioc)
                        
                        # Send alert
                        alert_message = (
                            f"IOC Detected: {ioc['type']}\n"
                            f"Pattern: {ioc['pattern']}\n"
                            f"Message: {ioc['message']}\n"
                            f"Source: {filepath}"
                        )
                        
                        # Send via all configured channels
                        self.alert_sender.send_webhook(alert_message)
                        self.alert_sender.send_slack(alert_message)
                        self.alert_sender.send_telegram(alert_message)
                        
        except Exception as e:
            logger.error(f"Error processing log file {filepath}: {e}")


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
    logger.info("Starting IOC Detector and Alerting Service")
    
    watch_logs()


if __name__ == '__main__':
    main()

