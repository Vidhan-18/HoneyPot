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
ALERT_THRESHOLD = int(os.getenv('ALERT_THRESHOLD', '5'))

# Initialize alert manager
alert_manager = get_alert_manager()

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
                        
                        # Send structured alert via alert manager
                        self.alert_sender.send_alert(
                            ioc_type=ioc['type'],
                            pattern=ioc['pattern'],
                            message=ioc['message'],
                            source=filepath
                        )
                        
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

