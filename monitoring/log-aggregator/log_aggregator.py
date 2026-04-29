#!/usr/bin/env python3
"""
Log Aggregator Service
Aggregates logs from all honeypot services.
"""

import os
import json
import logging
import time
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
        logging.FileHandler(log_dir / "log_aggregator.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Aggregated log file
aggregated_log = log_dir / "aggregated.log"


class LogHandler(FileSystemEventHandler):
    """Handles log file changes"""
    
    def __init__(self):
        self.processed_files = set()
        
    def on_modified(self, event):
        """Called when a log file is modified"""
        if event.is_directory:
            return
            
        if event.src_path.endswith('.log'):
            self.process_log_file(event.src_path)
            
    def process_log_file(self, filepath):
        """Process a log file"""
        try:
            # Read new lines from log file
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
                
            # Append to aggregated log
            with open(aggregated_log, 'a', encoding='utf-8') as f:
                for line in lines:
                    if line.strip():
                        # Add metadata
                        log_entry = {
                            'timestamp': datetime.now().isoformat(),
                            'source': filepath,
                            'message': line.strip()
                        }
                        f.write(json.dumps(log_entry) + '\n')
                        
        except Exception as e:
            logger.error(f"Error processing log file {filepath}: {e}")


LOG_RETENTION_DAYS = int(os.getenv('LOG_RETENTION_DAYS', '0'))

def cleanup_old_logs():
    """Cleanup logs older than LOG_RETENTION_DAYS"""
    if LOG_RETENTION_DAYS <= 0:
        return
        
    try:
        from datetime import timedelta
        cutoff = datetime.now() - timedelta(days=LOG_RETENTION_DAYS)
        paths_to_clean = [Path("/logs"), Path("/var/log/honeypot")]
        
        for base_path in paths_to_clean:
            if not base_path.exists():
                continue
            for ext in ("*.log", "*.json"):
                for file_path in base_path.rglob(ext):
                    try:
                        if file_path.is_file() and file_path.name != "aggregated.log":
                            mtime = datetime.fromtimestamp(file_path.stat().st_mtime)
                            if mtime < cutoff:
                                file_path.unlink()
                                logger.info(f"Deleted old log file: {file_path}")
                    except Exception as e:
                        logger.debug(f"Error checking file {file_path}: {e}")
    except Exception as e:
        logger.error(f"Error during log cleanup: {e}")

def watch_log_directories():
    """Watch log directories for changes"""
    # Watch all honeypot log directories
    watch_dirs = [
        Path("/var/log/honeypot"),
    ]
    
    observer = Observer()
    handler = LogHandler()
    
    for watch_dir in watch_dirs:
        if watch_dir.exists():
            observer.schedule(handler, str(watch_dir), recursive=True)
            logger.info(f"Watching directory: {watch_dir}")
        else:
            logger.warning(f"Directory does not exist: {watch_dir}")
    
    observer.start()
    logger.info("Log aggregator started")
    
    last_cleanup = 0
    try:
        while True:
            time.sleep(1)
            current_time = time.time()
            if current_time - last_cleanup >= 3600:
                cleanup_old_logs()
                last_cleanup = current_time
    except KeyboardInterrupt:
        observer.stop()
    observer.join()


def main():
    """Main entry point"""
    logger.info("Starting Log Aggregator Service")
    
    # Create aggregated log file
    aggregated_log.touch()
    
    watch_log_directories()


if __name__ == '__main__':
    main()
