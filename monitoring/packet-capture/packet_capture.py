#!/usr/bin/env python3
"""
Packet Capture Service
Captures all network traffic on the honeypot network.
"""

import os
import logging
import subprocess
import time
from datetime import datetime
from pathlib import Path

# Setup logging
log_dir = Path("/logs")
log_dir.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(log_dir / "packet_capture.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# PCAP storage
pcaps_dir = Path("/pcaps")
pcaps_dir.mkdir(parents=True, exist_ok=True)


def start_tcpdump():
    """Start tcpdump to capture packets"""
    interface = os.getenv('INTERFACE', 'eth0')
    capture_size = os.getenv('CAPTURE_SIZE', '100M')
    
    # Generate filename with timestamp
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    pcap_file = pcaps_dir / f"capture_{timestamp}.pcap"
    
    logger.info(f"Starting packet capture on {interface}, saving to {pcap_file}")
    
    # Build tcpdump command
    cmd = [
        'tcpdump',
        '-i', interface,
        '-w', str(pcap_file),
        '-C', '100',  # Rotate files at 100MB
        '-W', '10',   # Keep 10 files
        '-v'          # Verbose
    ]
    
    try:
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        logger.info(f"tcpdump started with PID {process.pid}")
        
        # Monitor process
        while True:
            if process.poll() is not None:
                logger.error("tcpdump process died, restarting...")
                time.sleep(5)
                process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
            time.sleep(10)
            
    except Exception as e:
        logger.error(f"Error running tcpdump: {e}")
        raise


def main():
    """Main entry point"""
    logger.info("Starting Packet Capture Service")
    
    try:
        start_tcpdump()
    except KeyboardInterrupt:
        logger.info("Shutting down Packet Capture Service")


if __name__ == '__main__':
    main()




