#!/usr/bin/env python3
"""
Alert Manager - Centralized alerting system with retry logic
Handles Telegram, Slack, and Webhook alerts with proper error handling
"""

import os
import json
import logging
import time
import requests
from datetime import datetime
from typing import Dict, List, Optional
from dataclasses import dataclass
from enum import Enum

# Configure logging
logger = logging.getLogger(__name__)

class AlertChannel(Enum):
    TELEGRAM = "telegram"
    SLACK = "slack"
    WEBHOOK = "webhook"

@dataclass
class AlertMessage:
    """Structured alert message"""
    title: str
    message: str
    severity: str  # low, medium, high, critical
    source: str
    timestamp: datetime
    metadata: Optional[Dict] = None
    
    def to_telegram_html(self) -> str:
        """Convert to Telegram HTML format"""
        emoji_map = {
            'low': 'ℹ️',
            'medium': '⚠️',
            'high': '🚨',
            'critical': '🔴'
        }
        emoji = emoji_map.get(self.severity, 'ℹ️')
        
        html = f"""
<b>{emoji} {self.title}</b>

<b>Severity:</b> {self.severity.upper()}
<b>Source:</b> {self.source}
<b>Time:</b> {self.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}

<pre>{self.message}</pre>
"""
        if self.metadata:
            html += "\n<b>Details:</b>\n"
            for key, value in self.metadata.items():
                html += f"• {key}: {value}\n"
        
        return html
    
    def to_slack_text(self) -> str:
        """Convert to Slack text format"""
        emoji_map = {
            'low': ':information_source:',
            'medium': ':warning:',
            'high': ':rotating_light:',
            'critical': ':red_circle:'
        }
        emoji = emoji_map.get(self.severity, ':information_source:')
        
        return f"""
{emoji} *{self.title}*

*Severity:* {self.severity.upper()}
*Source:* {self.source}
*Time:* {self.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}

```{self.message}```
"""

class TelegramBot:
    """Telegram Bot with retry logic and error handling"""
    
    def __init__(self, bot_token: str, chat_id: str):
        self.bot_token = bot_token
        self.chat_id = chat_id
        self.base_url = f"https://api.telegram.org/bot{bot_token}"
        self.max_retries = 3
        self.retry_delay = 2  # seconds
        
        # Validate configuration
        if not bot_token or not chat_id:
            logger.warning("Telegram bot not fully configured - alerts will be disabled")
            self.enabled = False
        else:
            self.enabled = True
            logger.info("Telegram bot initialized successfully")
    
    def send_message(self, message: str, parse_mode: str = 'HTML') -> bool:
        """Send message with retry logic"""
        if not self.enabled:
            logger.debug("Telegram bot disabled - skipping alert")
            return False
        
        url = f"{self.base_url}/sendMessage"
        payload = {
            'chat_id': self.chat_id,
            'text': message,
            'parse_mode': parse_mode,
            'disable_web_page_preview': True
        }
        
        for attempt in range(self.max_retries):
            try:
                response = requests.post(url, json=payload, timeout=10)
                
                if response.status_code == 200:
                    logger.info("Telegram alert sent successfully")
                    return True
                elif response.status_code == 429:
                    # Rate limited
                    retry_after = response.json().get('parameters', {}).get('retry_after', 30)
                    logger.warning(f"Telegram rate limited. Retrying after {retry_after}s")
                    time.sleep(retry_after)
                else:
                    logger.error(f"Telegram API error: {response.status_code} - {response.text}")
                    if attempt < self.max_retries - 1:
                        time.sleep(self.retry_delay * (attempt + 1))
                        
            except requests.exceptions.Timeout:
                logger.warning(f"Telegram request timeout (attempt {attempt + 1}/{self.max_retries})")
                if attempt < self.max_retries - 1:
                    time.sleep(self.retry_delay * (attempt + 1))
                    
            except requests.exceptions.RequestException as e:
                logger.error(f"Telegram request failed: {e}")
                if attempt < self.max_retries - 1:
                    time.sleep(self.retry_delay * (attempt + 1))
            
            except Exception as e:
                logger.error(f"Unexpected error sending Telegram message: {e}")
                return False
        
        logger.error("Failed to send Telegram alert after all retries")
        return False
    
    def test_connection(self) -> bool:
        """Test bot connection and chat ID"""
        if not self.enabled:
            return False
        
        try:
            url = f"{self.base_url}/getMe"
            response = requests.get(url, timeout=5)
            
            if response.status_code == 200:
                bot_info = response.json().get('result', {})
                logger.info(f"Telegram bot connected: @{bot_info.get('username')}")
                return True
            else:
                logger.error(f"Telegram bot connection failed: {response.text}")
                return False
                
        except Exception as e:
            logger.error(f"Telegram connection test failed: {e}")
            return False

class SlackWebhook:
    """Slack webhook client with retry logic"""
    
    def __init__(self, webhook_url: str):
        self.webhook_url = webhook_url
        self.max_retries = 3
        self.retry_delay = 2
        
        if not webhook_url:
            logger.warning("Slack webhook not configured - alerts will be disabled")
            self.enabled = False
        else:
            self.enabled = True
    
    def send_message(self, text: str) -> bool:
        """Send message to Slack with retry"""
        if not self.enabled:
            return False
        
        payload = {'text': text}
        
        for attempt in range(self.max_retries):
            try:
                response = requests.post(
                    self.webhook_url,
                    json=payload,
                    timeout=10,
                    headers={'Content-Type': 'application/json'}
                )
                
                if response.status_code == 200:
                    logger.info("Slack alert sent successfully")
                    return True
                else:
                    logger.error(f"Slack webhook error: {response.status_code}")
                    if attempt < self.max_retries - 1:
                        time.sleep(self.retry_delay * (attempt + 1))
                        
            except Exception as e:
                logger.error(f"Slack request failed: {e}")
                if attempt < self.max_retries - 1:
                    time.sleep(self.retry_delay * (attempt + 1))
        
        return False

class WebhookClient:
    """Generic webhook client"""
    
    def __init__(self, webhook_url: str):
        self.webhook_url = webhook_url
        self.max_retries = 3
        self.retry_delay = 2
        
        if not webhook_url:
            logger.warning("Webhook URL not configured - alerts will be disabled")
            self.enabled = False
        else:
            self.enabled = True
    
    def send_message(self, data: Dict) -> bool:
        """Send JSON payload to webhook"""
        if not self.enabled:
            return False
        
        payload = {
            'timestamp': datetime.now().isoformat(),
            'source': 'honeypot',
            **data
        }
        
        for attempt in range(self.max_retries):
            try:
                response = requests.post(
                    self.webhook_url,
                    json=payload,
                    timeout=10,
                    headers={'Content-Type': 'application/json'}
                )
                
                if response.status_code in [200, 201, 204]:
                    logger.info("Webhook alert sent successfully")
                    return True
                else:
                    logger.error(f"Webhook error: {response.status_code}")
                    if attempt < self.max_retries - 1:
                        time.sleep(self.retry_delay * (attempt + 1))
                        
            except Exception as e:
                logger.error(f"Webhook request failed: {e}")
                if attempt < self.max_retries - 1:
                    time.sleep(self.retry_delay * (attempt + 1))
        
        return False

class AlertManager:
    """Centralized alert manager"""
    
    def __init__(self):
        # Initialize clients from environment variables
        self.telegram = TelegramBot(
            os.getenv('TELEGRAM_BOT_TOKEN', ''),
            os.getenv('TELEGRAM_CHAT_ID', '')
        )
        self.slack = SlackWebhook(os.getenv('SLACK_WEBHOOK', ''))
        self.webhook = WebhookClient(os.getenv('WEBHOOK_URL', ''))
        
        # Track alert statistics
        self.stats = {
            'sent': 0,
            'failed': 0,
            'by_channel': {}
        }
    
    def send_alert(self, alert: AlertMessage, channels: Optional[List[AlertChannel]] = None) -> Dict[str, bool]:
        """
        Send alert to specified channels
        
        Args:
            alert: AlertMessage object
            channels: List of channels to send to (default: all configured)
        
        Returns:
            Dict mapping channel names to success status
        """
        if channels is None:
            channels = [AlertChannel.TELEGRAM, AlertChannel.SLACK, AlertChannel.WEBHOOK]
        
        results = {}
        
        for channel in channels:
            try:
                if channel == AlertChannel.TELEGRAM:
                    success = self.telegram.send_message(alert.to_telegram_html())
                elif channel == AlertChannel.SLACK:
                    success = self.slack.send_message(alert.to_slack_text())
                elif channel == AlertChannel.WEBHOOK:
                    success = self.webhook.send_message({
                        'title': alert.title,
                        'message': alert.message,
                        'severity': alert.severity,
                        'source': alert.source,
                        'metadata': alert.metadata or {}
                    })
                else:
                    continue
                
                results[channel.value] = success
                
                # Update stats
                if success:
                    self.stats['sent'] += 1
                    self.stats['by_channel'][channel.value] = self.stats['by_channel'].get(channel.value, 0) + 1
                else:
                    self.stats['failed'] += 1
                    
            except Exception as e:
                logger.error(f"Error sending alert to {channel.value}: {e}")
                results[channel.value] = False
                self.stats['failed'] += 1
        
        return results
    
    def send_test_alert(self) -> Dict[str, bool]:
        """Send a test alert to verify all channels"""
        test_alert = AlertMessage(
            title="Test Alert",
            message="This is a test alert from your honeypot system.",
            severity="low",
            source="test",
            timestamp=datetime.utcnow(),
            metadata={'test': True}
        )
        
        logger.info("Sending test alert to all configured channels...")
        results = self.send_alert(test_alert)
        
        for channel, success in results.items():
            status = "✓" if success else "✗"
            logger.info(f"  {status} {channel}")
        
        return results
    
    def get_stats(self) -> Dict:
        """Get alert statistics"""
        return self.stats.copy()
    
    def test_connections(self) -> Dict[str, bool]:
        """Test all configured connections"""
        results = {}
        
        logger.info("Testing alert connections...")
        results['telegram'] = self.telegram.test_connection()
        results['slack'] = self.slack.enabled  # Slack doesn't have a test endpoint
        results['webhook'] = self.webhook.enabled
        
        return results

# Singleton instance
_alert_manager = None

def get_alert_manager() -> AlertManager:
    """Get or create AlertManager singleton"""
    global _alert_manager
    if _alert_manager is None:
        _alert_manager = AlertManager()
    return _alert_manager

# Convenience function for quick alerts
def send_alert(
    title: str,
    message: str,
    severity: str = "medium",
    source: str = "honeypot",
    metadata: Optional[Dict] = None
) -> Dict[str, bool]:
    """
    Quick function to send an alert
    
    Example:
        send_alert(
            title="Brute Force Detected",
            message="Multiple failed login attempts from 192.168.1.1",
            severity="high",
            metadata={'ip': '192.168.1.1', 'attempts': 50}
        )
    """
    alert = AlertMessage(
        title=title,
        message=message,
        severity=severity,
        source=source,
        timestamp=datetime.utcnow(),
        metadata=metadata
    )
    
    return get_alert_manager().send_alert(alert)

if __name__ == '__main__':
    # Test the alert system
    logging.basicConfig(level=logging.INFO)
    
    manager = get_alert_manager()
    
    # Test connections
    connections = manager.test_connections()
    logger.info("Connection Status:")
    for channel, status in connections.items():
        icon = "✓" if status else "✗"
        status_text = "Connected" if status else "Not configured"
        logger.info(f"  {icon} {channel}: {status_text}")
    
    # Send test alert
    logger.info("Sending test alert...")
    results = manager.send_test_alert()
    
    logger.info("Results:")
    for channel, success in results.items():
        icon = "✓" if success else "✗"
        status_text = "Sent" if success else "Failed"
        logger.info(f"  {icon} {channel}: {status_text}")
