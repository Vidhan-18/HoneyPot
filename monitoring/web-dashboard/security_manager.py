#!/usr/bin/env python3
"""
Security Manager - Comprehensive attack detection and prevention system
Handles SQL injection, XSS, DDoS, API abuse, and unauthorized access detection
"""

import os
import re
import json
import time
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from collections import defaultdict, deque
from pathlib import Path
import logging
import threading

from logging_middleware import logger, log_attack_detected, log_security_event
from ioc_tracker import get_ioc_db, record_ioc, is_ip_blocked, IPBlocker

# Configuration
DDOS_THRESHOLD = int(os.getenv('DDOS_THRESHOLD', '100'))  # requests per minute
DDOS_WINDOW = int(os.getenv('DDOS_WINDOW', '60'))  # seconds
API_RATE_LIMIT = int(os.getenv('API_RATE_LIMIT', '60'))  # requests per minute
BLOCK_DURATION_MINUTES = int(os.getenv('BLOCK_DURATION_MINUTES', '60'))
AUTO_BLOCK_ENABLED = os.getenv('AUTO_BLOCK_ENABLED', 'false').lower() == 'true'

# Setup logger
security_logger = logging.getLogger('security')


@dataclass
class SecurityEvent:
    """Represents a security event"""
    event_type: str
    source_ip: str
    timestamp: datetime
    details: Dict
    severity: str = 'medium'
    blocked: bool = False
    request_id: Optional[str] = None


@dataclass
class RateLimitEntry:
    """Tracks request rate for an IP"""
    requests: List[datetime] = field(default_factory=list)
    blocked_until: Optional[datetime] = None
    violation_count: int = 0


class DDoSProtector:
    """
    DDoS and flooding attack protection
    
    How it works:
    1. Track request timestamps per IP
    2. Count requests in sliding window
    3. Block if threshold exceeded
    4. Gradually unblock after cooldown
    """
    
    def __init__(self):
        self.ip_requests: Dict[str, RateLimitEntry] = defaultdict(RateLimitEntry)
        self.lock = threading.Lock()
        self.blocker = IPBlocker()
    
    def is_ddos_attack(self, ip_address: str) -> Tuple[bool, Dict]:
        """
        Check if IP is performing DDoS attack
        
        Returns:
            (is_attack, details)
        """
        with self.lock:
            entry = self.ip_requests[ip_address]
            now = datetime.now()
            
            # Check if currently blocked
            if entry.blocked_until and now < entry.blocked_until:
                return True, {
                    'reason': 'currently_blocked',
                    'blocked_until': entry.blocked_until.isoformat(),
                    'violation_count': entry.violation_count
                }
            
            # Clean old requests outside window
            cutoff = now - timedelta(seconds=DDOS_WINDOW)
            entry.requests = [req_time for req_time in entry.requests if req_time > cutoff]
            
            # Add current request
            entry.requests.append(now)
            
            # Check threshold
            request_count = len(entry.requests)
            
            if request_count > DDOS_THRESHOLD:
                # DDoS detected!
                entry.violation_count += 1
                
                # Calculate block duration (increases with violations)
                block_duration = min(BLOCK_DURATION_MINUTES * entry.violation_count, 1440)  # Max 24 hours
                entry.blocked_until = now + timedelta(minutes=block_duration)
                
                # Auto-block if enabled
                if AUTO_BLOCK_ENABLED:
                    self.blocker.block(ip_address, f"DDoS attack detected: {request_count} requests in {DDOS_WINDOW}s")
                
                return True, {
                    'reason': 'threshold_exceeded',
                    'request_count': request_count,
                    'threshold': DDOS_THRESHOLD,
                    'window_seconds': DDOS_WINDOW,
                    'block_duration_minutes': block_duration,
                    'violation_count': entry.violation_count
                }
            
            return False, {
                'request_count': request_count,
                'threshold': DDOS_THRESHOLD
            }
    
    def get_rate_limit_status(self, ip_address: str) -> Dict:
        """Get current rate limit status for IP"""
        with self.lock:
            entry = self.ip_requests.get(ip_address)
            if not entry:
                return {
                    'request_count': 0,
                    'threshold': DDOS_THRESHOLD,
                    'blocked': False
                }
            
            now = datetime.now()
            cutoff = now - timedelta(seconds=DDOS_WINDOW)
            recent_requests = [req for req in entry.requests if req > cutoff]
            
            return {
                'request_count': len(recent_requests),
                'threshold': DDOS_THRESHOLD,
                'blocked': entry.blocked_until is not None and now < entry.blocked_until,
                'blocked_until': entry.blocked_until.isoformat() if entry.blocked_until else None,
                'violation_count': entry.violation_count
            }


class APIAbuseDetector:
    """
    Detects API abuse patterns
    
    Patterns detected:
    - Excessive API calls
    - Enumeration attacks (sequential IDs)
    - Abnormal request patterns
    """
    
    def __init__(self):
        self.api_usage: Dict[str, Dict] = defaultdict(lambda: {
            'endpoints': defaultdict(int),
            'errors': 0,
            'last_request': None,
            'suspicious_patterns': []
        })
        self.lock = threading.Lock()
    
    def track_request(self, ip_address: str, endpoint: str, status_code: int, 
                     user_agent: Optional[str] = None) -> Optional[Dict]:
        """
        Track API request and detect abuse
        
        Returns:
            Abuse details if detected, None otherwise
        """
        with self.lock:
            usage = self.api_usage[ip_address]
            now = datetime.now()
            
            # Update stats
            usage['endpoints'][endpoint] += 1
            usage['last_request'] = now
            
            if status_code >= 400:
                usage['errors'] += 1
            
            # Check for abuse patterns
            abuse_indicators = []
            
            # Pattern 1: Excessive calls to same endpoint
            max_endpoint_calls = max(usage['endpoints'].values())
            if max_endpoint_calls > 100:
                abuse_indicators.append({
                    'type': 'endpoint_flooding',
                    'details': f'{max_endpoint_calls} calls to single endpoint'
                })
            
            # Pattern 2: High error rate
            total_calls = sum(usage['endpoints'].values())
            if total_calls > 20 and usage['errors'] / total_calls > 0.5:
                abuse_indicators.append({
                    'type': 'high_error_rate',
                    'details': f'{usage["errors"]}/{total_calls} requests returned errors'
                })
            
            # Pattern 3: Missing/suspicious user agent
            if not user_agent or user_agent in ['-', '']:
                abuse_indicators.append({
                    'type': 'missing_user_agent',
                    'details': 'No user agent provided'
                })
            
            if abuse_indicators:
                return {
                    'ip_address': ip_address,
                    'indicators': abuse_indicators,
                    'total_requests': total_calls,
                    'error_count': usage['errors'],
                    'endpoints': dict(usage['endpoints'])
                }
            
            return None


class SQLInjectionDetector:
    """
    SQL Injection detection and prevention
    
    Detection methods:
    1. Pattern matching (regex)
    2. Keyword analysis
    3. Syntax analysis
    """
    
    # SQL injection patterns
    SQLI_PATTERNS = [
        # Union-based
        r"(\%27)|(\')|(\-\-)|(#)",
        r"((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))",
        r"\w*((\%27)|(\'))((\%6F)|o|(\%4F))((\%72)|r|(\%52))",
        r"UNION\s+SELECT",
        r"UNION\s+ALL\s+SELECT",
        
        # Error-based
        r"AND\s+\d+=\d+",
        r"OR\s+\d+=\d+",
        r"AND\s+'\w+'=\s*'\w+",
        r"OR\s+'\w+'=\s*'\w+",
        
        # Time-based blind
        r"WAITFOR\s+DELAY",
        r"SLEEP\s*\(\s*\d+\s*\)",
        r"BENCHMARK\s*\(",
        
        # Stacked queries
        r";\s*DROP\s+TABLE",
        r";\s*DELETE\s+FROM",
        r";\s*INSERT\s+INTO",
        r";\s*UPDATE\s+\w+\s+SET",
        
        # Comment-based
        r"/\*!\d+\*/",
        r"/\*.*\*/",
        
        # Boolean-based
        r"'\s*AND\s*\d+=\d+\s*--",
        r"'\s*OR\s*'\w+'\s*=\s*'\w+",
    ]
    
    SQL_KEYWORDS = [
        'SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 'CREATE',
        'ALTER', 'EXEC', 'EXECUTE', 'UNION', 'FROM', 'WHERE',
        'ORDER BY', 'GROUP BY', 'HAVING', 'JOIN', 'TABLE'
    ]
    
    def detect(self, data: str) -> Optional[Dict]:
        """
        Detect SQL injection in data
        
        Returns:
            Detection details if SQLi found, None otherwise
        """
        if not data:
            return None
        
        data_upper = data.upper()
        findings = []
        confidence = 0
        
        # Pattern matching
        for pattern in self.SQLI_PATTERNS:
            try:
                matches = re.findall(pattern, data, re.IGNORECASE)
                if matches:
                    findings.append({
                        'type': 'pattern_match',
                        'pattern': pattern,
                        'matches': len(matches)
                    })
                    confidence += 25
            except re.error:
                continue
        
        # Keyword analysis
        keyword_count = sum(1 for kw in self.SQL_KEYWORDS if kw in data_upper)
        if keyword_count >= 2:
            findings.append({
                'type': 'keyword_cluster',
                'keywords_found': keyword_count
            })
            confidence += keyword_count * 10
        
        # Syntax analysis - look for balanced quotes after keywords
        if 'SELECT' in data_upper and data.count("'") % 2 != 0:
            findings.append({
                'type': 'unbalanced_quotes',
                'details': 'Odd number of single quotes'
            })
            confidence += 20
        
        if findings and confidence >= 30:
            return {
                'detected': True,
                'confidence': min(confidence, 100),
                'findings': findings,
                'sample': data[:100]  # Truncated sample
            }
        
        return None
    
    def sanitize(self, data: str) -> str:
        """
        Basic SQL injection sanitization
        
        WARNING: This is NOT a replacement for parameterized queries!
        Use this only as an additional layer of defense.
        """
        # Escape single quotes
        sanitized = data.replace("'", "''")
        
        # Remove null bytes
        sanitized = sanitized.replace('\x00', '')
        
        # Remove comment sequences
        sanitized = re.sub(r'/\*.*?\*/', '', sanitized, flags=re.DOTALL)
        
        return sanitized


class XSSDetector:
    """
    Cross-Site Scripting (XSS) detection
    
    Detects:
    - Reflected XSS
    - Stored XSS
    - DOM-based XSS
    """
    
    XSS_PATTERNS = [
        # Script tags
        r"<script[^>]*>[\s\S]*?</script>",
        r"<script[^>]*>",
        
        # Event handlers
        r"on\w+\s*=\s*['\"]",
        r"on\w+\s*=\s*[^\s>]+",
        
        # JavaScript protocols
        r"javascript:",
        r"vbscript:",
        r"data:text/html",
        
        # HTML entities that could be dangerous
        r"&#[xX]?[0-9a-fA-F]+;",
        
        # SVG with onload
        r"<svg[^>]*onload\s*=",
        
        # Image with onerror
        r"<img[^>]*onerror\s*=",
        
        # iframe
        r"<iframe[^>]*src\s*=",
        
        # Object/Embed
        r"<object[^>]*data\s*=",
        r"<embed[^>]*src\s*=",
    ]
    
    DANGEROUS_ATTRIBUTES = [
        'onerror', 'onload', 'onclick', 'onmouseover',
        'onmouseout', 'onmousedown', 'onmouseup',
        'onfocus', 'onblur', 'onchange', 'onsubmit'
    ]
    
    def detect(self, data: str) -> Optional[Dict]:
        """Detect XSS in data"""
        if not data:
            return None
        
        findings = []
        confidence = 0
        
        # Pattern matching
        for pattern in self.XSS_PATTERNS:
            try:
                matches = re.findall(pattern, data, re.IGNORECASE)
                if matches:
                    findings.append({
                        'type': 'pattern_match',
                        'pattern': pattern[:50],
                        'matches': [m[:50] for m in matches[:3]]  # Limit output
                    })
                    confidence += 30
            except re.error:
                continue
        
        # Check for dangerous attributes
        for attr in self.DANGEROUS_ATTRIBUTES:
            if attr in data.lower():
                findings.append({
                    'type': 'dangerous_attribute',
                    'attribute': attr
                })
                confidence += 15
        
        if findings and confidence >= 30:
            return {
                'detected': True,
                'confidence': min(confidence, 100),
                'findings': findings,
                'sample': data[:100]
            }
        
        return None
    
    def sanitize(self, data: str) -> str:
        """Sanitize XSS by escaping HTML"""
        # Replace HTML special characters
        sanitized = data.replace('&', '&amp;')
        sanitized = sanitized.replace('<', '&lt;')
        sanitized = sanitized.replace('>', '&gt;')
        sanitized = sanitized.replace('"', '&quot;')
        sanitized = sanitized.replace("'", '&#x27;')
        
        return sanitized


class UnauthorizedAccessDetector:
    """
    Detects unauthorized access attempts
    
    Monitors:
    - Failed login attempts
    - Access to restricted endpoints
    - Token/Session abuse
    """
    
    def __init__(self):
        self.failed_logins: Dict[str, List[datetime]] = defaultdict(list)
        self.restricted_access: Dict[str, List[datetime]] = defaultdict(list)
        self.lock = threading.Lock()
    
    def record_failed_login(self, ip_address: str, username: str) -> Optional[Dict]:
        """Record failed login and detect brute force"""
        with self.lock:
            now = datetime.now()
            
            # Clean old entries (older than 1 hour)
            cutoff = now - timedelta(hours=1)
            self.failed_logins[ip_address] = [
                t for t in self.failed_logins[ip_address] if t > cutoff
            ]
            
            # Add current attempt
            self.failed_logins[ip_address].append(now)
            
            # Check threshold
            attempt_count = len(self.failed_logins[ip_address])
            
            if attempt_count >= 10:
                return {
                    'attack_type': 'brute_force',
                    'ip_address': ip_address,
                    'username': username,
                    'attempt_count': attempt_count,
                    'time_window': '1 hour',
                    'severity': 'high'
                }
            
            return None
    
    def record_restricted_access(self, ip_address: str, endpoint: str, 
                                 user_agent: Optional[str] = None) -> Optional[Dict]:
        """Record access attempt to restricted endpoint"""
        with self.lock:
            now = datetime.now()
            
            # Clean old entries
            cutoff = now - timedelta(hours=1)
            self.restricted_access[ip_address] = [
                t for t in self.restricted_access[ip_address] if t > cutoff
            ]
            
            self.restricted_access[ip_address].append(now)
            
            # Check for scanning behavior
            if len(self.restricted_access[ip_address]) >= 5:
                return {
                    'attack_type': 'unauthorized_access_scanning',
                    'ip_address': ip_address,
                    'endpoint': endpoint,
                    'attempt_count': len(self.restricted_access[ip_address]),
                    'user_agent': user_agent,
                    'severity': 'medium'
                }
            
            return None


class SecurityManager:
    """
    Main security manager that coordinates all detection modules
    """
    
    def __init__(self):
        self.ddos_protector = DDoSProtector()
        self.api_abuse_detector = APIAbuseDetector()
        self.sqli_detector = SQLInjectionDetector()
        self.xss_detector = XSSDetector()
        self.unauthorized_detector = UnauthorizedAccessDetector()
        self.blocker = IPBlocker()
        
        # Track all security events — bounded to 10K to prevent OOM
        self.events: deque = deque(maxlen=10000)
        self.events_lock = threading.Lock()
    
    def check_request(self, ip_address: str, endpoint: str, method: str,
                     headers: Dict, body: Optional[str] = None,
                     user_agent: Optional[str] = None) -> Dict:
        """
        Comprehensive security check for incoming request
        
        Returns:
            Security check results with action recommendation
        """
        results = {
            'allowed': True,
            'blocked': False,
            'reasons': [],
            'actions_taken': [],
            'severity': 'low'
        }
        
        # Check 1: Is IP already blocked?
        if self.blocker.is_blocked(ip_address):
            results['allowed'] = False
            results['blocked'] = True
            results['reasons'].append('IP is blocked')
            results['severity'] = 'critical'
            return results
        
        # Check 2: DDoS protection
        is_ddos, ddos_details = self.ddos_protector.is_ddos_attack(ip_address)
        if is_ddos:
            results['allowed'] = False
            results['blocked'] = True
            results['reasons'].append(f"DDoS attack detected: {ddos_details}")
            results['actions_taken'].append('IP blocked for DDoS')
            results['severity'] = 'critical'
            
            self._log_event('ddos_attack', ip_address, ddos_details, 'critical')
            record_ioc(ip_address, 'ddos', ddos_details)
            return results
        
        # Check 3: SQL Injection
        check_data = f"{endpoint} {str(body)}"
        sqli_result = self.sqli_detector.detect(check_data)
        if sqli_result:
            results['reasons'].append(f"SQL Injection detected: {sqli_result['confidence']}% confidence")
            results['severity'] = 'high'
            
            self._log_event('sql_injection', ip_address, sqli_result, 'high')
            record_ioc(ip_address, 'sql_injection', sqli_result)
            
            if AUTO_BLOCK_ENABLED and sqli_result['confidence'] > 80:
                self.blocker.block(ip_address, 'SQL Injection attack')
                results['blocked'] = True
                results['actions_taken'].append('IP auto-blocked for SQLi')
        
        # Check 4: XSS
        xss_result = self.xss_detector.detect(check_data)
        if xss_result:
            results['reasons'].append(f"XSS detected: {xss_result['confidence']}% confidence")
            results['severity'] = 'high'
            
            self._log_event('xss', ip_address, xss_result, 'high')
            record_ioc(ip_address, 'xss', xss_result)
        
        # Check 5: API Abuse
        abuse_result = self.api_abuse_detector.track_request(
            ip_address, endpoint, 200, user_agent
        )
        if abuse_result:
            results['reasons'].append(f"API abuse detected: {abuse_result['indicators']}")
            results['severity'] = 'medium'
            
            self._log_event('api_abuse', ip_address, abuse_result, 'medium')
        
        # Determine final allow/block decision
        if results['blocked']:
            results['allowed'] = False
        
        return results
    
    def check_response(self, ip_address: str, endpoint: str, 
                      status_code: int, response_body: Optional[str] = None):
        """Check response for security issues"""
        # Update API abuse tracking with actual status code
        self.api_abuse_detector.track_request(
            ip_address, endpoint, status_code
        )
    
    def record_failed_login(self, ip_address: str, username: str) -> Optional[Dict]:
        """Record and check failed login attempt"""
        result = self.unauthorized_detector.record_failed_login(ip_address, username)
        
        if result:
            self._log_event('brute_force', ip_address, result, 'high')
            record_ioc(ip_address, 'brute_force', result)
            
            if AUTO_BLOCK_ENABLED and result['attempt_count'] >= 20:
                self.blocker.block(ip_address, 'Brute force attack')
                result['blocked'] = True
        
        return result
    
    def record_restricted_access(self, ip_address: str, endpoint: str,
                                user_agent: Optional[str] = None) -> Optional[Dict]:
        """Record access attempt to restricted area"""
        result = self.unauthorized_detector.record_restricted_access(
            ip_address, endpoint, user_agent
        )
        
        if result:
            self._log_event('unauthorized_access', ip_address, result, 'medium')
            record_ioc(ip_address, 'unauthorized_access', result)
        
        return result
    
    def _log_event(self, event_type: str, source_ip: str, 
                  details: Dict, severity: str):
        """Log security event"""
        event = SecurityEvent(
            event_type=event_type,
            source_ip=source_ip,
            timestamp=datetime.now(),
            details=details,
            severity=severity
        )
        
        with self.events_lock:
            self.events.append(event)
            # Emergency cleanup if deque maxlen somehow doesn't limit (paranoia guard)
            if len(self.events) > 11000:
                self.events = deque(list(self.events)[-10000:], maxlen=10000)
        
        # Also log to standard logger
        log_attack_detected(event_type, details, source_ip)
    
    def get_recent_events(self, limit: int = 100) -> List[Dict]:
        """Get recent security events"""
        with self.events_lock:
            recent = sorted(
                self.events, 
                key=lambda e: e.timestamp, 
                reverse=True
            )[:limit]
            
            return [{
                'event_type': e.event_type,
                'source_ip': e.source_ip,
                'timestamp': e.timestamp.isoformat(),
                'severity': e.severity,
                'details': e.details,
                'blocked': e.blocked
            } for e in recent]
    
    def get_security_stats(self) -> Dict:
        """Get security statistics"""
        with self.events_lock:
            total_events = len(self.events)
            
            # Count by severity
            severity_counts = defaultdict(int)
            type_counts = defaultdict(int)
            
            for event in self.events:
                severity_counts[event.severity] += 1
                type_counts[event.event_type] += 1
            
            return {
                'total_events': total_events,
                'by_severity': dict(severity_counts),
                'by_type': dict(type_counts),
                'blocked_ips': len(self.blocker.blocked_ips),
                'ddos_protector': self.ddos_protector.ip_requests
            }


# Global security manager instance
_security_manager = None
_security_lock = threading.Lock()


def get_security_manager() -> SecurityManager:
    """Get or create security manager singleton"""
    global _security_manager
    if _security_manager is None:
        with _security_lock:
            if _security_manager is None:
                _security_manager = SecurityManager()
    return _security_manager


# Convenience functions
def check_request_security(ip_address: str, endpoint: str, method: str,
                          headers: Dict, body: Optional[str] = None,
                          user_agent: Optional[str] = None) -> Dict:
    """Quick function to check request security"""
    manager = get_security_manager()
    return manager.check_request(ip_address, endpoint, method, headers, body, user_agent)


def record_login_failure(ip_address: str, username: str) -> Optional[Dict]:
    """Record failed login attempt"""
    manager = get_security_manager()
    return manager.record_failed_login(ip_address, username)


# Example usage
if __name__ == '__main__':
    print("Testing Security Manager...")
    
    manager = get_security_manager()
    
    # Test SQL injection detection
    sqli_tests = [
        "'; DROP TABLE users; --",
        "admin' OR '1'='1",
        "normal_username",
        "1 UNION SELECT * FROM passwords"
    ]
    
    print("\nSQL Injection Tests:")
    for test in sqli_tests:
        result = manager.sqli_detector.detect(test)
        if result:
            print(f"  [DETECTED] {test[:30]}... (confidence: {result['confidence']}%)")
        else:
            print(f"  [CLEAN] {test}")
    
    # Test XSS detection
    xss_tests = [
        "<script>alert('xss')</script>",
        "<img src=x onerror=alert(1)>",
        "javascript:alert(1)",
        "normal text"
    ]
    
    print("\nXSS Tests:")
    for test in xss_tests:
        result = manager.xss_detector.detect(test)
        if result:
            print(f"  [DETECTED] {test[:30]}... (confidence: {result['confidence']}%)")
        else:
            print(f"  [CLEAN] {test}")
    
    # Test DDoS protection
    print("\nDDoS Protection Test:")
    test_ip = "192.168.1.100"
    for i in range(105):  # Exceed threshold
        is_ddos, details = manager.ddos_protector.is_ddos_attack(test_ip)
        if is_ddos:
            print(f"  DDoS detected after {i} requests")
            print(f"  Details: {details}")
            break
    
    print("\nSecurity Manager test complete!")
