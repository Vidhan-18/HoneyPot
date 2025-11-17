#!/usr/bin/env python3
"""
Attack Classification Module
Categorizes and classifies attack patterns
"""

import re
import logging
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

# Attack categories
ATTACK_CATEGORIES = {
    'brute_force': {
        'name': 'Brute Force',
        'description': 'Repeated authentication attempts',
        'severity': 'high',
        'icon': '🔨'
    },
    'sql_injection': {
        'name': 'SQL Injection',
        'description': 'SQL injection attempts',
        'severity': 'critical',
        'icon': '💉'
    },
    'command_injection': {
        'name': 'Command Injection',
        'description': 'Command execution attempts',
        'severity': 'critical',
        'icon': '⚡'
    },
    'path_traversal': {
        'name': 'Path Traversal',
        'description': 'Directory traversal attempts',
        'severity': 'high',
        'icon': '📁'
    },
    'xss': {
        'name': 'Cross-Site Scripting',
        'description': 'XSS attack attempts',
        'severity': 'high',
        'icon': '🎯'
    },
    'credential_harvesting': {
        'name': 'Credential Harvesting',
        'description': 'Credential theft attempts',
        'severity': 'high',
        'icon': '🎣'
    },
    'malware_deployment': {
        'name': 'Malware Deployment',
        'description': 'Malware download/execution attempts',
        'severity': 'critical',
        'icon': '🦠'
    },
    'data_exfiltration': {
        'name': 'Data Exfiltration',
        'description': 'Data theft attempts',
        'severity': 'critical',
        'icon': '📤'
    },
    'reconnaissance': {
        'name': 'Reconnaissance',
        'description': 'Information gathering',
        'severity': 'medium',
        'icon': '🔍'
    },
    'privilege_escalation': {
        'name': 'Privilege Escalation',
        'description': 'Privilege escalation attempts',
        'severity': 'high',
        'icon': '⬆️'
    },
    'denial_of_service': {
        'name': 'Denial of Service',
        'description': 'DoS/DDoS attempts',
        'severity': 'high',
        'icon': '💥'
    },
    'unauthorized_access': {
        'name': 'Unauthorized Access',
        'description': 'Unauthorized access attempts',
        'severity': 'medium',
        'icon': '🚫'
    }
}

# Attack patterns
ATTACK_PATTERNS = {
    'brute_force': [
        r'multiple.*login',
        r'failed.*authentication',
        r'password.*attempt',
    ],
    'sql_injection': [
        r'union.*select',
        r"';.*--",
        r'or.*1=1',
        r'drop.*table',
        r'exec.*xp_',
        r'select.*from',
        r'insert.*into',
        r'delete.*from',
    ],
    'command_injection': [
        r';.*cat.*\/etc\/passwd',
        r'\|.*bash',
        r'`.*whoami',
        r'\$\(.*id\)',
        r'cmd\.exe',
        r'powershell',
        r'wget.*http',
        r'curl.*http',
        r'nc.*-e',
        r'bash.*-i',
    ],
    'path_traversal': [
        r'\.\.\/',
        r'\.\.\\',
        r'\/etc\/passwd',
        r'\/etc\/shadow',
        r'c:\\windows\\system32',
        r'\.\.\/\.\.\/',
    ],
    'xss': [
        r'<script>',
        r'javascript:',
        r'onerror=',
        r'onload=',
        r'alert\(',
        r'document\.cookie',
    ],
    'credential_harvesting': [
        r'password.*=.*[\'"]',
        r'passwd.*=.*[\'"]',
        r'pwd.*=.*[\'"]',
        r'credential',
    ],
    'malware_deployment': [
        r'wget.*http',
        r'curl.*http.*\|.*bash',
        r'powershell.*download',
        r'base64.*decode',
        r'eval\(',
        r'exec\(',
    ],
    'data_exfiltration': [
        r'cat.*\/etc\/passwd',
        r'cat.*\/etc\/shadow',
        r'type.*config',
        r'download.*file',
        r'export.*data',
    ],
    'reconnaissance': [
        r'whoami',
        r'uname',
        r'hostname',
        r'ifconfig',
        r'ipconfig',
        r'netstat',
        r'ps.*aux',
        r'ls.*-la',
    ],
    'privilege_escalation': [
        r'sudo',
        r'su.*root',
        r'chmod.*777',
        r'setuid',
        r'privilege',
    ],
    'denial_of_service': [
        r'fork.*bomb',
        r'while.*true',
        r'flood',
    ],
    'unauthorized_access': [
        r'admin',
        r'root',
        r'login',
        r'auth',
    ]
}


def classify_attack(session_data: Dict) -> List[Dict]:
    """
    Classify an attack based on session data
    Returns list of attack categories detected
    """
    attacks = []
    text_content = _extract_text_from_session(session_data)
    
    for category, patterns in ATTACK_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, text_content, re.IGNORECASE):
                attack_info = ATTACK_CATEGORIES[category].copy()
                attack_info['category'] = category
                attack_info['pattern_matched'] = pattern
                attacks.append(attack_info)
                break  # Only add each category once
    
    # Special classification for brute force
    if _is_brute_force(session_data):
        if not any(a['category'] == 'brute_force' for a in attacks):
            attack_info = ATTACK_CATEGORIES['brute_force'].copy()
            attack_info['category'] = 'brute_force'
            attacks.append(attack_info)
    
    return attacks


def _extract_text_from_session(session_data: Dict) -> str:
    """Extract all text content from session for pattern matching"""
    text_parts = []
    
    # Extract from commands
    if 'commands' in session_data:
        for cmd in session_data['commands']:
            if isinstance(cmd, dict):
                text_parts.append(cmd.get('command', ''))
            else:
                text_parts.append(str(cmd))
    
    # Extract from login attempts
    if 'login_attempts' in session_data:
        for login in session_data['login_attempts']:
            if isinstance(login, dict):
                text_parts.append(login.get('username', ''))
                text_parts.append(login.get('password', ''))
    
    # Extract from queries
    if 'queries' in session_data:
        for query in session_data['queries']:
            if isinstance(query, dict):
                text_parts.append(query.get('query', ''))
            else:
                text_parts.append(str(query))
    
    # Extract from HTTP data
    if 'data' in session_data:
        text_parts.append(str(session_data['data']))
    
    if 'path' in session_data:
        text_parts.append(str(session_data['path']))
    
    if 'query_string' in session_data:
        text_parts.append(str(session_data['query_string']))
    
    return ' '.join(text_parts).lower()


def _is_brute_force(session_data: Dict) -> bool:
    """Detect if session is a brute force attack"""
    # Multiple login attempts
    if 'login_attempts' in session_data:
        if len(session_data['login_attempts']) >= 3:
            return True
    
    # Multiple failed authentications
    failed_logins = sum(1 for login in session_data.get('login_attempts', [])
                       if not login.get('success', False))
    if failed_logins >= 3:
        return True
    
    return False


def get_attack_summary(attacks: List[Dict]) -> Dict:
    """Get summary of attacks"""
    if not attacks:
        return {
            'total': 0,
            'critical': 0,
            'high': 0,
            'medium': 0,
            'categories': []
        }
    
    severities = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
    categories = {}
    
    for attack in attacks:
        severity = attack.get('severity', 'medium')
        severities[severity] = severities.get(severity, 0) + 1
        
        category = attack.get('category', 'unknown')
        categories[category] = categories.get(category, 0) + 1
    
    return {
        'total': len(attacks),
        'critical': severities['critical'],
        'high': severities['high'],
        'medium': severities['medium'],
        'low': severities['low'],
        'categories': categories
    }


