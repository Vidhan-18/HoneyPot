#!/usr/bin/env python3
"""
Authentication module for web dashboard
"""

import os
import hashlib
import secrets
from functools import wraps
from flask import session, redirect, url_for, request, flash

# Default credentials (should be changed in production)
DEFAULT_USERNAME = os.getenv('DASHBOARD_USERNAME', 'admin')
DEFAULT_PASSWORD_HASH = os.getenv('DASHBOARD_PASSWORD_HASH', '')

# Generate default password hash if not set
if not DEFAULT_PASSWORD_HASH:
    # Default password: "honeypot2024" (change this!)
    DEFAULT_PASSWORD_HASH = hashlib.sha256('honeypot2024'.encode()).hexdigest()

def hash_password(password):
    """Hash a password using SHA256"""
    return hashlib.sha256(password.encode()).hexdigest()

def verify_password(username, password):
    """Verify username and password"""
    if username != DEFAULT_USERNAME:
        return False
    
    password_hash = hash_password(password)
    return password_hash == DEFAULT_PASSWORD_HASH

def login_required(f):
    """Decorator to require login"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session or not session['logged_in']:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function




