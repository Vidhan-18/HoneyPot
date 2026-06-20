#!/usr/bin/env python3
"""
Authentication module for web dashboard
"""

import hashlib
import logging
import os
from functools import wraps

from flask import flash, redirect, request, session, url_for

logger = logging.getLogger(__name__)

DEFAULT_USERNAME = os.getenv("ADMIN_USERNAME", os.getenv("DASHBOARD_USERNAME", "admin"))
DEFAULT_PASSWORD_HASH = os.getenv("DASHBOARD_PASSWORD_HASH", "")


def is_production() -> bool:
    return (
        os.getenv("VERCEL") == "1"
        or os.getenv("ENVIRONMENT", "").lower() == "production"
    )


def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


def _resolve_password_hash() -> str:
    """Prefer DASHBOARD_PASSWORD_HASH, else hash ADMIN_PASSWORD at startup."""
    if DEFAULT_PASSWORD_HASH:
        return DEFAULT_PASSWORD_HASH
    admin_password = os.getenv("ADMIN_PASSWORD", "")
    if admin_password:
        return hash_password(admin_password)
    if is_production():
        logger.error(
            "Production requires ADMIN_PASSWORD or DASHBOARD_PASSWORD_HASH. "
            "Login is disabled until configured."
        )
        return ""
    # Local Docker only — dev default (change via .env)
    logger.warning("Using dev default password; set ADMIN_PASSWORD for production.")
    return hash_password("honeypot2024")


RESOLVED_PASSWORD_HASH = _resolve_password_hash()


def verify_password(username: str, password: str) -> bool:
    if not RESOLVED_PASSWORD_HASH:
        return False
    if username != DEFAULT_USERNAME:
        return False
    return hash_password(password) == RESOLVED_PASSWORD_HASH


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "logged_in" not in session or not session["logged_in"]:
            return redirect(url_for("login"))
        return f(*args, **kwargs)

    return decorated_function
