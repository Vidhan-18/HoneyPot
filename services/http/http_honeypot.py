#!/usr/bin/env python3
"""
HTTP Honeypot Service
Simulates web services to capture attacker interactions.
"""

import os
import json
import logging
import time
from datetime import datetime
from pathlib import Path
from flask import Flask, request, Response, jsonify, render_template_string
import threading

# Setup logging
log_dir = Path("/var/log/honeypot")
log_dir.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(log_dir / "http_honeypot.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Session storage
sessions_dir = Path("/sessions")
sessions_dir.mkdir(parents=True, exist_ok=True)

app = Flask(__name__)
app.config['JSONIFY_PRETTYPRINT_REGULAR'] = True

# Track requests
request_counter = 0
request_lock = threading.Lock()


def log_request(request_data):
    """Log HTTP request to file"""
    global request_counter
    with request_lock:
        request_counter += 1
        session_id = f"{int(time.time())}_{request_counter}"
    
    log_entry = {
        'session_id': session_id,
        'timestamp': datetime.now().isoformat(),
        'client_ip': request.remote_addr,
        'method': request.method,
        'path': request.path,
        'query_string': request.query_string.decode('utf-8', errors='ignore'),
        'headers': dict(request.headers),
        'data': request.get_data(as_text=True),
        'user_agent': request.headers.get('User-Agent', ''),
        'referer': request.headers.get('Referer', '')
    }
    
    logger.warning(f"HTTP Request: {request.method} {request.path} from {request.remote_addr}")
    
    # Save to session file
    session_file = sessions_dir / f"http_session_{session_id}.json"
    try:
        with open(session_file, 'w') as f:
            json.dump(log_entry, f, indent=2)
    except Exception as e:
        logger.error(f"Failed to save session: {e}")
    
    return log_entry


@app.before_request
def before_request():
    """Log all requests"""
    log_request(request)


@app.route('/', methods=['GET', 'POST'])
def index():
    """Main page - Premium Redesign"""
    html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Nexus Portal — Enterprise Access</title>
        <link rel="preconnect" href="https://fonts.googleapis.com">
        <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
        <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&family=Space+Grotesk:wght@600;700&display=swap" rel="stylesheet">
        <style>
            * { margin: 0; padding: 0; box-sizing: border-box; }
            
            :root {
                --void: #0D0D12;
                --cosmic: #1A1429;
                --nebula: #2D1F4F;
                --aurora: #7C3AED;
                --lavender: #A78BFA;
                --coral: #F97066;
                --teal: #14B8A6;
                --solar: #FBBF24;
                --pink: #EC4899;
                --text-primary: #F8FAFC;
                --text-secondary: #94A3B8;
                --glass: rgba(26, 20, 41, 0.8);
            }
            
            body {
                font-family: 'Inter', sans-serif;
                background: var(--void);
                min-height: 100vh;
                color: var(--text-primary);
                overflow-x: hidden;
            }
            
            /* Animated background */
            .bg-mesh {
                position: fixed;
                top: 0;
                left: 0;
                width: 100%;
                height: 100%;
                z-index: -1;
                background: 
                    radial-gradient(ellipse at 20% 20%, rgba(124, 58, 237, 0.15) 0%, transparent 50%),
                    radial-gradient(ellipse at 80% 80%, rgba(20, 184, 166, 0.1) 0%, transparent 50%),
                    radial-gradient(ellipse at 50% 50%, rgba(249, 112, 102, 0.05) 0%, transparent 70%);
                animation: meshMove 20s ease-in-out infinite;
            }
            
            @keyframes meshMove {
                0%, 100% { transform: translate(0, 0) scale(1); }
                33% { transform: translate(30px, -30px) scale(1.1); }
                66% { transform: translate(-20px, 20px) scale(0.95); }
            }
            
            /* Navigation */
            .navbar {
                background: var(--glass);
                backdrop-filter: blur(20px);
                border-bottom: 1px solid rgba(124, 58, 237, 0.2);
                padding: 20px 40px;
                display: flex;
                justify-content: space-between;
                align-items: center;
                position: sticky;
                top: 0;
                z-index: 100;
            }
            
            .navbar-brand {
                font-family: 'Space Grotesk', sans-serif;
                font-size: 26px;
                font-weight: 700;
                background: linear-gradient(135deg, var(--aurora) 0%, var(--coral) 100%);
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
                background-clip: text;
                text-decoration: none;
                display: flex;
                align-items: center;
                gap: 10px;
            }
            
            .navbar-brand::before {
                content: '◆';
                font-size: 20px;
                background: linear-gradient(135deg, var(--aurora) 0%, var(--teal) 100%);
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
            }
            
            .navbar-nav {
                display: flex;
                gap: 8px;
                list-style: none;
            }
            
            .navbar-nav a {
                color: var(--text-secondary);
                text-decoration: none;
                font-weight: 500;
                font-size: 14px;
                padding: 10px 20px;
                border-radius: 12px;
                transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
                position: relative;
                overflow: hidden;
            }
            
            .navbar-nav a::before {
                content: '';
                position: absolute;
                inset: 0;
                background: linear-gradient(135deg, rgba(124, 58, 237, 0.2) 0%, rgba(20, 184, 166, 0.1) 100%);
                opacity: 0;
                transition: opacity 0.3s;
            }
            
            .navbar-nav a:hover {
                color: var(--text-primary);
                transform: translateY(-2px);
            }
            
            .navbar-nav a:hover::before {
                opacity: 1;
            }
            
            /* Hero Section */
            .hero {
                padding: 100px 40px 60px;
                max-width: 1400px;
                margin: 0 auto;
                display: grid;
                grid-template-columns: 1.2fr 1fr;
                gap: 80px;
                align-items: center;
            }
            
            .hero-content h1 {
                font-family: 'Space Grotesk', sans-serif;
                font-size: 64px;
                font-weight: 700;
                line-height: 1.1;
                margin-bottom: 24px;
                background: linear-gradient(135deg, var(--text-primary) 0%, var(--lavender) 100%);
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
                background-clip: text;
            }
            
            .hero-content h1 span {
                display: block;
                background: linear-gradient(135deg, var(--aurora) 0%, var(--coral) 50%, var(--teal) 100%);
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
            }
            
            .hero-content p {
                font-size: 20px;
                color: var(--text-secondary);
                line-height: 1.7;
                margin-bottom: 40px;
                max-width: 500px;
            }
            
            .hero-actions {
                display: flex;
                gap: 16px;
                flex-wrap: wrap;
            }
            
            .btn {
                display: inline-flex;
                align-items: center;
                gap: 10px;
                padding: 16px 32px;
                font-family: 'Inter', sans-serif;
                font-weight: 600;
                font-size: 15px;
                text-decoration: none;
                border-radius: 14px;
                transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
                position: relative;
                overflow: hidden;
                border: none;
                cursor: pointer;
            }
            
            .btn-primary {
                background: linear-gradient(135deg, var(--coral) 0%, var(--pink) 100%);
                color: white;
                box-shadow: 0 4px 20px rgba(249, 112, 102, 0.4);
            }
            
            .btn-primary:hover {
                transform: translateY(-3px) scale(1.02);
                box-shadow: 0 8px 30px rgba(249, 112, 102, 0.5);
            }
            
            .btn-secondary {
                background: rgba(124, 58, 237, 0.1);
                color: var(--lavender);
                border: 1px solid rgba(124, 58, 237, 0.3);
            }
            
            .btn-secondary:hover {
                background: rgba(124, 58, 237, 0.2);
                border-color: rgba(124, 58, 237, 0.5);
                transform: translateY(-3px);
            }
            
            .btn::after {
                content: '→';
                transition: transform 0.3s;
            }
            
            .btn:hover::after {
                transform: translateX(4px);
            }
            
            /* Hero Visual */
            .hero-visual {
                position: relative;
                height: 400px;
            }
            
            .dashboard-preview {
                position: absolute;
                width: 100%;
                height: 100%;
                background: linear-gradient(145deg, var(--cosmic) 0%, var(--nebula) 100%);
                border-radius: 24px;
                border: 1px solid rgba(124, 58, 237, 0.2);
                box-shadow: 
                    0 25px 50px -12px rgba(0, 0, 0, 0.5),
                    0 0 0 1px rgba(124, 58, 237, 0.1);
                padding: 24px;
                display: flex;
                flex-direction: column;
                gap: 16px;
                animation: float 6s ease-in-out infinite;
            }
            
            @keyframes float {
                0%, 100% { transform: translateY(0px); }
                50% { transform: translateY(-10px); }
            }
            
            .preview-header {
                display: flex;
                gap: 8px;
            }
            
            .preview-dot {
                width: 12px;
                height: 12px;
                border-radius: 50%;
            }
            
            .preview-dot:nth-child(1) { background: var(--coral); }
            .preview-dot:nth-child(2) { background: var(--solar); }
            .preview-dot:nth-child(3) { background: var(--teal); }
            
            .preview-content {
                flex: 1;
                display: grid;
                grid-template-columns: 2fr 1fr;
                gap: 16px;
            }
            
            .preview-card {
                background: rgba(124, 58, 237, 0.1);
                border-radius: 12px;
                border: 1px solid rgba(124, 58, 237, 0.15);
            }
            
            .preview-card.large {
                grid-row: span 2;
            }
            
            /* Features Section */
            .features {
                padding: 100px 40px;
                max-width: 1400px;
                margin: 0 auto;
            }
            
            .section-header {
                text-align: center;
                margin-bottom: 60px;
            }
            
            .section-header h2 {
                font-family: 'Space Grotesk', sans-serif;
                font-size: 40px;
                font-weight: 700;
                margin-bottom: 16px;
                background: linear-gradient(135deg, var(--text-primary) 0%, var(--lavender) 100%);
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
            }
            
            .section-header p {
                color: var(--text-secondary);
                font-size: 18px;
            }
            
            .features-grid {
                display: grid;
                grid-template-columns: repeat(3, 1fr);
                gap: 24px;
            }
            
            .feature-card {
                background: linear-gradient(145deg, var(--cosmic) 0%, rgba(45, 31, 79, 0.5) 100%);
                border: 1px solid rgba(124, 58, 237, 0.15);
                border-radius: 20px;
                padding: 32px;
                transition: all 0.4s cubic-bezier(0.4, 0, 0.2, 1);
                position: relative;
                overflow: hidden;
            }
            
            .feature-card::before {
                content: '';
                position: absolute;
                top: 0;
                left: 0;
                right: 0;
                height: 3px;
                background: linear-gradient(90deg, var(--aurora), var(--coral), var(--teal));
                opacity: 0;
                transition: opacity 0.3s;
            }
            
            .feature-card:hover {
                transform: translateY(-8px);
                border-color: rgba(124, 58, 237, 0.3);
                box-shadow: 0 20px 40px rgba(124, 58, 237, 0.2);
            }
            
            .feature-card:hover::before {
                opacity: 1;
            }
            
            .feature-card.featured {
                grid-column: span 2;
                display: grid;
                grid-template-columns: 1fr 1fr;
                gap: 32px;
                align-items: center;
            }
            
            .feature-icon {
                width: 56px;
                height: 56px;
                border-radius: 16px;
                display: flex;
                align-items: center;
                justify-content: center;
                font-size: 28px;
                margin-bottom: 24px;
                background: linear-gradient(135deg, rgba(124, 58, 237, 0.2) 0%, rgba(20, 184, 166, 0.1) 100%);
                border: 1px solid rgba(124, 58, 237, 0.2);
            }
            
            .feature-card h3 {
                font-family: 'Space Grotesk', sans-serif;
                font-size: 22px;
                font-weight: 600;
                margin-bottom: 12px;
                color: var(--text-primary);
            }
            
            .feature-card p {
                color: var(--text-secondary);
                line-height: 1.7;
                font-size: 15px;
            }
            
            .feature-stats {
                display: flex;
                gap: 32px;
                margin-top: 24px;
            }
            
            .stat {
                display: flex;
                flex-direction: column;
            }
            
            .stat-value {
                font-family: 'Space Grotesk', sans-serif;
                font-size: 32px;
                font-weight: 700;
                background: linear-gradient(135deg, var(--aurora) 0%, var(--coral) 100%);
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
            }
            
            .stat-label {
                font-size: 13px;
                color: var(--text-secondary);
                text-transform: uppercase;
                letter-spacing: 0.5px;
            }
            
            /* Footer */
            .footer {
                border-top: 1px solid rgba(124, 58, 237, 0.1);
                padding: 40px;
                text-align: center;
                color: var(--text-secondary);
                font-size: 14px;
            }
            
            /* Responsive */
            @media (max-width: 1024px) {
                .hero {
                    grid-template-columns: 1fr;
                    gap: 60px;
                    text-align: center;
                }
                .hero-content h1 {
                    font-size: 48px;
                }
                .hero-content p {
                    margin: 0 auto 40px;
                }
                .hero-actions {
                    justify-content: center;
                }
                .features-grid {
                    grid-template-columns: 1fr;
                }
                .feature-card.featured {
                    grid-column: span 1;
                    grid-template-columns: 1fr;
                }
            }
            
            @media (max-width: 640px) {
                .navbar {
                    padding: 16px 20px;
                }
                .navbar-nav {
                    display: none;
                }
                .hero {
                    padding: 60px 20px;
                }
                .hero-content h1 {
                    font-size: 36px;
                }
                .features {
                    padding: 60px 20px;
                }
            }
        </style>
    </head>
    <body>
        <div class="bg-mesh"></div>
        
        <nav class="navbar">
            <a href="/" class="navbar-brand">Nexus Portal</a>
            <ul class="navbar-nav">
                <li><a href="/">Platform</a></li>
                <li><a href="/login">Access</a></li>
                <li><a href="/admin">Control</a></li>
                <li><a href="/api">Developers</a></li>
            </ul>
        </nav>
        
        <section class="hero">
            <div class="hero-content">
                <h1>Secure Access for <span>Modern Teams</span></h1>
                <p>Enterprise-grade identity management with intelligent threat detection. Protect your infrastructure without compromising user experience.</p>
                <div class="hero-actions">
                    <a href="/login" class="btn btn-primary">Access Portal</a>
                    <a href="/admin" class="btn btn-secondary">Admin Console</a>
                </div>
            </div>
            <div class="hero-visual">
                <div class="dashboard-preview">
                    <div class="preview-header">
                        <div class="preview-dot"></div>
                        <div class="preview-dot"></div>
                        <div class="preview-dot"></div>
                    </div>
                    <div class="preview-content">
                        <div class="preview-card large"></div>
                        <div class="preview-card"></div>
                        <div class="preview-card"></div>
                    </div>
                </div>
            </div>
        </section>
        
        <section class="features">
            <div class="section-header">
                <h2>Built for Security Teams</h2>
                <p>Everything you need to monitor, analyze, and respond to threats</p>
            </div>
            <div class="features-grid">
                <div class="feature-card featured">
                    <div>
                        <div class="feature-icon">🛡️</div>
                        <h3>Intelligent Threat Detection</h3>
                        <p>AI-powered analysis identifies suspicious patterns in real-time. Our system learns from every interaction to improve detection accuracy.</p>
                        <div class="feature-stats">
                            <div class="stat">
                                <span class="stat-value">99.9%</span>
                                <span class="stat-label">Uptime</span>
                            </div>
                            <div class="stat">
                                <span class="stat-value">< 50ms</span>
                                <span class="stat-label">Response</span>
                            </div>
                        </div>
                    </div>
                    <div class="preview-card" style="height: 200px;"></div>
                </div>
                <div class="feature-card">
                    <div class="feature-icon">📊</div>
                    <h3>Real-time Analytics</h3>
                    <p>Comprehensive dashboards with actionable insights into access patterns and security events.</p>
                </div>
                <div class="feature-card">
                    <div class="feature-icon">⚡</div>
                    <h3>Instant Response</h3>
                    <p>Automated countermeasures deploy within seconds of threat detection.</p>
                </div>
                <div class="feature-card">
                    <div class="feature-icon">🔐</div>
                    <h3>Zero Trust Architecture</h3>
                    <p>Every request verified, every session monitored, every access logged.</p>
                </div>
            </div>
        </section>
        
        <footer class="footer">
            <p>© 2024 Nexus Portal. Enterprise Security Platform.</p>
        </footer>
    </body>
    </html>
    """
    return Response(html, mimetype='text/html')


@app.route('/admin', methods=['GET', 'POST'])
def admin():
    """Fake admin panel"""
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        logger.warning(f"Admin login attempt: username={username}, password={password}")
        # Show "success" but log it
        html = """
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Access Denied — Nexus Admin</title>
            <link rel="preconnect" href="https://fonts.googleapis.com">
            <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
            <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&family=Space+Grotesk:wght@600;700&display=swap" rel="stylesheet">
            <style>
                * { margin: 0; padding: 0; box-sizing: border-box; }
                
                :root {
                    --void: #0D0D12;
                    --cosmic: #1A1429;
                    --nebula: #2D1F4F;
                    --aurora: #7C3AED;
                    --lavender: #A78BFA;
                    --coral: #F97066;
                    --teal: #14B8A6;
                    --solar: #FBBF24;
                    --pink: #EC4899;
                    --text-primary: #F8FAFC;
                    --text-secondary: #94A3B8;
                }
                
                body {
                    font-family: 'Inter', sans-serif;
                    background: var(--void);
                    min-height: 100vh;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    padding: 20px;
                    position: relative;
                    overflow: hidden;
                }
                
                .orb {
                    position: absolute;
                    border-radius: 50%;
                    filter: blur(80px);
                    opacity: 0.5;
                    animation: orbFloat 15s ease-in-out infinite;
                }
                
                .orb-1 { width: 400px; height: 400px; background: var(--aurora); top: -100px; right: -100px; }
                .orb-2 { width: 300px; height: 300px; background: var(--coral); bottom: -50px; left: -50px; animation-delay: -5s; }
                
                @keyframes orbFloat {
                    0%, 100% { transform: translate(0, 0) scale(1); }
                    33% { transform: translate(30px, -30px) scale(1.1); }
                    66% { transform: translate(-20px, 20px) scale(0.9); }
                }
                
                .container {
                    position: relative;
                    z-index: 10;
                    text-align: center;
                    max-width: 420px;
                }
                
                .error-icon {
                    width: 80px;
                    height: 80px;
                    margin: 0 auto 32px;
                    background: linear-gradient(135deg, rgba(249, 112, 102, 0.1) 0%, rgba(236, 72, 153, 0.1) 100%);
                    border: 1px solid rgba(249, 112, 102, 0.2);
                    border-radius: 24px;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    font-size: 40px;
                }
                
                .card {
                    background: linear-gradient(145deg, rgba(26, 20, 41, 0.9) 0%, rgba(45, 31, 79, 0.6) 100%);
                    backdrop-filter: blur(20px);
                    border: 1px solid rgba(124, 58, 237, 0.2);
                    border-radius: 24px;
                    padding: 48px;
                    box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5);
                }
                
                .card h1 {
                    font-family: 'Space Grotesk', sans-serif;
                    font-size: 28px;
                    font-weight: 700;
                    color: var(--text-primary);
                    margin-bottom: 16px;
                }
                
                .alert {
                    background: rgba(249, 112, 102, 0.1);
                    border: 1px solid rgba(249, 112, 102, 0.3);
                    color: var(--coral);
                    padding: 16px;
                    border-radius: 12px;
                    margin-bottom: 24px;
                    font-size: 14px;
                }
                
                .card p {
                    color: var(--text-secondary);
                    margin-bottom: 24px;
                    line-height: 1.6;
                }
                
                .btn {
                    display: inline-flex;
                    align-items: center;
                    gap: 10px;
                    padding: 16px 32px;
                    background: linear-gradient(135deg, var(--coral) 0%, var(--pink) 100%);
                    color: white;
                    text-decoration: none;
                    border-radius: 14px;
                    font-weight: 600;
                    font-size: 15px;
                    transition: all 0.3s;
                    box-shadow: 0 4px 20px rgba(249, 112, 102, 0.3);
                }
                
                .btn:hover {
                    transform: translateY(-2px);
                    box-shadow: 0 8px 30px rgba(249, 112, 102, 0.4);
                }
                
                @media (max-width: 480px) {
                    .card { padding: 32px 24px; }
                }
            </style>
        </head>
        <body>
            <div class="orb orb-1"></div>
            <div class="orb orb-2"></div>
            
            <div class="container">
                <div class="error-icon">🚫</div>
                <div class="card">
                    <h1>Access Denied</h1>
                    <div class="alert">Invalid administrator credentials</div>
                    <p>This incident has been logged. Unauthorized access attempts are monitored and may result in account suspension.</p>
                    <a href="/admin" class="btn">Return to Login</a>
                </div>
            </div>
        </body>
        </html>
        """
        return Response(html, mimetype='text/html')
        
    html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Admin Console — Nexus</title>
        <link rel="preconnect" href="https://fonts.googleapis.com">
        <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
        <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&family=Space+Grotesk:wght@600;700&display=swap" rel="stylesheet">
        <style>
            * { margin: 0; padding: 0; box-sizing: border-box; }
            
            :root {
                --void: #0D0D12;
                --cosmic: #1A1429;
                --nebula: #2D1F4F;
                --aurora: #7C3AED;
                --lavender: #A78BFA;
                --coral: #F97066;
                --teal: #14B8A6;
                --solar: #FBBF24;
                --pink: #EC4899;
                --text-primary: #F8FAFC;
                --text-secondary: #94A3B8;
            }
            
            body {
                font-family: 'Inter', sans-serif;
                background: var(--void);
                min-height: 100vh;
                display: flex;
                align-items: center;
                justify-content: center;
                padding: 20px;
                position: relative;
                overflow: hidden;
            }
            
            .orb {
                position: absolute;
                border-radius: 50%;
                filter: blur(80px);
                opacity: 0.5;
                animation: orbFloat 15s ease-in-out infinite;
            }
            
            .orb-1 { width: 400px; height: 400px; background: var(--aurora); top: -100px; right: -100px; }
            .orb-2 { width: 300px; height: 300px; background: var(--teal); bottom: -50px; left: -50px; animation-delay: -5s; }
            
            @keyframes orbFloat {
                0%, 100% { transform: translate(0, 0) scale(1); }
                33% { transform: translate(30px, -30px) scale(1.1); }
                66% { transform: translate(-20px, 20px) scale(0.9); }
            }
            
            .login-container {
                position: relative;
                z-index: 10;
                width: 100%;
                max-width: 420px;
            }
            
            .brand {
                text-align: center;
                margin-bottom: 40px;
            }
            
            .brand-logo {
                font-family: 'Space Grotesk', sans-serif;
                font-size: 32px;
                font-weight: 700;
                background: linear-gradient(135deg, var(--aurora) 0%, var(--teal) 100%);
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
                display: inline-flex;
                align-items: center;
                gap: 12px;
                margin-bottom: 12px;
            }
            
            .brand-logo::before { content: '◆'; font-size: 24px; }
            
            .brand-tagline {
                color: var(--text-secondary);
                font-size: 15px;
            }
            
            .card {
                background: linear-gradient(145deg, rgba(26, 20, 41, 0.9) 0%, rgba(45, 31, 79, 0.6) 100%);
                backdrop-filter: blur(20px);
                border: 1px solid rgba(124, 58, 237, 0.2);
                border-radius: 24px;
                padding: 48px;
                box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5);
            }
            
            .card h1 {
                font-family: 'Space Grotesk', sans-serif;
                font-size: 28px;
                font-weight: 700;
                color: var(--text-primary);
                margin-bottom: 8px;
                text-align: center;
            }
            
            .card-subtitle {
                color: var(--text-secondary);
                text-align: center;
                margin-bottom: 32px;
                font-size: 15px;
            }
            
            .admin-badge {
                display: inline-flex;
                align-items: center;
                gap: 8px;
                background: rgba(20, 184, 166, 0.1);
                border: 1px solid rgba(20, 184, 166, 0.3);
                color: var(--teal);
                padding: 8px 16px;
                border-radius: 20px;
                font-size: 12px;
                font-weight: 600;
                text-transform: uppercase;
                letter-spacing: 0.5px;
                margin: 0 auto 24px;
                display: block;
                width: fit-content;
            }
            
            .form-group { margin-bottom: 24px; }
            .form-group label {
                display: block;
                margin-bottom: 8px;
                font-weight: 500;
                color: var(--text-secondary);
                font-size: 14px;
                text-transform: uppercase;
                letter-spacing: 0.5px;
            }
            
            .form-group input {
                width: 100%;
                padding: 16px 18px;
                background: rgba(13, 13, 18, 0.6);
                border: 1px solid rgba(124, 58, 237, 0.2);
                border-radius: 12px;
                font-size: 16px;
                color: var(--text-primary);
                font-family: 'Inter', sans-serif;
                transition: all 0.3s;
            }
            
            .form-group input:focus {
                outline: none;
                border-color: var(--teal);
                box-shadow: 0 0 0 4px rgba(20, 184, 166, 0.1);
            }
            
            .btn {
                width: 100%;
                padding: 18px;
                background: linear-gradient(135deg, var(--teal) 0%, var(--aurora) 100%);
                color: white;
                border: none;
                border-radius: 14px;
                font-size: 16px;
                font-weight: 600;
                font-family: 'Inter', sans-serif;
                cursor: pointer;
                transition: all 0.3s;
                box-shadow: 0 4px 20px rgba(20, 184, 166, 0.3);
            }
            
            .btn:hover {
                transform: translateY(-2px);
                box-shadow: 0 8px 30px rgba(20, 184, 166, 0.4);
            }
            
            .back-link {
                display: block;
                text-align: center;
                margin-top: 24px;
                color: var(--text-secondary);
                text-decoration: none;
                font-size: 14px;
                transition: color 0.3s;
            }
            
            .back-link:hover { color: var(--lavender); }
            
            @media (max-width: 480px) {
                .card { padding: 32px 24px; }
            }
        </style>
    </head>
    <body>
        <div class="orb orb-1"></div>
        <div class="orb orb-2"></div>
        
        <div class="login-container">
            <div class="brand">
                <div class="brand-logo">Nexus</div>
                <div class="brand-tagline">Administrative Console</div>
            </div>
            
            <div class="card">
                <span class="admin-badge">🔐 Restricted Access</span>
                <h1>Admin Login</h1>
                <p class="card-subtitle">Elevated privileges required</p>
                
                <form method="POST">
                    <div class="form-group">
                        <label for="username">Administrator ID</label>
                        <input type="text" id="username" name="username" placeholder="admin" required autofocus autocomplete="username">
                    </div>
                    <div class="form-group">
                        <label for="password">Password</label>
                        <input type="password" id="password" name="password" placeholder="••••••••" required autocomplete="current-password">
                    </div>
                    <button type="submit" class="btn">Authenticate</button>
                </form>
            </div>
            
            <a href="/" class="back-link">← Return to homepage</a>
        </div>
    </body>
    </html>
    """
    return Response(html, mimetype='text/html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Fake login page"""
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        logger.warning(f"Login attempt: username={username}, password={password}")
        # Show error but log credentials
        html = """
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Access Denied — Nexus</title>
            <link rel="preconnect" href="https://fonts.googleapis.com">
            <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
            <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&family=Space+Grotesk:wght@600;700&display=swap" rel="stylesheet">
            <style>
                * { margin: 0; padding: 0; box-sizing: border-box; }
                
                :root {
                    --void: #0D0D12;
                    --cosmic: #1A1429;
                    --nebula: #2D1F4F;
                    --aurora: #7C3AED;
                    --lavender: #A78BFA;
                    --coral: #F97066;
                    --teal: #14B8A6;
                    --solar: #FBBF24;
                    --pink: #EC4899;
                    --text-primary: #F8FAFC;
                    --text-secondary: #94A3B8;
                }
                
                body {
                    font-family: 'Inter', sans-serif;
                    background: var(--void);
                    min-height: 100vh;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    padding: 20px;
                    position: relative;
                    overflow: hidden;
                }
                
                .orb {
                    position: absolute;
                    border-radius: 50%;
                    filter: blur(80px);
                    opacity: 0.5;
                    animation: orbFloat 15s ease-in-out infinite;
                }
                
                .orb-1 { width: 400px; height: 400px; background: var(--aurora); top: -100px; right: -100px; }
                .orb-2 { width: 300px; height: 300px; background: var(--coral); bottom: -50px; left: -50px; animation-delay: -5s; }
                
                @keyframes orbFloat {
                    0%, 100% { transform: translate(0, 0) scale(1); }
                    33% { transform: translate(30px, -30px) scale(1.1); }
                    66% { transform: translate(-20px, 20px) scale(0.9); }
                }
                
                .login-container {
                    position: relative;
                    z-index: 10;
                    width: 100%;
                    max-width: 420px;
                }
                
                .brand {
                    text-align: center;
                    margin-bottom: 40px;
                }
                
                .brand-logo {
                    font-family: 'Space Grotesk', sans-serif;
                    font-size: 32px;
                    font-weight: 700;
                    background: linear-gradient(135deg, var(--aurora) 0%, var(--coral) 100%);
                    -webkit-background-clip: text;
                    -webkit-text-fill-color: transparent;
                    display: inline-flex;
                    align-items: center;
                    gap: 12px;
                    margin-bottom: 12px;
                }
                
                .brand-logo::before { content: '◆'; font-size: 24px; }
                
                .card {
                    background: linear-gradient(145deg, rgba(26, 20, 41, 0.9) 0%, rgba(45, 31, 79, 0.6) 100%);
                    backdrop-filter: blur(20px);
                    border: 1px solid rgba(124, 58, 237, 0.2);
                    border-radius: 24px;
                    padding: 48px;
                    box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5);
                }
                
                .card h1 {
                    font-family: 'Space Grotesk', sans-serif;
                    font-size: 28px;
                    font-weight: 700;
                    color: var(--text-primary);
                    margin-bottom: 8px;
                    text-align: center;
                }
                
                .alert {
                    background: rgba(249, 112, 102, 0.1);
                    border: 1px solid rgba(249, 112, 102, 0.3);
                    color: var(--coral);
                    padding: 16px;
                    border-radius: 12px;
                    margin-bottom: 24px;
                    font-size: 14px;
                    text-align: center;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    gap: 10px;
                }
                
                .alert::before { content: '⚠️'; }
                
                .form-group { margin-bottom: 24px; }
                .form-group label {
                    display: block;
                    margin-bottom: 8px;
                    font-weight: 500;
                    color: var(--text-secondary);
                    font-size: 14px;
                    text-transform: uppercase;
                    letter-spacing: 0.5px;
                }
                
                .form-group input {
                    width: 100%;
                    padding: 16px 18px;
                    background: rgba(13, 13, 18, 0.6);
                    border: 1px solid rgba(124, 58, 237, 0.2);
                    border-radius: 12px;
                    font-size: 16px;
                    color: var(--text-primary);
                    font-family: 'Inter', sans-serif;
                    transition: all 0.3s;
                }
                
                .form-group input:focus {
                    outline: none;
                    border-color: var(--aurora);
                    box-shadow: 0 0 0 4px rgba(124, 58, 237, 0.1);
                }
                
                .btn {
                    width: 100%;
                    padding: 18px;
                    background: linear-gradient(135deg, var(--coral) 0%, var(--pink) 100%);
                    color: white;
                    border: none;
                    border-radius: 14px;
                    font-size: 16px;
                    font-weight: 600;
                    font-family: 'Inter', sans-serif;
                    cursor: pointer;
                    transition: all 0.3s;
                    box-shadow: 0 4px 20px rgba(249, 112, 102, 0.3);
                }
                
                .btn:hover {
                    transform: translateY(-2px);
                    box-shadow: 0 8px 30px rgba(249, 112, 102, 0.4);
                }
                
                @media (max-width: 480px) {
                    .card { padding: 32px 24px; }
                }
            </style>
        </head>
        <body>
            <div class="orb orb-1"></div>
            <div class="orb orb-2"></div>
            
            <div class="login-container">
                <div class="brand">
                    <div class="brand-logo">Nexus</div>
                </div>
                
                <div class="card">
                    <h1>Authentication Failed</h1>
                    <div class="alert">Invalid credentials. Please verify and try again.</div>
                    <form method="POST">
                        <div class="form-group">
                            <label for="username">Username</label>
                            <input type="text" id="username" name="username" required autofocus autocomplete="username">
                        </div>
                        <div class="form-group">
                            <label for="password">Password</label>
                            <input type="password" id="password" name="password" required autocomplete="current-password">
                        </div>
                        <button type="submit" class="btn">Try Again</button>
                    </form>
                </div>
            </div>
        </body>
        </html>
        """
        return Response(html, mimetype='text/html')
    
    html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Access Portal — Nexus</title>
        <link rel="preconnect" href="https://fonts.googleapis.com">
        <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
        <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&family=Space+Grotesk:wght@600;700&display=swap" rel="stylesheet">
        <style>
            * { margin: 0; padding: 0; box-sizing: border-box; }
            
            :root {
                --void: #0D0D12;
                --cosmic: #1A1429;
                --nebula: #2D1F4F;
                --aurora: #7C3AED;
                --lavender: #A78BFA;
                --coral: #F97066;
                --teal: #14B8A6;
                --solar: #FBBF24;
                --pink: #EC4899;
                --text-primary: #F8FAFC;
                --text-secondary: #94A3B8;
            }
            
            body {
                font-family: 'Inter', sans-serif;
                background: var(--void);
                min-height: 100vh;
                display: flex;
                align-items: center;
                justify-content: center;
                padding: 20px;
                position: relative;
                overflow: hidden;
            }
            
            /* Animated background orbs */
            .orb {
                position: absolute;
                border-radius: 50%;
                filter: blur(80px);
                opacity: 0.5;
                animation: orbFloat 15s ease-in-out infinite;
            }
            
            .orb-1 {
                width: 400px;
                height: 400px;
                background: var(--aurora);
                top: -100px;
                right: -100px;
                animation-delay: 0s;
            }
            
            .orb-2 {
                width: 300px;
                height: 300px;
                background: var(--coral);
                bottom: -50px;
                left: -50px;
                animation-delay: -5s;
            }
            
            .orb-3 {
                width: 200px;
                height: 200px;
                background: var(--teal);
                top: 50%;
                left: 30%;
                animation-delay: -10s;
            }
            
            @keyframes orbFloat {
                0%, 100% { transform: translate(0, 0) scale(1); }
                33% { transform: translate(30px, -30px) scale(1.1); }
                66% { transform: translate(-20px, 20px) scale(0.9); }
            }
            
            .login-container {
                position: relative;
                z-index: 10;
                width: 100%;
                max-width: 420px;
            }
            
            .brand {
                text-align: center;
                margin-bottom: 40px;
            }
            
            .brand-logo {
                font-family: 'Space Grotesk', sans-serif;
                font-size: 32px;
                font-weight: 700;
                background: linear-gradient(135deg, var(--aurora) 0%, var(--coral) 100%);
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
                background-clip: text;
                display: inline-flex;
                align-items: center;
                gap: 12px;
                margin-bottom: 12px;
            }
            
            .brand-logo::before {
                content: '◆';
                font-size: 24px;
            }
            
            .brand-tagline {
                color: var(--text-secondary);
                font-size: 15px;
            }
            
            .card {
                background: linear-gradient(145deg, rgba(26, 20, 41, 0.9) 0%, rgba(45, 31, 79, 0.6) 100%);
                backdrop-filter: blur(20px);
                border: 1px solid rgba(124, 58, 237, 0.2);
                border-radius: 24px;
                padding: 48px;
                box-shadow: 
                    0 25px 50px -12px rgba(0, 0, 0, 0.5),
                    0 0 0 1px rgba(124, 58, 237, 0.1),
                    inset 0 1px 0 rgba(255, 255, 255, 0.05);
            }
            
            .card h1 {
                font-family: 'Space Grotesk', sans-serif;
                font-size: 28px;
                font-weight: 700;
                color: var(--text-primary);
                margin-bottom: 8px;
                text-align: center;
            }
            
            .card-subtitle {
                color: var(--text-secondary);
                text-align: center;
                margin-bottom: 32px;
                font-size: 15px;
            }
            
            .form-group {
                margin-bottom: 24px;
                position: relative;
            }
            
            .form-group label {
                display: block;
                margin-bottom: 8px;
                font-weight: 500;
                color: var(--text-secondary);
                font-size: 14px;
                text-transform: uppercase;
                letter-spacing: 0.5px;
            }
            
            .input-wrapper {
                position: relative;
            }
            
            .input-wrapper::before {
                content: '';
                position: absolute;
                inset: -2px;
                background: linear-gradient(135deg, var(--aurora), var(--coral));
                border-radius: 14px;
                opacity: 0;
                transition: opacity 0.3s;
                z-index: -1;
            }
            
            .form-group:focus-within .input-wrapper::before {
                opacity: 0.5;
            }
            
            .form-group input {
                width: 100%;
                padding: 16px 18px;
                background: rgba(13, 13, 18, 0.6);
                border: 1px solid rgba(124, 58, 237, 0.2);
                border-radius: 12px;
                font-size: 16px;
                color: var(--text-primary);
                font-family: 'Inter', sans-serif;
                transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            }
            
            .form-group input::placeholder {
                color: rgba(148, 163, 184, 0.5);
            }
            
            .form-group input:focus {
                outline: none;
                border-color: var(--aurora);
                background: rgba(13, 13, 18, 0.8);
                box-shadow: 0 0 0 4px rgba(124, 58, 237, 0.1);
            }
            
            .btn {
                width: 100%;
                padding: 18px;
                background: linear-gradient(135deg, var(--coral) 0%, var(--pink) 100%);
                color: white;
                border: none;
                border-radius: 14px;
                font-size: 16px;
                font-weight: 600;
                font-family: 'Inter', sans-serif;
                cursor: pointer;
                transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
                position: relative;
                overflow: hidden;
                box-shadow: 0 4px 20px rgba(249, 112, 102, 0.3);
            }
            
            .btn::before {
                content: '';
                position: absolute;
                top: 0;
                left: -100%;
                width: 100%;
                height: 100%;
                background: linear-gradient(90deg, transparent, rgba(255,255,255,0.2), transparent);
                transition: left 0.5s;
            }
            
            .btn:hover {
                transform: translateY(-2px);
                box-shadow: 0 8px 30px rgba(249, 112, 102, 0.4);
            }
            
            .btn:hover::before {
                left: 100%;
            }
            
            .btn:active {
                transform: translateY(0);
            }
            
            .security-note {
                margin-top: 32px;
                padding: 20px;
                background: rgba(251, 191, 36, 0.05);
                border: 1px solid rgba(251, 191, 36, 0.15);
                border-radius: 12px;
                text-align: center;
            }
            
            .security-note-icon {
                font-size: 24px;
                margin-bottom: 8px;
            }
            
            .security-note strong {
                display: block;
                color: var(--solar);
                font-size: 13px;
                text-transform: uppercase;
                letter-spacing: 0.5px;
                margin-bottom: 4px;
            }
            
            .security-note p {
                color: var(--text-secondary);
                font-size: 13px;
            }
            
            .back-link {
                display: block;
                text-align: center;
                margin-top: 24px;
                color: var(--text-secondary);
                text-decoration: none;
                font-size: 14px;
                transition: color 0.3s;
            }
            
            .back-link:hover {
                color: var(--lavender);
            }
            
            @media (max-width: 480px) {
                .card {
                    padding: 32px 24px;
                }
                .brand-logo {
                    font-size: 28px;
                }
            }
        </style>
    </head>
    <body>
        <div class="orb orb-1"></div>
        <div class="orb orb-2"></div>
        <div class="orb orb-3"></div>
        
        <div class="login-container">
            <div class="brand">
                <div class="brand-logo">Nexus</div>
                <div class="brand-tagline">Enterprise Access Portal</div>
            </div>
            
            <div class="card">
                <h1>Welcome Back</h1>
                <p class="card-subtitle">Enter your credentials to continue</p>
                
                <form method="POST">
                    <div class="form-group">
                        <label for="username">Username</label>
                        <div class="input-wrapper">
                            <input type="text" id="username" name="username" placeholder="Enter your username" required autofocus autocomplete="username">
                        </div>
                    </div>
                    <div class="form-group">
                        <label for="password">Password</label>
                        <div class="input-wrapper">
                            <input type="password" id="password" name="password" placeholder="Enter your password" required autocomplete="current-password">
                        </div>
                    </div>
                    <button type="submit" class="btn">Access Portal</button>
                </form>
                
                <div class="security-note">
                    <div class="security-note-icon">🔒</div>
                    <strong>Secure Connection</strong>
                    <p>All access attempts are monitored and logged</p>
                </div>
            </div>
            
            <a href="/" class="back-link">← Return to homepage</a>
        </div>
    </body>
    </html>
    """
    return Response(html, mimetype='text/html')


@app.route('/api', methods=['GET', 'POST', 'PUT', 'DELETE'])
def api():
    """Fake API endpoint"""
    return jsonify({
        'status': 'ok',
        'message': 'API endpoint',
        'timestamp': datetime.now().isoformat()
    })


@app.route('/api/users', methods=['GET', 'POST'])
def api_users():
    """Fake users API"""
    if request.method == 'POST':
        data = request.get_json() or {}
        logger.warning(f"API user creation attempt: {data}")
    
    return jsonify({
        'users': [
            {'id': 1, 'name': 'user1'},
            {'id': 2, 'name': 'user2'}
        ]
    })


@app.route('/api/database', methods=['GET', 'POST'])
def api_database():
    """Fake database API"""
    query = request.args.get('query', '')
    if query:
        logger.warning(f"Database query attempt: {query}")
    
    return jsonify({
        'status': 'ok',
        'results': []
    })


@app.route('/phpmyadmin', methods=['GET', 'POST'])
def phpmyadmin():
    """Fake phpMyAdmin"""
    logger.warning("phpMyAdmin access attempt")
    return Response("404 Not Found", status=404)


@app.route('/wp-admin', methods=['GET', 'POST'])
def wp_admin():
    """Fake WordPress admin"""
    logger.warning("WordPress admin access attempt")
    return Response("404 Not Found", status=404)


@app.route('/.env', methods=['GET'])
def env_file():
    """Fake .env file access"""
    logger.warning(".env file access attempt")
    return Response("404 Not Found", status=404)


@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'])
def catch_all(path):
    """Catch all other routes"""
    logger.info(f"Unknown path accessed: /{path}")
    return Response("404 Not Found", status=404)


def main():
    """Main entry point"""
    port = int(os.getenv('HTTP_PORT', 8080))
    host = '0.0.0.0'
    
    logger.info(f"Starting HTTP Honeypot on {host}:{port}")
    
    # Run Flask in production mode (for container)
    app.run(host=host, port=port, threaded=True, debug=False)


if __name__ == '__main__':
    main()

