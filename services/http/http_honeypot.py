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
from flask import Flask, request, Response, jsonify
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


def detect_web_attack_indicators():
    """
    Detect common web attack patterns in query params, body, and headers.
    Only logs indicators — never executes anything.
    """
    indicators = []
    payload_sources = []

    qs = request.query_string.decode("utf-8", errors="ignore")
    body = request.get_data(as_text=True)
    combined = f"{qs} {body}".lower()

    if any(x in combined for x in ["' or 1=1", "\" or 1=1", "union select", "information_schema"]):
        indicators.append("sql_injection")

    if any(x in combined for x in ["<script", "javascript:", "onerror=", "onload="]):
        indicators.append("xss")

    if "../" in combined or "..%2f" in combined:
        indicators.append("path_traversal")

    if any(x in combined for x in [";cat ", ";ls ", "|bash", "|sh", "`"]):
        indicators.append("command_injection")

    if indicators:
        logger.warning(f"Web attack indicators detected from {request.remote_addr}: {indicators}")

    return indicators


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
    """Log all requests and detect attacks"""
    log_request(request)
    detect_web_attack_indicators()


@app.route('/', methods=['GET', 'POST'])
def index():
    """Main page"""
    html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Corporate Portal - Welcome</title>
        <style>
            * { margin: 0; padding: 0; box-sizing: border-box; }
            body {
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh;
                color: #333;
            }
            .navbar {
                background: rgba(255, 255, 255, 0.95);
                padding: 15px 30px;
                box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                display: flex;
                justify-content: space-between;
                align-items: center;
            }
            .navbar-brand {
                font-size: 24px;
                font-weight: bold;
                color: #667eea;
                text-decoration: none;
            }
            .navbar-nav {
                display: flex;
                gap: 20px;
                list-style: none;
            }
            .navbar-nav a {
                color: #333;
                text-decoration: none;
                font-weight: 500;
            }
            .navbar-nav a:hover { color: #667eea; }
            .hero {
                text-align: center;
                padding: 80px 20px;
                color: white;
            }
            .hero h1 {
                font-size: 48px;
                margin-bottom: 20px;
            }
            .hero p {
                font-size: 20px;
                margin-bottom: 30px;
                opacity: 0.9;
            }
            .btn {
                display: inline-block;
                padding: 15px 40px;
                background: white;
                color: #667eea;
                text-decoration: none;
                border-radius: 8px;
                font-weight: 600;
                margin: 10px;
                transition: all 0.3s;
            }
            .btn:hover {
                transform: translateY(-2px);
                box-shadow: 0 10px 20px rgba(0,0,0,0.2);
            }
            .features {
                max-width: 1200px;
                margin: 0 auto;
                padding: 60px 20px;
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
                gap: 30px;
            }
            .feature-card {
                background: white;
                padding: 30px;
                border-radius: 15px;
                box-shadow: 0 10px 30px rgba(0,0,0,0.1);
            }
            .feature-card h3 {
                color: #667eea;
                margin-bottom: 15px;
            }
            .footer {
                text-align: center;
                padding: 30px;
                color: rgba(255, 255, 255, 0.8);
            }
        </style>
    </head>
    <body>
        <nav class="navbar">
            <a href="/" class="navbar-brand">🏢 Corporate Portal</a>
            <ul class="navbar-nav">
                <li><a href="/">Home</a></li>
                <li><a href="/login">Login</a></li>
                <li><a href="/admin">Admin</a></li>
                <li><a href="/api">API</a></li>
            </ul>
        </nav>
        
        <div class="hero">
            <h1>Welcome to Corporate Portal</h1>
            <p>Your trusted business management platform</p>
            <a href="/login" class="btn">Get Started</a>
            <a href="/admin" class="btn">Admin Access</a>
        </div>
        
        <div class="features">
            <div class="feature-card">
                <h3>🔐 Secure Access</h3>
                <p>Enterprise-grade security for your business data and applications.</p>
            </div>
            <div class="feature-card">
                <h3>📊 Analytics</h3>
                <p>Real-time insights and comprehensive reporting tools.</p>
            </div>
            <div class="feature-card">
                <h3>⚡ Performance</h3>
                <p>Lightning-fast response times and reliable uptime.</p>
            </div>
        </div>
        
        <div class="footer">
            <p>&copy; 2024 Corporate Portal. All rights reserved.</p>
        </div>
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
            <title>Admin Panel - Access Denied</title>
            <style>
                * { margin: 0; padding: 0; box-sizing: border-box; }
                body {
                    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    min-height: 100vh;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    padding: 20px;
                }
                .card {
                    background: white;
                    padding: 40px;
                    border-radius: 15px;
                    box-shadow: 0 20px 60px rgba(0,0,0,0.3);
                    max-width: 500px;
                    width: 100%;
                    text-align: center;
                }
                .alert {
                    background: #fee;
                    color: #c33;
                    padding: 15px;
                    border-radius: 8px;
                    margin-bottom: 20px;
                    border: 1px solid #fcc;
                }
                .btn {
                    display: inline-block;
                    padding: 12px 30px;
                    background: #667eea;
                    color: white;
                    text-decoration: none;
                    border-radius: 8px;
                    margin-top: 20px;
                }
            </style>
        </head>
        <body>
            <div class="card">
                <h1 style="color: #667eea; margin-bottom: 20px;">🔒 Admin Panel</h1>
                <div class="alert">Invalid credentials. Access denied.</div>
                <p>Please contact your system administrator.</p>
                <a href="/admin" class="btn">Try Again</a>
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
        <title>Admin Panel - Corporate Portal</title>
        <style>
            * { margin: 0; padding: 0; box-sizing: border-box; }
            body {
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh;
                display: flex;
                align-items: center;
                justify-content: center;
                padding: 20px;
            }
            .navbar {
                position: fixed;
                top: 0;
                left: 0;
                right: 0;
                background: rgba(255, 255, 255, 0.95);
                padding: 15px 30px;
                box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            }
            .navbar-brand {
                font-size: 24px;
                font-weight: bold;
                color: #667eea;
                text-decoration: none;
            }
            .card {
                background: white;
                padding: 40px;
                border-radius: 15px;
                box-shadow: 0 20px 60px rgba(0,0,0,0.3);
                max-width: 450px;
                width: 100%;
                margin-top: 80px;
            }
            .card h1 {
                color: #667eea;
                margin-bottom: 10px;
                text-align: center;
            }
            .card p {
                color: #666;
                text-align: center;
                margin-bottom: 30px;
            }
            .form-group {
                margin-bottom: 20px;
            }
            .form-group label {
                display: block;
                margin-bottom: 8px;
                font-weight: 500;
                color: #333;
            }
            .form-group input {
                width: 100%;
                padding: 12px 15px;
                border: 2px solid #e0e0e0;
                border-radius: 8px;
                font-size: 16px;
                transition: all 0.3s;
            }
            .form-group input:focus {
                outline: none;
                border-color: #667eea;
                box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
            }
            .btn {
                width: 100%;
                padding: 14px;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white;
                border: none;
                border-radius: 8px;
                font-size: 16px;
                font-weight: 600;
                cursor: pointer;
                transition: all 0.3s;
            }
            .btn:hover {
                transform: translateY(-2px);
                box-shadow: 0 5px 15px rgba(102, 126, 234, 0.4);
            }
        </style>
    </head>
    <body>
        <nav class="navbar">
            <a href="/" class="navbar-brand">🏢 Corporate Portal</a>
        </nav>
        <div class="card">
            <h1>🔒 Admin Panel</h1>
            <p>Administrator Access Required</p>
            <form method="POST">
                <div class="form-group">
                    <label for="username">Username</label>
                    <input type="text" id="username" name="username" required autofocus>
                </div>
                <div class="form-group">
                    <label for="password">Password</label>
                    <input type="password" id="password" name="password" required>
                </div>
                <button type="submit" class="btn">Login</button>
            </form>
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
            <title>Login - Corporate Portal</title>
            <style>
                * { margin: 0; padding: 0; box-sizing: border-box; }
                body {
                    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    min-height: 100vh;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    padding: 20px;
                }
                .card {
                    background: white;
                    padding: 40px;
                    border-radius: 15px;
                    box-shadow: 0 20px 60px rgba(0,0,0,0.3);
                    max-width: 450px;
                    width: 100%;
                }
                .card h1 {
                    color: #667eea;
                    margin-bottom: 10px;
                    text-align: center;
                }
                .alert {
                    background: #fee;
                    color: #c33;
                    padding: 15px;
                    border-radius: 8px;
                    margin-bottom: 20px;
                    border: 1px solid #fcc;
                }
                .form-group {
                    margin-bottom: 20px;
                }
                .form-group label {
                    display: block;
                    margin-bottom: 8px;
                    font-weight: 500;
                    color: #333;
                }
                .form-group input {
                    width: 100%;
                    padding: 12px 15px;
                    border: 2px solid #e0e0e0;
                    border-radius: 8px;
                    font-size: 16px;
                    transition: all 0.3s;
                }
                .form-group input:focus {
                    outline: none;
                    border-color: #667eea;
                    box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
                }
                .btn {
                    width: 100%;
                    padding: 14px;
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white;
                    border: none;
                    border-radius: 8px;
                    font-size: 16px;
                    font-weight: 600;
                    cursor: pointer;
                    transition: all 0.3s;
                }
                .btn:hover {
                    transform: translateY(-2px);
                    box-shadow: 0 5px 15px rgba(102, 126, 234, 0.4);
                }
            </style>
        </head>
        <body>
            <div class="card">
                <h1>🔐 Login</h1>
                <div class="alert">Invalid username or password. Please try again.</div>
                <form method="POST">
                    <div class="form-group">
                        <label for="username">Username</label>
                        <input type="text" id="username" name="username" required autofocus>
                    </div>
                    <div class="form-group">
                        <label for="password">Password</label>
                        <input type="password" id="password" name="password" required>
                    </div>
                    <button type="submit" class="btn">Login</button>
                </form>
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
        <title>Login - Corporate Portal</title>
        <style>
            * { margin: 0; padding: 0; box-sizing: border-box; }
            body {
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh;
                display: flex;
                align-items: center;
                justify-content: center;
                padding: 20px;
            }
            .navbar {
                position: fixed;
                top: 0;
                left: 0;
                right: 0;
                background: rgba(255, 255, 255, 0.95);
                padding: 15px 30px;
                box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            }
            .navbar-brand {
                font-size: 24px;
                font-weight: bold;
                color: #667eea;
                text-decoration: none;
            }
            .card {
                background: white;
                padding: 40px;
                border-radius: 15px;
                box-shadow: 0 20px 60px rgba(0,0,0,0.3);
                max-width: 450px;
                width: 100%;
                margin-top: 80px;
            }
            .card h1 {
                color: #667eea;
                margin-bottom: 10px;
                text-align: center;
            }
            .card p {
                color: #666;
                text-align: center;
                margin-bottom: 30px;
            }
            .form-group {
                margin-bottom: 20px;
            }
            .form-group label {
                display: block;
                margin-bottom: 8px;
                font-weight: 500;
                color: #333;
            }
            .form-group input {
                width: 100%;
                padding: 12px 15px;
                border: 2px solid #e0e0e0;
                border-radius: 8px;
                font-size: 16px;
                transition: all 0.3s;
            }
            .form-group input:focus {
                outline: none;
                border-color: #667eea;
                box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
            }
            .btn {
                width: 100%;
                padding: 14px;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white;
                border: none;
                border-radius: 8px;
                font-size: 16px;
                font-weight: 600;
                cursor: pointer;
                transition: all 0.3s;
            }
            .btn:hover {
                transform: translateY(-2px);
                box-shadow: 0 5px 15px rgba(102, 126, 234, 0.4);
            }
        </style>
    </head>
    <body>
        <nav class="navbar">
            <a href="/" class="navbar-brand">🏢 Corporate Portal</a>
        </nav>
        <div class="card">
            <h1>🔐 Login</h1>
            <p>Sign in to access your account</p>
            <form method="POST">
                <div class="form-group">
                    <label for="username">Username</label>
                    <input type="text" id="username" name="username" required autofocus>
                </div>
                <div class="form-group">
                    <label for="password">Password</label>
                    <input type="password" id="password" name="password" required>
                </div>
                <button type="submit" class="btn">Login</button>
            </form>
        </div>
    </body>
    </html>
    """
    return Response(html, mimetype='text/html')


@app.route('/search', methods=['GET'])
def search():
    """Simulated search endpoint"""
    q = request.args.get("q", "")
    logger.warning(f"Search query received: {q}")

    return jsonify({
        "query": q,
        "results": [
            {"id": 101, "name": "Enterprise Server"},
            {"id": 102, "name": "Cloud Platform"},
            {"id": 103, "name": "Security Gateway"}
        ]
    })


@app.route('/product', methods=['GET'])
def product():
    """Simulated product page"""
    pid = request.args.get("id", "0")
    logger.warning(f"Product lookup: id={pid}")

    return jsonify({
        "product_id": pid,
        "name": "Enterprise Appliance",
        "price": "$4999",
        "status": "available"
    })


@app.route('/api/user', methods=['GET'])
def api_user():
    """Simulated user API"""
    uid = request.args.get("id", "0")
    logger.warning(f"API user lookup id={uid}")

    return jsonify({
        "id": uid,
        "username": "user"+uid,
        "role": "user",
        "status": "active"
    })


@app.route('/upload', methods=['POST'])
def upload():
    """Simulated file upload endpoint"""
    file = request.files.get("file")
    filename = file.filename if file else "none"

    logger.warning(f"File upload attempt: {filename}")

    return jsonify({
        "status": "received",
        "filename": filename,
        "message": "File queued for processing"
    })


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


@app.route('/test-input', methods=['GET', 'POST'])
def test_input():
    """
    Controlled test endpoint with a parameter attackers can target.
    All input is logged and safely reflected back for analysis.
    """
    user_input = ""
    if request.method == 'POST':
        user_input = request.form.get('input', '')
        logger.warning(f"Test input received on /test-input: {user_input}")
    html = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Test Input - Corporate Portal</title>
        <style>
            * {{ margin: 0; padding: 0; box-sizing: border-box; }}
            body {{
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh;
                display: flex;
                align-items: center;
                justify-content: center;
                padding: 20px;
            }}
            .card {{
                background: white;
                padding: 40px;
                border-radius: 15px;
                box-shadow: 0 20px 60px rgba(0,0,0,0.3);
                max-width: 600px;
                width: 100%;
            }}
            .card h1 {{
                color: #667eea;
                margin-bottom: 10px;
                text-align: center;
            }}
            .card p {{
                color: #666;
                text-align: center;
                margin-bottom: 20px;
            }}
            form {{
                margin-top: 10px;
            }}
            input[type="text"] {{
                width: 100%;
                padding: 12px 15px;
                border: 2px solid #e0e0e0;
                border-radius: 8px;
                font-size: 16px;
                margin-bottom: 15px;
            }}
            input[type="text"]:focus {{
                outline: none;
                border-color: #667eea;
                box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
            }}
            button {{
                width: 100%;
                padding: 12px;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white;
                border: none;
                border-radius: 8px;
                font-size: 16px;
                font-weight: 600;
                cursor: pointer;
            }}
            .output {{
                margin-top: 20px;
                padding: 10px;
                background: #f3f4f6;
                border-radius: 8px;
                font-family: 'Courier New', monospace;
                font-size: 13px;
                color: #374151;
                word-break: break-all;
            }}
        </style>
    </head>
    <body>
        <div class="card">
            <h1>Test Input Endpoint</h1>
            <p>Submit any payload here. It will be logged for analysis.</p>
            <form method="POST">
                <input type="text" name="input" placeholder="Enter payload or test string" required>
                <button type="submit">Submit</button>
            </form>
            <div class="output">
                <strong>Last submitted value (safely echoed):</strong><br>
                {json.dumps(user_input)}
            </div>
        </div>
    </body>
    </html>
    """
    return Response(html, mimetype="text/html")


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

