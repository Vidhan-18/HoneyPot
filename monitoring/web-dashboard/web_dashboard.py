#!/usr/bin/env python3
"""
Web Dashboard for Honeypot Platform
Provides a web interface to view logs, sessions, IOCs, and statistics.
"""

import os
import json
import logging
from datetime import datetime, timedelta
from pathlib import Path
from flask import Flask, render_template, jsonify, request, send_file, session, redirect, url_for, flash
from flask_socketio import SocketIO, emit
import threading
import time
import secrets

# Setup logging first
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Import with error handling
try:
    from auth import login_required, verify_password, hash_password
except ImportError as e:
    logger.error(f"Failed to import auth module: {e}")
    # Fallback auth functions
    def login_required(f):
        return f
    def verify_password(username, password):
        return username == 'admin' and password == 'honeypot2024'
    def hash_password(password):
        import hashlib
        return hashlib.sha256(password.encode()).hexdigest()

try:
    from geoip_lookup import get_ip_location
except ImportError as e:
    logger.warning(f"GeoIP lookup not available: {e}")
    def get_ip_location(ip):
        return {'country': 'Unknown', 'city': 'Unknown', 'isp': 'Unknown', 'country_code': 'XX'}

try:
    from attack_classifier import classify_attack, get_attack_summary, ATTACK_CATEGORIES
except ImportError as e:
    logger.warning(f"Attack classifier not available: {e}")
    def classify_attack(session):
        return []
    def get_attack_summary(attacks):
        return {'total': 0, 'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'categories': []}
    ATTACK_CATEGORIES = {}

# Set template and static folders
template_dir = Path(__file__).parent / 'templates'
app = Flask(__name__, template_folder=str(template_dir))
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', secrets.token_hex(32))
socketio = SocketIO(app, cors_allowed_origins="*")

# Data directories (mounted from docker-compose volumes)
LOGS_DIR = Path("/logs")
SESSIONS_DIR = Path("/sessions")
IOCS_DIR = Path("/iocs")
PCAPS_DIR = Path("/pcaps")

# Ensure directories exist
for dir_path in [LOGS_DIR, SESSIONS_DIR, IOCS_DIR, PCAPS_DIR]:
    dir_path.mkdir(parents=True, exist_ok=True)


def get_recent_files(directory, extension=".json", limit=50):
    """Get recent files from directory"""
    if not directory.exists():
        return []
    
    files = []
    for file_path in directory.glob(f"*{extension}"):
        try:
            stat = file_path.stat()
            files.append({
                'name': file_path.name,
                'path': str(file_path),
                'size': stat.st_size,
                'modified': datetime.fromtimestamp(stat.st_mtime).isoformat()
            })
        except Exception as e:
            logger.error(f"Error reading file {file_path}: {e}")
    
    # Sort by modification time, newest first
    files.sort(key=lambda x: x['modified'], reverse=True)
    return files[:limit]


def read_json_file(file_path):
    """Read and parse JSON file"""
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"Error reading JSON file {file_path}: {e}")
        return None


def get_statistics():
    """Calculate platform statistics"""
    stats = {
        'total_sessions': 0,
        'total_iocs': 0,
        'total_pcaps': 0,
        'recent_activity': 0,
        'services': {
            'ssh': 0,
            'http': 0,
            'db': 0,
            'smb_ftp': 0
        }
    }
    
    # Count sessions
    if SESSIONS_DIR.exists():
        stats['total_sessions'] = len(list(SESSIONS_DIR.glob("*.json")))
        for session_file in SESSIONS_DIR.glob("*.json"):
            session = read_json_file(session_file)
            if session:
                protocol = session.get('protocol', '')
                if 'ssh' in session_file.name.lower():
                    stats['services']['ssh'] += 1
                elif 'http' in session_file.name.lower():
                    stats['services']['http'] += 1
                elif 'postgres' in session_file.name.lower() or 'mysql' in session_file.name.lower():
                    stats['services']['db'] += 1
                elif 'smb' in session_file.name.lower() or 'ftp' in session_file.name.lower():
                    stats['services']['smb_ftp'] += 1
    
    # Count IOCs
    if IOCS_DIR.exists():
        stats['total_iocs'] = len(list(IOCS_DIR.glob("*.json")))
    
    # Count PCAPs
    if PCAPS_DIR.exists():
        stats['total_pcaps'] = len(list(PCAPS_DIR.glob("*.pcap")))
    
    # Count recent activity (last hour)
    one_hour_ago = datetime.now() - timedelta(hours=1)
    if SESSIONS_DIR.exists():
        for session_file in SESSIONS_DIR.glob("*.json"):
            try:
                if datetime.fromtimestamp(session_file.stat().st_mtime) > one_hour_ago:
                    stats['recent_activity'] += 1
            except:
                pass
    
    return stats


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page"""
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        
        if verify_password(username, password):
            session['logged_in'] = True
            session['username'] = username
            logger.info(f"User {username} logged in from {request.remote_addr}")
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password', 'error')
            logger.warning(f"Failed login attempt from {request.remote_addr}")
    
    # If already logged in, redirect to dashboard
    if session.get('logged_in'):
        return redirect(url_for('index'))
    
    return render_template('login.html')


@app.route('/logout')
def logout():
    """Logout"""
    username = session.get('username', 'Unknown')
    session.clear()
    logger.info(f"User {username} logged out")
    flash('You have been logged out', 'info')
    return redirect(url_for('login'))


@app.route('/')
@login_required
def index():
    """Main dashboard page"""
    return render_template('dashboard.html')


@app.route('/attackers')
@login_required
def attackers():
    """Attacker tracking page"""
    return render_template('attackers.html')


@app.route('/api/stats')
@login_required
def api_stats():
    """Get platform statistics"""
    return jsonify(get_statistics())


@app.route('/api/sessions')
@login_required
def api_sessions():
    """Get list of sessions with attack classification and location"""
    try:
        limit = int(request.args.get('limit', 50))
        sessions = []
        
        if SESSIONS_DIR.exists():
            for session_file in sorted(SESSIONS_DIR.glob("*.json"), key=lambda x: x.stat().st_mtime, reverse=True)[:limit]:
                session = read_json_file(session_file)
                if session:
                    session['file'] = session_file.name
                    
                    # Add location info
                    client_ip = session.get('client_ip', '')
                    if client_ip:
                        try:
                            location = get_ip_location(client_ip)
                            session['location'] = location
                        except Exception as e:
                            logger.warning(f"Failed to get location for {client_ip}: {e}")
                            session['location'] = {'country': 'Unknown', 'city': 'Unknown', 'isp': 'Unknown'}
                    
                    # Classify attacks
                    try:
                        attacks = classify_attack(session)
                        session['attacks'] = attacks
                        session['attack_summary'] = get_attack_summary(attacks)
                    except Exception as e:
                        logger.warning(f"Failed to classify attacks: {e}")
                        session['attacks'] = []
                        session['attack_summary'] = {'total': 0, 'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
                    
                    sessions.append(session)
        
        return jsonify(sessions)
    except Exception as e:
        logger.error(f"Error in api_sessions: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/session/<filename>')
@login_required
def api_session(filename):
    """Get specific session details with location and attack classification"""
    session_file = SESSIONS_DIR / filename
    if not session_file.exists():
        return jsonify({'error': 'Session not found'}), 404
    
    session = read_json_file(session_file)
    if not session:
        return jsonify({'error': 'Failed to read session'}), 500
    
    # Add location info
    client_ip = session.get('client_ip', '')
    if client_ip:
        location = get_ip_location(client_ip)
        session['location'] = location
    
    # Classify attacks
    attacks = classify_attack(session)
    session['attacks'] = attacks
    session['attack_summary'] = get_attack_summary(attacks)
    
    return jsonify(session)


@app.route('/api/iocs')
@login_required
def api_iocs():
    """Get list of detected IOCs"""
    limit = int(request.args.get('limit', 50))
    iocs = []
    
    if IOCS_DIR.exists():
        for ioc_file in sorted(IOCS_DIR.glob("*.json"), key=lambda x: x.stat().st_mtime, reverse=True)[:limit]:
            ioc = read_json_file(ioc_file)
            if ioc:
                ioc['file'] = ioc_file.name
                iocs.append(ioc)
    
    return jsonify(iocs)


@app.route('/api/ioc/<filename>')
@login_required
def api_ioc(filename):
    """Get specific IOC details"""
    ioc_file = IOCS_DIR / filename
    if not ioc_file.exists():
        return jsonify({'error': 'IOC not found'}), 404
    
    ioc = read_json_file(ioc_file)
    if not ioc:
        return jsonify({'error': 'Failed to read IOC'}), 500
    
    return jsonify(ioc)


@app.route('/api/logs')
@login_required
def api_logs():
    """Get recent logs"""
    limit = int(request.args.get('limit', 100))
    service = request.args.get('service', '')
    
    logs = []
    log_file = LOGS_DIR / "aggregated.log"
    
    if log_file.exists():
        try:
            with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
                for line in lines[-limit:]:
                    line = line.strip()
                    if not line:
                        continue
                    
                    try:
                        log_entry = json.loads(line)
                        if service and service.lower() not in log_entry.get('source', '').lower():
                            continue
                        logs.append(log_entry)
                    except:
                        # If not JSON, treat as plain text
                        logs.append({'message': line, 'timestamp': datetime.now().isoformat()})
        except Exception as e:
            logger.error(f"Error reading logs: {e}")
    
    return jsonify(logs[-limit:])


@app.route('/api/pcaps')
@login_required
def api_pcaps():
    """Get list of packet captures"""
    pcaps = get_recent_files(PCAPS_DIR, ".pcap", 20)
    return jsonify(pcaps)


@app.route('/api/services')
@login_required
def api_services():
    """Get service status"""
    # This would ideally check Docker container status
    # For now, return basic info
    services = {
        'ssh-honeypot': {'status': 'running', 'port': 2222},
        'http-honeypot': {'status': 'running', 'port': 8080},
        'db-api-honeypot': {'status': 'running', 'ports': [5432, 3306]},
        'smb-ftp-honeypot': {'status': 'running', 'ports': [445, 21, 139]},
        'packet-capture': {'status': 'running'},
        'log-aggregator': {'status': 'running'},
        'ioc-detector': {'status': 'running'},
    }
    return jsonify(services)


@app.route('/api/attack-categories')
@login_required
def api_attack_categories():
    """Get all attack categories"""
    return jsonify(ATTACK_CATEGORIES)


@app.route('/api/attackers-summary')
@login_required
def api_attackers_summary():
    """Get summary of all attackers with location and attack types"""
    try:
        if not SESSIONS_DIR.exists():
            return jsonify([])
        
        attackers = {}
        
        for session_file in SESSIONS_DIR.glob("*.json"):
            try:
                session = read_json_file(session_file)
                if not session:
                    continue
                
                client_ip = session.get('client_ip', 'Unknown')
                if client_ip == 'Unknown' or not client_ip:
                    continue
                
                if client_ip not in attackers:
                    try:
                        location = get_ip_location(client_ip)
                    except:
                        location = {'country': 'Unknown', 'city': 'Unknown', 'isp': 'Unknown'}
                    
                    attackers[client_ip] = {
                        'ip': client_ip,
                        'location': location,
                        'sessions': [],
                        'total_attacks': 0,
                        'attack_categories': set(),
                        'severity_counts': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
                    }
                
                # Classify attacks
                try:
                    attacks = classify_attack(session)
                except:
                    attacks = []
                
                attackers[client_ip]['total_attacks'] += len(attacks)
                
                for attack in attacks:
                    if isinstance(attack, dict):
                        cat = attack.get('category', 'unknown')
                        attackers[client_ip]['attack_categories'].add(cat)
                        severity = attack.get('severity', 'medium')
                        attackers[client_ip]['severity_counts'][severity] = attackers[client_ip]['severity_counts'].get(severity, 0) + 1
                
                attackers[client_ip]['sessions'].append({
                    'session_id': session.get('session_id', ''),
                    'protocol': session.get('protocol', ''),
                    'start_time': session.get('start_time', ''),
                    'attacks': attacks
                })
            except Exception as e:
                logger.warning(f"Error processing session {session_file}: {e}")
                continue
        
        # Convert sets to lists for JSON
        result = []
        for ip, data in attackers.items():
            data['attack_categories'] = list(data['attack_categories'])
            result.append(data)
        
        # Sort by total attacks (most dangerous first)
        result.sort(key=lambda x: x['total_attacks'], reverse=True)
        
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in api_attackers_summary: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/country/<country_code>')
@login_required
def api_country_data(country_code):
    """Get detailed cybersecurity data for a specific country"""
    try:
        time_range = request.args.get('timeRange', '24h')
        attack_type = request.args.get('attackType', 'all')
        
        # Calculate time threshold based on range
        now = datetime.now()
        if time_range == '1h':
            threshold = now - timedelta(hours=1)
        elif time_range == '7d':
            threshold = now - timedelta(days=7)
        elif time_range == '30d':
            threshold = now - timedelta(days=30)
        else:  # 24h default
            threshold = now - timedelta(days=1)
        
        # Collect sessions for this country
        country_sessions = []
        unique_ips = set()
        attack_types = {}
        
        if SESSIONS_DIR.exists():
            for session_file in SESSIONS_DIR.glob("*.json"):
                try:
                    session = read_json_file(session_file)
                    if not session:
                        continue
                    
                    location = session.get('location', {})
                    session_country = location.get('country_code', '') or location.get('country', '')
                    
                    if session_country.upper() != country_code.upper():
                        continue
                    
                    # Check time range
                    start_time = session.get('start_time', '')
                    if start_time:
                        try:
                            session_time = datetime.fromisoformat(start_time.replace('Z', '+00:00'))
                            if session_time < threshold:
                                continue
                        except:
                            pass
                    
                    # Classify attacks
                    attacks = classify_attack(session)
                    
                    # Filter by attack type if specified
                    if attack_type != 'all':
                        attacks = [a for a in attacks if attack_type.lower() in (a.get('category', '') + a.get('name', '')).lower()]
                    
                    country_sessions.append({
                        'session_id': session.get('session_id', ''),
                        'client_ip': session.get('client_ip', 'Unknown'),
                        'start_time': start_time,
                        'attacks': attacks,
                        'commands': session.get('commands', [])
                    })
                    
                    unique_ips.add(session.get('client_ip', 'Unknown'))
                    
                    for attack in attacks:
                        attack_cat = attack.get('category', attack.get('name', 'Unknown'))
                        attack_types[attack_cat] = attack_types.get(attack_cat, 0) + 1
                        
                except Exception as e:
                    logger.warning(f"Error processing session {session_file}: {e}")
                    continue
        
        # Calculate threat level
        total_attacks = sum(attack_types.values())
        if total_attacks > 100:
            threat_level = 'high'
        elif total_attacks > 20:
            threat_level = 'medium'
        else:
            threat_level = 'low'
        
        # Build response
        response = {
            'country': country_code,
            'countryName': get_country_name(country_code),
            'totalAttacks': total_attacks,
            'uniqueIPs': len(unique_ips),
            'threatLevel': threat_level,
            'attackTypes': attack_types,
            'logs': [
                {
                    'timestamp': s['start_time'],
                    'ip': s['client_ip'],
                    'type': (s['attacks'][0].get('category', s['attacks'][0].get('name', 'Unknown')) if s['attacks'] else 'Reconnaissance')
                }
                for s in sorted(country_sessions, key=lambda x: x['start_time'] or '', reverse=True)[:50]
            ]
        }
        
        return jsonify(response)
        
    except Exception as e:
        logger.error(f"Error in api_country_data: {e}")
        return jsonify({'error': str(e)}), 500


def get_country_name(country_code):
    """Convert country code to country name"""
    country_names = {
        'US': 'United States', 'CN': 'China', 'RU': 'Russia', 'DE': 'Germany',
        'GB': 'United Kingdom', 'FR': 'France', 'IN': 'India', 'JP': 'Japan',
        'BR': 'Brazil', 'CA': 'Canada', 'AU': 'Australia', 'KR': 'South Korea',
        'NL': 'Netherlands', 'IT': 'Italy', 'ES': 'Spain', 'TR': 'Turkey',
        'PL': 'Poland', 'UA': 'Ukraine', 'VN': 'Vietnam', 'TW': 'Taiwan',
        'ID': 'Indonesia', 'TH': 'Thailand', 'SG': 'Singapore', 'SE': 'Sweden',
        'CH': 'Switzerland', 'BE': 'Belgium', 'AT': 'Austria', 'CZ': 'Czech Republic',
        'RO': 'Romania', 'HU': 'Hungary', 'DK': 'Denmark', 'FI': 'Finland',
        'NO': 'Norway', 'IE': 'Ireland', 'PT': 'Portugal', 'GR': 'Greece',
        'IL': 'Israel', 'SA': 'Saudi Arabia', 'AE': 'UAE', 'ZA': 'South Africa',
        'EG': 'Egypt', 'NG': 'Nigeria', 'KE': 'Kenya', 'MX': 'Mexico',
        'AR': 'Argentina', 'CL': 'Chile', 'CO': 'Colombia', 'PE': 'Peru',
        'BD': 'Bangladesh', 'MY': 'Malaysia', 'PH': 'Philippines', 'PK': 'Pakistan',
        'IR': 'Iran', 'IQ': 'Iraq', 'KZ': 'Kazakhstan', 'UZ': 'Uzbekistan'
    }
    return country_names.get(country_code.upper(), country_code)


def background_thread():
    """Background thread to emit statistics updates"""
    while True:
        time.sleep(5)  # Update every 5 seconds
        try:
            stats = get_statistics()
            socketio.emit('stats_update', stats)
        except Exception as e:
            logger.error(f"Error in background thread: {e}")


@socketio.on('connect')
def handle_connect():
    """Handle client connection"""
    logger.info('Client connected')
    emit('stats_update', get_statistics())


@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection"""
    logger.info('Client disconnected')


def main():
    """Main entry point"""
    port = int(os.getenv('DASHBOARD_PORT', 5000))
    host = '0.0.0.0'
    
    # Start background thread
    thread = threading.Thread(target=background_thread, daemon=True)
    thread.start()
    
    logger.info(f"Starting Web Dashboard on {host}:{port}")
    socketio.run(app, host=host, port=port, debug=False, allow_unsafe_werkzeug=True, use_reloader=False)


if __name__ == '__main__':
    main()

