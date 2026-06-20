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
from flask import Flask, render_template, jsonify, request, session, redirect, url_for, flash
import secrets

from data_store import get_store, LOGS_DIR, SESSIONS_DIR, IOCS_DIR, PCAPS_DIR, use_supabase

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
        return False
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

def _enable_mock_api() -> bool:
    if os.getenv("ENABLE_MOCK_API", "").lower() == "true":
        return True
    if is_production():
        return False
    return os.getenv("FLASK_ENV", "").lower() == "development"


def is_production() -> bool:
    return (
        os.getenv("VERCEL") == "1"
        or os.getenv("ENVIRONMENT", "").lower() == "production"
    )


if _enable_mock_api():
    from mock_api import mock_api

    app.register_blueprint(mock_api)
    logger.info("Mock API enabled (development only)")

# Local filesystem dirs (Docker); Supabase used when env vars set
if not use_supabase():
    for dir_path in [LOGS_DIR, SESSIONS_DIR, IOCS_DIR, PCAPS_DIR]:
        try:
            dir_path.mkdir(parents=True, exist_ok=True)
        except OSError as e:
            logger.warning(f"Could not create directory {dir_path}: {e}")


@app.context_processor
def inject_public_config():
    return {
        "supabase_url": os.getenv("SUPABASE_URL", ""),
        "supabase_anon_key": os.getenv("SUPABASE_ANON_KEY", ""),
        "use_supabase_realtime": os.getenv("USE_SUPABASE_REALTIME", "true").lower()
        == "true",
        "data_backend": "supabase" if use_supabase() else "filesystem",
    }


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
    return get_store().get_statistics()


def enrich_session(session: dict) -> dict:
    """Add geolocation and attack classification to a session dict."""
    client_ip = session.get("client_ip", "")
    if (client_ip and (not session.get("location") or session.get("location", {}).get("country") == "Unknown")):
        try:
            session["location"] = get_ip_location(client_ip)
        except Exception as e:
            logger.warning(f"Failed to get location for {client_ip}: {e}")
            session["location"] = {
                "country": "Unknown",
                "city": "Unknown",
                "isp": "Unknown",
            }
    try:
        attacks = classify_attack(session)
        session["attacks"] = attacks
        session["attack_summary"] = get_attack_summary(attacks)
    except Exception as e:
        logger.warning(f"Failed to classify attacks: {e}")
        session["attacks"] = []
        session["attack_summary"] = {
            "total": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
        }
    return session


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page - uses new modern design"""
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
    
    # Use new modern login template
    return render_template('login_new.html')


@app.route('/login-classic', methods=['GET', 'POST'])
def login_classic():
    """Classic login page (original design)"""
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        
        if verify_password(username, password):
            session['logged_in'] = True
            session['username'] = username
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password', 'error')
    
    if session.get('logged_in'):
        return redirect(url_for('index'))
    
    return render_template('login.html')


@app.route('/login-demo', methods=['GET'])
def login_demo():
    """Demo/Simulation login page for testing"""
    return render_template('login_simulation.html')


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


@app.route('/map-test')
def map_test():
    """Test page for threat map"""
    return render_template('map_test.html')


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
        store = get_store()
        sessions = [enrich_session(s) for s in store.list_sessions(limit)]
        return jsonify(sessions)
    except Exception as e:
        logger.error(f"Error in api_sessions: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/session/<filename>')
@login_required
def api_session(filename):
    """Get specific session details with location and attack classification"""
    sess = get_store().get_session(filename)
    if not sess:
        return jsonify({'error': 'Session not found'}), 404
    return jsonify(enrich_session(sess))


@app.route('/api/threat-map')
@app.route('/api/threats')
def api_threat_map():
    """Get threat data for map visualization - uses real session data with geolocation"""
    threats = []
    seen_ips = set()
    store = get_store()

    for session in store.iter_sessions_for_map(500):
        session = enrich_session(session)
        client_ip = session.get('client_ip', '')
        session_id = session.get('_id') or session.get('file', '')

        if client_ip.startswith(
            (
                '192.168.', '10.', '172.16.', '172.17.', '172.18.', '172.19.',
                '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.',
                '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.',
                '127.', 'localhost', '::1',
            )
        ):
            continue

        location = session.get('location')
        if not location:
            try:
                location = get_ip_location(client_ip)
            except Exception:
                location = {
                    'country': 'Unknown', 'country_code': 'XX', 'city': 'Unknown',
                    'lat': 0, 'lon': 0, 'isp': 'Unknown',
                }

        lat = location.get('lat', 0)
        lon = location.get('lon', 0)
        if not lat or not lon or lat == 0.0001 or lon == 0.0001:
            continue

        attacks = session.get('attacks', [])
        attack_summary = session.get('attack_summary', {})
        service = session.get('service', session.get('type', 'unknown'))
        method = session.get('method', '')
        path = session.get('path', '')

        attack_type = 'unknown'
        severity = 'low'
        if attacks:
            attack_type = attacks[0] if isinstance(attacks, list) else str(attacks)
        elif path:
            if '/admin' in path or '/login' in path or '/wp-' in path or '/phpmyadmin' in path:
                attack_type = 'brute_force'
                severity = 'high'
            elif 'SELECT' in str(session.get('data', '')).upper() or 'UNION' in str(session.get('data', '')).upper():
                attack_type = 'sql_injection'
                severity = 'critical'
            elif '<' in str(session.get('data', '')) and '>' in str(session.get('data', '')):
                attack_type = 'xss'
                severity = 'medium'

        if client_ip not in seen_ips:
            seen_ips.add(client_ip)
            attempts = 1
        else:
            continue

        threats.append({
            'id': session_id,
            'ip': client_ip,
            'lat': lat,
            'lng': lon,
            'country': location.get('country_code', 'XX'),
            'country_name': location.get('country', 'Unknown'),
            'city': location.get('city', 'Unknown'),
            'service': service,
            'attack_type': attack_type,
            'severity': severity,
            'timestamp': session.get('timestamp', session.get('start_time', '')),
            'target': f"{method} {path}" if method else path,
            'attempts': attempts + attack_summary.get('total', 0),
        })
    
    # Sort by timestamp (newest first)
    threats.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
    
    return jsonify({
        'status': 'success',
        'count': len(threats),
        'threats': threats[:100],
        'generated_at': datetime.utcnow().isoformat()
    })


@app.route('/api/block-ip', methods=['POST'])
def api_block_ip():
    """Block an IP address"""
    data = request.get_json()
    ip = data.get('ip', '')
    
    if not ip:
        return jsonify({'error': 'IP required'}), 400
    
    store = get_store()
    blocked = store.add_blocked_ip(ip, data.get('reason', 'manual_block'))
    return jsonify({'status': 'success', 'blocked_ips': [b['ip'] for b in blocked]})


@app.route('/api/watchlist-add', methods=['POST'])
def api_watchlist_add():
    """Add IP to watchlist"""
    data = request.get_json()
    ip = data.get('ip', '')
    
    if not ip:
        return jsonify({'error': 'IP required'}), 400
    
    store = get_store()
    watchlist = store.add_watchlist_ip(
        ip, data.get('reason', 'manual_watchlist'), data.get('notes', '')
    )
    return jsonify({'status': 'success', 'watchlist': [w['ip'] for w in watchlist]})


@app.route('/api/blocked-ips')
def api_blocked_ips():
    """Get list of blocked IPs"""
    return jsonify({'status': 'success', 'blocked': get_store().list_blocked_ips()})


@app.route('/api/watchlist')
def api_watchlist():
    """Get watchlist"""
    return jsonify({'status': 'success', 'watchlist': get_store().list_watchlist()})


@app.route('/api/iocs')
@login_required
def api_iocs():
    """Get list of detected IOCs"""
    limit = int(request.args.get('limit', 50))
    return jsonify(get_store().list_iocs(limit))


@app.route('/api/ioc/<filename>')
@login_required
def api_ioc(filename):
    """Get specific IOC details"""
    ioc = get_store().get_ioc(filename)
    if not ioc:
        return jsonify({'error': 'IOC not found'}), 404
    return jsonify(ioc)


@app.route('/api/logs')
@login_required
def api_logs():
    """Get recent logs"""
    limit = int(request.args.get('limit', 100))
    service = request.args.get('service', '')
    return jsonify(get_store().list_logs(limit, service))


@app.route('/api/pcaps')
@login_required
def api_pcaps():
    """Get list of packet captures"""
    return jsonify(get_store().list_pcaps(20))


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
        attackers = {}
        store = get_store()

        for session in store.list_sessions(500):
            try:
                session = enrich_session(session)
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
                logger.warning(f"Error processing session: {e}")
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
        
        store = get_store()
        for session in store.list_sessions(1000):
            try:
                session = enrich_session(session)
                location = session.get('location', {})
                session_country = location.get('country_code', '') or location.get('country', '')

                if session_country.upper() != country_code.upper():
                    continue

                start_time = session.get('start_time', '')
                if start_time:
                    try:
                        session_time = datetime.fromisoformat(start_time.replace('Z', '+00:00'))
                        if session_time < threshold:
                            continue
                    except Exception:
                        pass

                attacks = classify_attack(session)
                if attack_type != 'all':
                    attacks = [
                        a for a in attacks
                        if attack_type.lower()
                        in (a.get('category', '') + a.get('name', '')).lower()
                    ]

                country_sessions.append({
                    'session_id': session.get('session_id', ''),
                    'client_ip': session.get('client_ip', 'Unknown'),
                    'start_time': start_time,
                    'attacks': attacks,
                    'commands': session.get('commands', []),
                })

                unique_ips.add(session.get('client_ip', 'Unknown'))

                for attack in attacks:
                    attack_cat = attack.get('category', attack.get('name', 'Unknown'))
                    attack_types[attack_cat] = attack_types.get(attack_cat, 0) + 1

            except Exception as e:
                logger.warning(f"Error processing session: {e}")
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


@app.route('/api/cleanup', methods=['POST'])
@login_required
def api_cleanup():
    """Cleanup data files with partial or full mode"""
    try:
        data_payload = request.get_json() or {}
        mode = data_payload.get('mode', 'partial')
        
        import shutil
        
        data_dir = Path(__file__).resolve().parent.parent.parent / 'data'
        
        def safe_remove_contents(directory):
            if not directory.exists():
                return
            for item in directory.iterdir():
                try:
                    if item.is_file():
                        os.remove(item)
                    elif item.is_dir():
                        shutil.rmtree(item)
                except Exception as e:
                    logger.warning(f"Failed to remove {item}: {e}")

        if mode == 'partial':
            # Local data directory targets
            if data_dir.exists():
                for target in ['logs', 'sessions', 'iocs']:
                    target_dir = data_dir / target
                    safe_remove_contents(target_dir)
            
            # Docker paths targets
            safe_remove_contents(LOGS_DIR)
            safe_remove_contents(SESSIONS_DIR)
            safe_remove_contents(IOCS_DIR)
            
        elif mode == 'full':
            if data_dir.exists():
                for subfolder in data_dir.iterdir():
                    if subfolder.is_dir():
                        safe_remove_contents(subfolder)
            
            # Docker paths targets
            safe_remove_contents(LOGS_DIR)
            safe_remove_contents(SESSIONS_DIR)
            safe_remove_contents(IOCS_DIR)
            safe_remove_contents(PCAPS_DIR)
            
            # Ensure required folders exist
            required_folders = ['pcaps', 'logs', 'sessions', 'iocs', 'ssh', 'http', 'db', 'smb-ftp']
            if data_dir.exists():
                for folder in required_folders:
                    try:
                        (data_dir / folder).mkdir(parents=True, exist_ok=True)
                    except Exception as e:
                        logger.warning(f"Failed to create directory {folder}: {e}")
                        
        return jsonify({'status': 'success', 'message': f'{mode.capitalize()} cleanup completed successfully'})
        
    except Exception as e:
        logger.error(f"Cleanup error: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500


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


def main():
    """Main entry point (local Docker / dev). On Vercel, the platform imports `app`."""
    port = int(os.getenv('DASHBOARD_PORT', 5000))
    host = os.getenv('DASHBOARD_HOST', '0.0.0.0')
    logger.info(f"Starting Web Dashboard on {host}:{port} (backend={inject_public_config()['data_backend']})")
    app.run(host=host, port=port, debug=False)


if __name__ == '__main__':
    main()

