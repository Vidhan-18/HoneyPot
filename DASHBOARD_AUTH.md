# Dashboard Authentication

## Default Credentials

**Username:** `admin`  
**Password:** `honeypot2024`

⚠️ **IMPORTANT:** Change these credentials in production!

## Changing Credentials

### Option 1: Environment Variables

Set in `.env` file or docker-compose.yml:

```bash
DASHBOARD_USERNAME=your_username
DASHBOARD_PASSWORD_HASH=<sha256_hash_of_password>
```

To generate password hash:
```python
import hashlib
hashlib.sha256('your_password'.encode()).hexdigest()
```

### Option 2: Modify auth.py

Edit `monitoring/web-dashboard/auth.py`:
```python
DEFAULT_USERNAME = 'your_username'
DEFAULT_PASSWORD_HASH = hashlib.sha256('your_password'.encode()).hexdigest()
```

## Security Features

- ✅ Session-based authentication
- ✅ Secure password hashing (SHA256)
- ✅ Login attempt logging
- ✅ Session timeout on logout
- ✅ Protected API endpoints

## Access

1. Navigate to `http://localhost:5000`
2. You'll be redirected to login page
3. Enter credentials
4. Access dashboard

## Logout

Click "Logout" in the dashboard header or navigate to `/logout`

