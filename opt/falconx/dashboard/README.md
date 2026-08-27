# FALCON-X Dashboard — Deployment Guide

## Quick Start

```bash
# 1. Install dependencies
sudo apt install python3-yaml

# 2. Create default admin user
sudo python3 /opt/falconx/dashboard/auth.py

# 3. Start dashboard
sudo systemctl start falconx-web

# 4. Access dashboard
# https://<pi-ip>:8443
```

## First Login

1. Check the initial password:
```bash
cat /etc/falconx/initial-password.txt
```

2. Navigate to `https://<pi-ip>:8443`
3. Login with `admin` and the initial password
4. **Change the password immediately** (not yet implemented — use CLI)

## Dashboard Pages

### Overview
- System status (PROTECTED/DEGRADED/UNPROTECTED)
- Engine status and uptime
- Device count
- Active incidents
- Risk level
- CPU/RAM/Disk/Temperature bars
- Recent incidents

### Devices
- IP, status, flows, risk, first/last seen
- Auto-refreshes every 15 seconds

### Traffic
- Packets captured/dropped
- Active flows
- Total flows
- Drop rate

### Incidents
- Incident ID, time, device, type, severity, risk, status
- Click to view evidence

### Health
- Component-by-component health status
- Engine, detector, AI, firewall, network
- CPU, memory, disk, temperature

### Config
- Detection sensitivity
- Firewall mode
- Enforcement mode
- AI settings

## API Endpoints

| Method | Path | Auth | Description |
|---|---|---|---|
| POST | /api/login | No | Authenticate |
| POST | /api/logout | Yes | Destroy session |
| GET | /api/status | Yes | System status |
| GET | /api/health | Yes | Health check |
| GET | /api/devices | Yes | Device list |
| GET | /api/traffic | Yes | Traffic stats |
| GET | /api/incidents | Yes | Incidents |
| GET | /api/events | Yes | Event data |
| GET | /api/config | Yes | Configuration |
| POST | /api/config | Yes | Update config |
| POST | /api/ai/analyze | Yes | AI analysis |
| GET | /api/ai/status | Yes | AI status |

## Security Features

### Authentication
- PBKDF2-SHA256 password hashing (100K iterations)
- Random salt per user
- Session tokens (32 bytes, URL-safe)
- Session timeout: 30 minutes
- Max concurrent sessions: 50
- Account lockout after 5 failed attempts (15 min)

### Session Security
- HttpOnly cookies (no JavaScript access)
- Secure flag (HTTPS only)
- SameSite=Strict (CSRF protection)
- No default permanent credentials

### Rate Limiting
- API: 100 requests/minute per IP
- Login: 20 attempts/minute per IP
- Config changes: 50 requests/minute per IP

### HTTP Security Headers
- X-Content-Type-Options: nosniff
- X-Frame-Options: DENY
- Cache-Control: no-store

### Input Validation
- Username format validation (alphanumeric + _/-)
- Configuration change validation
- No shell command execution

## OmniRoute AI Integration

### Setup
```bash
# Set environment variables
export FALCONX_OMNIROUTE_ENABLED=true
export FALCONX_OMNIROUTE_URL=http://127.0.0.1:11434
export FALCONX_OMNIROUTE_MODEL=llama3.2

# Restart dashboard
sudo systemctl restart falconx-web
```

### How It Works
1. Incident detected by engine
2. Evidence formatted (IPs anonymized, no raw data)
3. Sent to OmniRoute for analysis
4. AI returns: summary, explanation, severity, recommendations
5. Displayed in dashboard

### Safety
- Never sends raw system access to AI
- Never sends credentials or keys
- Never sends full packet contents
- IP addresses anonymized
- AI cannot execute commands
- Falls back gracefully when unavailable

### When AI Is Offline
- All local detection continues
- Dashboard shows "AI: OFFLINE, LOCAL DETECTION: ACTIVE"
- No security degradation

## TLS Configuration

The dashboard uses TLS by default:
- Certificate: `/etc/falconx/secrets/server.crt`
- Private key: `/etc/falconx/secrets/server.key`

To generate new certificates:
```bash
sudo /opt/falconx/scripts/secrets.sh generate
```

## Troubleshooting

### Cannot access dashboard
```bash
# Check service status
sudo systemctl status falconx-web

# Check logs
sudo journalctl -u falconx-web -n 50

# Check port
ss -tlnp | grep 8443

# Check firewall
nft list ruleset | grep 8443
```

### Login fails
```bash
# Check user file
cat /etc/falconx/web-users.json

# Reset: delete and recreate
sudo rm /etc/falconx/web-users.json
sudo python3 /opt/falconx/dashboard/auth.py
```

### TLS errors
```bash
# Check certificates
openssl x509 -in /etc/falconx/secrets/server.crt -noout -dates

# Regenerate
sudo /opt/falconx/scripts/secrets.sh generate
```

### Performance issues
```bash
# Check memory
free -h

# Check CPU
top -bn1 | head -20

# Reduce refresh rate in browser (currently 15s)
```
