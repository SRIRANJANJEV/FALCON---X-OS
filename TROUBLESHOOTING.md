# FALCON-X Troubleshooting Guide

## Common Issues

### 1. Services Won't Start

**Symptoms:** `falconx status` shows services as stopped

**Solutions:**
```bash
# Check service status
systemctl status falconx-engine.service

# Check logs
journalctl -u falconx-engine.service -n 50

# Check if port is in use
ss -tlnp | grep 9100

# Restart the service
sudo systemctl restart falconx-engine.service

# Check for Python errors
python3 /opt/falconx/engine/main.py
```

### 2. Permission Denied Errors

**Symptoms:** Services fail to start with permission errors

**Solutions:**
```bash
# Fix ownership
sudo chown -R falconx-engine:falconx-engine /var/lib/falconx
sudo chown -R falconx-engine:falconx-engine /var/log/falconx

# Fix permissions
sudo chmod -R 755 /opt/falconx
sudo chmod 700 /etc/falconx/secrets

# Verify users exist
id falconx-engine
id falconx-web
```

### 3. Network Issues

**Symptoms:** No network connectivity, can't reach dashboard

**Solutions:**
```bash
# Check interface status
ip -brief addr show

# Check default route
ip route show default

# Restart networking
sudo systemctl restart systemd-networkd

# Check DNS
cat /etc/resolv.conf
ping -c 3 8.8.8.8

# For WiFi, check wpa_supplicant
sudo wpa_cli list_networks
```

### 4. Dashboard Not Accessible

**Symptoms:** Can't connect to https://<ip>:8443

**Solutions:**
```bash
# Check if web service is running
systemctl status falconx-web

# Check if port is listening
ss -tlnp | grep 8443

# Check firewall
nft list ruleset | grep 8443

# Test locally
curl -k https://127.0.0.1:8443/health

# Check SSL certificates
ls -la /etc/falconx/secrets/
```

### 5. Health Check Shows DEGRADED

**Symptoms:** `falconx health` shows DEGRADED status

**Solutions:**
```bash
# Run detailed health check
falconx health --json

# Check each component individually
curl http://127.0.0.1:9100/health  # Engine
curl http://127.0.0.1:9101/health  # Detector
curl http://127.0.0.1:9102/health  # AI

# Check firewall rules
nft list ruleset

# Check network connectivity
ping -c 3 8.8.8.8
```

### 6. First Boot Fails

**Symptoms:** Installation completes but first boot doesn't run

**Solutions:**
```bash
# Check if first boot marker exists
ls -la /var/lib/falconx/.first-boot-done

# Manually run first boot
sudo /opt/falconx/scripts/first-boot.sh

# Check for errors in the script
bash -x /opt/falconx/scripts/first-boot.sh
```

### 7. High Memory Usage

**Symptoms:** System becomes slow, services crash

**Solutions:**
```bash
# Check memory usage
free -h
ps aux --sort=-%mem | head

# Check for memory leaks
valgrind --leak-check=full python3 /opt/falconx/engine/main.py

# Adjust memory limits in systemd
sudo systemctl edit falconx-engine.service
# Add: [Service]
#      MemoryMax=512M
```

### 8. Log Files Too Large

**Symptoms:** Disk space running out

**Solutions:**
```bash
# Check log sizes
du -sh /var/log/falconx/*

# Configure logrotate
sudo nano /etc/logrotate.d/falconx
# Add:
# /var/log/falconx/*.log {
#     daily
#     rotate 7
#     compress
#     missingok
# }

# Manually rotate logs
sudo logrotate -f /etc/logrotate.d/falconx

# Clear old logs
sudo find /var/log/falconx -name "*.log" -mtime +7 -delete
```

### 9. Firewall Blocking Legitimate Traffic

**Symptoms:** Can't access services that should be allowed

**Solutions:**
```bash
# List all rules
nft list ruleset -v

# Check for specific port
nft list ruleset | grep <port-number>

# Temporarily allow a port
sudo nft add rule inet falconx_filter input tcp dport <port> accept

# Save rules
sudo nft list ruleset > /etc/nftables/falconx-backup.nft

# Restore default FALCON-X rules
sudo /opt/falconx/scripts/first-boot.sh
```

### 10. Service Won't Restart After Crash

**Symptoms:** Service crashes and doesn't come back

**Solutions:**
```bash
# Check service restart policy
systemctl show falconx-engine.service | grep Restart

# Check start limit
systemctl show falconx-engine.service | grep StartLimit

# Reset failed state
sudo systemctl reset-failed falconx-engine.service

# Manually start
sudo systemctl start falconx-engine.service
```

## Debug Mode

### Enable Verbose Logging

Edit `/etc/falconx/falconx.yaml`:
```yaml
system:
  log_level: "debug"
```

Restart services:
```bash
falconx restart
```

### Check System Logs

```bash
# System journal
journalctl -b -p err

# FALCON-X specific logs
journalctl -u falconx-engine -f
journalctl -u falconx-web -f
journalctl -u falconx-health -f

# Application logs
tail -f /var/log/falconx/engine.log
tail -f /var/log/falconx/detector.log
```

### Network Debugging

```bash
# Capture packets (if tcpdump installed)
sudo tcpdump -i eth0 -n port 8443

# Check connections
ss -tlnp | grep falconx
netstat -tlnp | grep falconx

# Trace network path
traceroute 8.8.8.8
```

## Recovery Procedures

### Service Recovery

```bash
# Stop all services
falconx stop

# Clear status files
sudo rm -f /var/lib/falconx/*.status

# Restart
falconx start
```

### Configuration Recovery

```bash
# Backup current config
cp /etc/falconx/falconx.yaml /etc/falconx/falconx.yaml.backup

# Restore from template
cp /opt/falconx/config/falconx.yaml /etc/falconx/falconx.yaml

# Re-run first boot
sudo /opt/falconx/scripts/first-boot.sh
```

### Full System Reset

```bash
# Stop services
falconx stop

# Remove all data
sudo rm -rf /var/lib/falconx/*
sudo rm -rf /var/log/falconx/*
sudo rm -f /var/lib/falconx/.first-boot-done

# Reinstall
sudo /opt/falconx/install.sh

# Verify
falconx status
falconx health
```

## Getting Help

### Collect Debug Information

```bash
#!/bin/bash
echo "=== FALCON-X Debug Info ==="
echo "Date: $(date)"
echo "Hostname: $(hostname)"
echo "Uptime: $(uptime)"
echo ""

echo "=== System Info ==="
uname -a
cat /etc/os-release
echo ""

echo "=== Memory ==="
free -h
echo ""

echo "=== Disk ==="
df -h
echo ""

echo "=== Network ==="
ip -brief addr show
ip route show
echo ""

echo "=== Services ==="
systemctl status falconx-engine falconx-web falconx-health falconx-enforcer
echo ""

echo "=== Health ==="
falconx health --no-color
echo ""

echo "=== Recent Logs ==="
journalctl -u falconx-engine --since "1 hour ago" -n 20
echo ""

echo "=== Firewall ==="
nft list ruleset
echo ""

echo "=== End Debug Info ==="
```

Save this as `debug.sh` and run:
```bash
chmod +x debug.sh
sudo ./debug.sh > falconx-debug.txt 2>&1
```

## Contact

For issues not covered here:
1. Check the logs: `falconx logs`
2. Run health check: `falconx health`
3. Review this guide
4. Check system resources: `free -h && df -h`
