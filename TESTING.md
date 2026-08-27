# FALCON-X Testing Commands

## Service Status Tests

```bash
# Check all services
falconx status

# Check individual services
systemctl status falconx-engine
systemctl status falconx-web
systemctl status falconx-health
systemctl status falconx-enforcer
```

## Health Check Tests

```bash
# Full health check
falconx health

# JSON output
falconx health --json

# Manual health endpoint tests
curl http://127.0.0.1:9100/health
curl http://127.0.0.1:9101/health
curl http://127.0.0.1:9102/health
curl http://127.0.0.1:8443/health
```

## Network Tests

```bash
# Show network info
falconx network

# Test connectivity
ping -c 3 8.8.8.8
ping -c 3 google.com

# Test DNS
nslookup google.com

# Show interfaces
ip -brief addr show
```

## CLI Tests

```bash
# Show help
falconx --help

# Show version
falconx --version

# Show config
falconx config --show
```

## Service Lifecycle Tests

```bash
# Start all
falconx start

# Stop all
falconx stop

# Restart all
falconx restart

# Check logs
falconx logs falconx-engine
falconx logs falconx-web -n 100
falconx logs falconx-health -f
```

## Firewall Tests

```bash
# List rules
nft list ruleset | grep falconx

# Test blocked ports (should timeout)
nc -zv 192.168.1.100 3306  # MySQL - should be blocked

# Test allowed ports (should connect)
nc -zv 192.168.1.100 22    # SSH - should work
nc -zv 192.168.1.100 8443  # Dashboard - should work
```

## Stress Tests

```bash
# Multiple health checks
for i in {1..10}; do falconx health --json; done

# Service restart storm
for i in {1..5}; do falconx restart; sleep 2; done

# Connection flood test
ab -n 1000 -c 10 http://127.0.0.1:8443/health
```

## Log Tests

```bash
# Check journal logs
journalctl -u falconx-engine --since "5 minutes ago"
journalctl -u falconx-web --since "5 minutes ago"

# Check file logs
tail -f /var/log/falconx/engine.log
tail -f /var/log/falconx/web.log
tail -f /var/log/falconx/web.log
```

## Directory Structure Tests

```bash
# Verify directories exist
ls -la /opt/falconx/
ls -la /etc/falconx/
ls -la /var/lib/falconx/
ls -la /var/log/falconx/

# Verify permissions
stat -c '%a %U:%G' /etc/falconx/secrets
stat -c '%a %U:%G' /var/lib/falconx/
```

## Process Tests

```bash
# Check running processes
ps aux | grep falconx

# Check resource usage
top -b -n 1 | grep falconx

# Check open ports
ss -tlnp | grep -E '(9100|9101|9102|8443)'
```

## First Boot Tests

```bash
# Simulate first boot
sudo rm /var/lib/falconx/.first-boot-done
sudo /opt/falconx/scripts/first-boot.sh

# Check device ID was generated
cat /var/lib/falconx/device-id

# Check marker file
ls -la /var/lib/falconx/.first-boot-done
```

## Integration Tests

```bash
# Full system test script
#!/bin/bash
echo "=== FALCON-X Integration Test ==="

echo "1. Checking services..."
falconx status

echo "2. Running health check..."
falconx health

echo "3. Testing network..."
falconx network

echo "4. Checking firewall..."
nft list ruleset | grep -c "drop\|accept"

echo "5. Testing CLI..."
falconx --version

echo "=== Tests Complete ==="
```
