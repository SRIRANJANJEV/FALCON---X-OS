# FALCON-X OS

**Plug-and-Protect Raspberry Pi 4 Cybersecurity Appliance**

> Flash SD card → Boot → Auto-setup → Protect.

## Overview

FALCON-X is an edge cybersecurity appliance designed for Raspberry Pi 4. It provides real-time network threat detection, anomaly identification, risk scoring, and security incident management — all running locally without requiring cloud connectivity.

## Quick Start

### Deployment
```bash
# 1. Build or download the FALCON-X image
sudo ./image-builder/build-image.sh

# 2. Flash to SD card
sudo dd if=output/falconx-os.img of=/dev/sdX bs=4M status=progress

# 3. Insert SD card into Raspberry Pi 4

# 4. Power on — FALCON-X auto-configures on first boot
```

### Access
```
Dashboard:  https://<pi-ip>:8443
SSH:        ssh pi@<pi-ip> (key-based only)
API:        https://<pi-ip>:8443/api/status
```

### First Login
```bash
cat /etc/falconx/initial-password.txt
# Use admin / <password> on the dashboard
```

## Architecture

```
Network Traffic
      ↓
Packet Capture (Scapy, 96B snap)
      ↓
Bounded Queue (10K, graceful overload)
      ↓
Feature Extraction (21 features)
      ↓
Behavioral Baseline (per-device profiles)
      ↓
Detection Pipeline
  ├── Rule Engine (10 rules)
  ├── Statistical Anomaly (z-score)
  └── ML Interface (Isolation Forest)
      ↓
Risk Scoring (weighted, explainable)
      ↓
Incident System (OPEN → RESOLVED)
      ↓
Enforcement (log-only default)
      ↓
Dashboard (real-time)
```

## Components

| Component | Port | Purpose |
|---|---|---|
| Engine | 9100 | Core detection pipeline |
| Detector | 9101 | Threat detection service |
| AI | 9102 | ML inference service |
| Dashboard | 8443 | Web management interface |
| Health | — | System health monitoring |

## Security Features

- **Firewall**: nftables, DROP by default, rate limiting
- **SSH**: Key-only, no root, group-restricted
- **systemd**: Full sandboxing (PrivateTmp, ProtectSystem, capabilities)
- **AppArmor**: Per-service profiles
- **Kernel**: ASLR, SYN cookies, no redirects, restricted BPF
- **Secrets**: PBKDF2 passwords, Ed25519 signing, AES-256 keys
- **Logging**: Security event logging, 90-day retention
- **TLS 1.2+**: Dashboard encrypted

## Protection States

| State | Meaning |
|---|---|
| **PROTECTED** | All core components operational |
| **DEGRADED** | Non-critical component failure (AI, web) |
| **UNPROTECTED** | Critical component failure (engine, firewall) |
| **RECOVERY** | System recovering from failure |

## Detection Rules

| Rule | Threshold | Severity |
|---|---|---|
| Port scan | 15+ unique ports/60s | HIGH |
| SYN flood | 100 pps + 80% SYN | CRITICAL |
| DNS anomaly | 60 queries/min | MEDIUM |
| ARP anomaly | 10 ARP/10s | HIGH |
| Unknown device | New device | LOW |
| Brute force | 10+ failed connections | HIGH |
| Data exfiltration | 100MB+ outbound | CRITICAL |
| ICMP flood | 50 pps | HIGH |

## Dashboard

Real-time web dashboard showing:
- System status and protection state
- Network devices and risk levels
- Traffic statistics
- Security incidents with evidence
- Health monitoring (CPU/RAM/disk/temp)
- Configuration management
- AI analysis status

## AI Integration (OmniRoute)

Optional AI analysis of security incidents:
- Structured evidence (no raw data sent)
- Summary, explanation, recommendations
- Graceful fallback when unavailable
- **Never** used as primary security authority

## Update System

Secure update pipeline:
1. Cryptographic signature verification
2. SHA-256 integrity check
3. Version verification (no downgrades)
4. Automatic backup
5. Health check
6. Auto-rollback on failure

## Factory Reset

```bash
sudo /opt/falconx/scripts/factory-reset.sh
# Type 'FACTORY RESET' to confirm
```

## Project Structure

```
falconx-os/
├── etc/                    # System configuration
│   ├── falconx/           # FALCON-X configs (YAML)
│   ├── nftables/          # Firewall rules
│   ├── apparmor.d/        # AppArmor profiles
│   ├── sysctl.d/          # Kernel hardening
│   ├── ssh/               # SSH hardening
│   ├── systemd/system/    # Service files
│   └── rsyslog.d/         # Logging
├── opt/falconx/           # Application
│   ├── engine/            # Detection engine (Python)
│   ├── dashboard/         # Web dashboard
│   ├── scripts/           # Management scripts
│   └── bin/               # CLI
├── scripts/               # System scripts
│   ├── update.sh          # Update system
│   └── factory-reset.sh   # Factory reset
├── tests/                 # Test suites
├── image-builder/         # Image building
└── docs/                  # Documentation
```

## Commands

```bash
falconx status      # System status
falconx health      # Health check
falconx network     # Network info
falconx logs        # View logs
falconx start       # Start services
falconx stop        # Stop services
falconx restart     # Restart services
```

## Testing

```bash
# End-to-end tests
sudo ./tests/e2e-test.sh

# Security audit
sudo ./scripts/security-verify.sh

# Performance benchmark
sudo ./tests/benchmark.sh

# Engine unit tests
cd /opt/falconx/engine && python3 -m pytest test_engine.py -v
```

## Documentation

- [Deployment Guide](docs/DEPLOYMENT.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Security Model](docs/SECURITY.md)
- [Configuration](docs/CONFIGURATION.md)
- [Troubleshooting](TROUBLESHOOTING.md)

## License

Proprietary — FALCON-X Security Appliance
