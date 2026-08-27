# FALCON-X Architecture Document

## System Architecture

### Hardware
- **Platform**: Raspberry Pi 4 (ARM64)
- **RAM**: 2GB+ recommended
- **Storage**: 32GB+ microSD
- **Network**: Ethernet (primary), Wi-Fi (optional)
- **OS**: Raspberry Pi OS Lite 64-bit (Bookworm)

### Software Stack
```
┌─────────────────────────────────────────────┐
│                 Dashboard                    │
│            (Python HTTP + HTML)              │
├─────────────────────────────────────────────┤
│              Detection Engine                │
│  Capture → Features → Baseline → Detection  │
├─────────────────────────────────────────────┤
│            Security Layer                    │
│  nftables + AppArmor + systemd + sysctl     │
├─────────────────────────────────────────────┤
│              Linux Kernel                    │
│         (Raspberry Pi OS Lite)              │
└─────────────────────────────────────────────┘
```

### Service Architecture

```
falconx-first-boot.service (oneshot)
  └─→ falconx-engine.service (CAP_NET_RAW — capture + detection + risk + incidents)
  └─→ falconx-web.service (no caps — dashboard)
  └─→ falconx-health.service (CAP_NET_ADMIN — health monitoring)
  └─→ falconx-enforcer.service (CAP_NET_ADMIN — privileged nftables enforcement)
```

### Data Flow

1. **Capture**: Scapy sniffs packets (96B snap, metadata only)
2. **Queue**: Bounded queue (10K packets, drop on overflow)
3. **Features**: Flow aggregation, 21 features per flow
4. **Baseline**: Per-device behavioral profiles, 24h learning
5. **Detection**: Rules + Statistical + ML (optional)
6. **Risk**: Weighted scoring, explainable
7. **Incidents**: Structured, deduplicated, auto-close
8. **Enforcement**: Log-only default, never auto-blocks

### Network Modes

**Monitor Mode** (default):
- Single interface (eth0)
- No IP forwarding
- All traffic monitored
- DROP by default

**Gateway Mode**:
- Two interfaces (eth0 + eth1)
- IP forwarding enabled
- NAT for LAN clients
- Full firewall + monitoring

### Protection State Machine

```
BOOTING → INITIALIZING → PROTECTED
                        ↕
                      DEGRADED
                        ↕
                    UNPROTECTED → RECOVERY → PROTECTED
```

### Security Boundaries

| Boundary | Mechanism | Purpose |
|---|---|---|
| Network | nftables | Block unauthorized traffic |
| Process | systemd sandboxing | Isolate services |
| Filesystem | AppArmor | Restrict file access |
| Kernel | sysctl | Harden kernel parameters |
| Auth | PBKDF2 + sessions | Control access |
| Secrets | Encryption + permissions | Protect credentials |

### Memory Budget (Raspberry Pi 4, 2GB)

| Component | Budget | Notes |
|---|---|---|
| OS | 300MB | Linux kernel + systemd |
| Engine | 150MB | Capture + features + baseline + rules + anomaly + ML + risk + incidents |
| Dashboard | 100MB | HTTP server + auth + API |
| Enforcer | 32MB | Privileged nftables helper |
| Health | 32MB | Health monitoring |
| Buffer | 100MB | Headroom |
| **Total** | **~714MB** | Leaves ~1.3GB free on 2GB model |

### Boot Sequence

1. Linux kernel boot
2. systemd starts
3. First-boot check
4. If first boot:
   - Generate device identity
   - Create users
   - Configure network
   - Set up firewall
   - Generate secrets
   - Start services
5. If not first boot:
   - Apply sysctl
   - Start firewall
   - Start services
6. Engine initializes
7. Baseline learning begins
8. Detection active
9. Dashboard accessible
10. Protection state: PROTECTED
