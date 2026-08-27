# FALCON-X OS Hardening Guide

## Overview

This document describes all security hardening applied to FALCON-X OS, including exceptions, rationale, and manual steps required.

## Compatibility Assessment

### Services and Ports

| Service | Port | Bind Address | Root Required | Reason |
|---|---|---|---|---|
| falconx-engine | 9100 | 127.0.0.1 | No | Detection pipeline (capture, rules, ML, risk, incidents) |
| falconx-web | 8443 | 0.0.0.0 | No | Dashboard (externally accessible) |
| falconx-enforcer | — | — | Yes | Privileged nftables enforcement (CAP_NET_ADMIN) |
| falconx-health | — | — | Yes | nftables access (CAP_NET_ADMIN) |

### Required Linux Capabilities

| Capability | Service | Reason | Exception? |
|---|---|---|---|
| CAP_NET_RAW | falconx-engine | Scapy packet capture | Yes — required for AF_PACKET sockets |
| CAP_NET_ADMIN | falconx-health | nft list commands | Yes — needed for firewall health checks |
| CAP_NET_ADMIN | falconx-enforcer | nft block/unblock commands | Yes — needed for enforcement |

### Services Requiring Root

- **falconx-health**: Runs as root for nftables access
- **falconx-enforcer**: Runs as root for nftables enforcement
- **first-boot.sh**: User creation, firewall setup
- **logrotate**: Log rotation

## Hardening Applied

### 1. nftables Firewall

**Config:** `/etc/nftables/falconx-monitor.nft` and `falconx-gateway.nft`

- Default INPUT: DROP
- Default FORWARD: DROP (monitor mode) / controlled (gateway mode)
- Default OUTPUT: ACCEPT (with outbound controls)
- Rate limiting on SSH (3/minute)
- ICMP rate limiting (5/second)
- Internal services restricted to localhost
- Firewall logging enabled

**Modes:**
- **Monitor mode**: Standard appliance, no forwarding
- **Gateway mode**: IP forwarding + NAT for LAN clients

### 2. SSH Hardening

**Config:** `/etc/ssh/sshd_config.d/falconx-hardened.conf`

- Root login: disabled
- Password auth: disabled (key-only)
- Max auth tries: 3
- Max sessions: 3
- X11 forwarding: disabled
- TCP forwarding: disabled
- AllowGroups: falconx-admin, ssh-users
- Logging: VERBOSE

**Manual activation required** — see "Manual Steps" below.

### 3. systemd Sandboxing

Applied to all FALCON-X services:

| Directive | Engine | Web | Enforcer | Health | Rationale |
|---|---|---|---|---|---|
| NoNewPrivileges | ✓ | ✓ | ✗ | ✗ | Enforcer/health need nftables |
| PrivateTmp | ✓ | ✓ | ✓ | ✓ | Isolate /tmp |
| ProtectSystem=strict | ✓ | ✓ | ✗ | ✗ | Enforcer/health need /proc |
| ProtectHome | ✓ | ✓ | ✓ | ✓ | No home dir access |
| ProtectKernelTunables | ✓ | ✓ | ✓ | ✓ | No /proc/sys writes |
| ProtectKernelModules | ✓ | ✓ | ✓ | ✓ | No module loading |
| CapabilityBoundingSet | CAP_NET_RAW | empty | CAP_NET_ADMIN | CAP_NET_ADMIN | Least privilege |
| RestrictNamespaces | ✓ | ✓ | ✓ | ✓ | No namespace creation |
| RestrictAddressFamilies | AF_INET+UNIX+AF_PACKET | AF_INET+UNIX | AF_UNIX+AF_NETLINK | AF_INET+UNIX | Network scope |

**Exceptions documented:**
- **MemoryDenyWriteExecute=false**: Python uses JIT/eval, incompatible with W^X
- **PrivateDevices=false (engine)**: Needs /dev/bpf* for packet capture
- **CAP_NET_RAW (engine)**: Required for Scapy raw socket access
- **CAP_NET_ADMIN (health)**: Required for nftables checks
- **CAP_NET_ADMIN (enforcer)**: Required for nftables enforcement

### 4. AppArmor Profiles

**Location:** `/etc/apparmor.d/`

Each profile:
- Allow only required binaries, libraries, config
- Allow required network access
- Deny SSH private keys, /etc/shadow, arbitrary writes
- Deny ptrace, kernel module access
- Deny writing to executables

### 5. Kernel Hardening (sysctl)

**Config:** `/etc/sysctl.d/99-falconx-hardening.conf`

| Setting | Value | Purpose |
|---|---|---|
| kernel.randomize_va_space | 2 | Full ASLR |
| kernel.dmesg_restrict | 1 | Hide dmesg from non-root |
| kernel.kptr_restrict | 2 | Hide kernel pointers |
| net.ipv4.ip_forward | 0 | No forwarding (monitor mode) |
| net.ipv4.conf.all.accept_source_route | 0 | Block source routing |
| net.ipv4.conf.all.accept_redirects | 0 | Block ICMP redirects |
| net.ipv4.tcp_syncookies | 1 | SYN flood protection |
| net.ipv4.conf.all.rp_filter | 1 | Reverse path filtering |
| kernel.sysrq | 0 | Disable SysRq |
| fs.suid_dumpable | 0 | No core dumps |
| kernel.unprivileged_bpf_disabled | 1 | Restrict BPF |

### 6. User/Permission Hardening

| Path | Owner | Permissions | Purpose |
|---|---|---|---|
| /etc/falconx/ | root:root | 755 | Config directory |
| /etc/falconx/*.yaml | root:root | 644 | Config files (read-only) |
| /etc/falconx/secrets/ | root:root | 700 | Secrets (root only) |
| /etc/falconx/secrets/*.key | root:root | 600 | Private keys |
| /etc/falconx/secrets/*.crt | root:root | 644 | Certificates (read-only) |
| /var/lib/falconx/ | root:root | 755 | Runtime data |
| /var/log/falconx/ | root:root | 755 | Logs |
| /opt/falconx/ | root:root | 755 | Application |

Service users:
- `falconx-engine`: nologin shell, engine detection pipeline
- `falconx-web`: nologin shell, dashboard

Groups:
- `falconx-admin`: SSH access
- `ssh-users`: SSH access
- `falconx-status`: Status file access
- `falconx-log`: Log file access

### 7. Protected Logging

- Security logs: `/var/log/falconx/security/`
  - auth.log, firewall.log, services.log, config-changes.log, boot.log
- rsyslog rules: `/etc/rsyslog.d/50-falconx-security.conf`
- Logrotate: 90-day retention for security logs, 7-day for app logs
- Security log ownership: root:adm, 640

### 8. Secret Management

Secrets stored in `/etc/falconx/secrets/` (700, root only):

- `master.key`: AES-256 encryption key (600)
- `server.crt`: TLS certificate (644)
- `server.key`: TLS private key (600)
- `signing.key`: Ed25519 signing key for updates (600)
- `signing.pub`: Public key for update verification (644)
- `api.key`: API authentication key (600)

Generation: `bash /opt/falconx/scripts/secrets.sh generate`

### 9. Update Verification

Foundation for secure updates:

1. **Signature verification**: Ed25519 signatures on release packages
2. **Integrity verification**: SHA-256 hash checking
3. **Version verification**: Prevents downgrades
4. **Tarball verification**: Archive integrity checks

Usage:
```bash
# Create release manifest
/opt/falconx/scripts/update-verify.sh manifest 0.2.0

# Sign a package
/opt/falconx/scripts/update-verify.sh sign falconx-0.2.0.tar.gz

# Verify an update
/opt/falconx/scripts/update-verify.sh verify falconx-0.2.0.tar.gz falconx-0.2.0.tar.gz.sig
```

## Manual Steps Required

### SSH Hardening (Recommended)

SSH hardening is NOT auto-enabled to prevent lockout:

```bash
# 1. Ensure you have SSH key access configured
ssh-copy-id pi@<falconx-ip>

# 2. Add your user to an allowed group
sudo usermod -aG falconx-admin pi

# 3. Test key-based login
ssh pi@<falconx-ip>

# 4. Enable hardening
sudo cp /etc/ssh/sshd_config.d/falconx-hardened.conf /etc/ssh/sshd_config.d/
sudo systemctl restart ssh

# 5. Verify (from another terminal!)
ssh pi@<falconx-ip>
```

### AppArmor Enforcement

```bash
# Load profiles
sudo apparmor_parser -r /etc/apparmor.d/falconx-engine
sudo apparmor_parser -r /etc/apparmor.d/falconx-web
sudo apparmor_parser -r /etc/apparmor.d/falconx-enforcer

# Set to enforce
sudo aa-enforce /etc/apparmor.d/falconx-engine
sudo aa-enforce /etc/apparmor.d/falconx-web
sudo aa-enforce /etc/apparmor.d/falconx-enforcer

# Verify
sudo aa-status
```

## Exceptions Summary

| Exception | Component | Reason | Risk Level |
|---|---|---|---|
| MemoryDenyWriteExecute=false | All services | Python JIT/eval | Low — Python sandboxing insufficient for W^X |
| CAP_NET_RAW | falconx-engine | Scapy packet capture | Medium — required for detection engine |
| CAP_NET_ADMIN | falconx-health | nftables health checks | Low — limited to nft list commands only |
| CAP_NET_ADMIN | falconx-enforcer | nftables enforcement | Medium — required for block/unblock |
| NoNewPrivileges=false | falconx-health | nftables requires privilege | Low — health check only |
| ProtectSystem not strict | falconx-health, falconx-enforcer | Needs /proc and nftables | Low — controlled services |
| PrivateDevices=false | falconx-engine | /dev/bpf* access | Medium — required for packet capture |

## Running Security Audit

```bash
# Full audit
sudo /opt/falconx/scripts/security-audit.sh

# Hardening verification tests
sudo /opt/falconx/scripts/hardening-test.sh
```

## Rollback Procedure

If hardening breaks functionality:

```bash
sudo /opt/falconx/scripts/rollback.sh
# Type 'ROLLBACK' to confirm
```

This will:
1. Backup current configuration
2. Flush firewall rules
3. Remove SSH hardening
4. Remove systemd sandboxing
5. Reset kernel settings
6. Reset permissions

**Warning:** System will be insecure after rollback.

## Files Created

| File | Purpose |
|---|---|
| `/etc/nftables/falconx-monitor.nft` | Monitor mode firewall |
| `/etc/nftables/falconx-gateway.nft` | Gateway mode firewall |
| `/etc/ssh/sshd_config.d/falconx-hardened.conf` | SSH hardening |
| `/etc/falconx/banner.txt` | SSH login banner |
| `/etc/sysctl.d/99-falconx-hardening.conf` | Kernel hardening |
| `/etc/apparmor.d/falconx-engine` | Engine AppArmor profile |
| `/etc/apparmor.d/falconx-enforcer` | Enforcer AppArmor profile |
| `/etc/apparmor.d/falconx-web` | Web AppArmor profile |
| `/etc/rsyslog.d/50-falconx-security.conf` | Security logging |
| `/etc/logrotate.d/falconx` | Log rotation |
| `/etc/falconx/security.yaml` | Security configuration |
| `/opt/falconx/scripts/firewall.sh` | Firewall management |
| `/opt/falconx/scripts/permissions.sh` | Permission hardening |
| `/opt/falconx/scripts/secrets.sh` | Secret management |
| `/opt/falconx/scripts/update-verify.sh` | Update verification |
| `/opt/falconx/scripts/security-audit.sh` | Security audit |
| `/opt/falconx/scripts/hardening-test.sh` | Hardening tests |
| `/opt/falconx/scripts/rollback.sh` | Rollback procedure |
| `/opt/falconx/scripts/apply-hardening.sh` | Apply all hardening |
