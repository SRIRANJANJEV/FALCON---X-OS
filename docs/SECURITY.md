# FALCON-X Security Model

## Security Principles

1. **Least Privilege**: Each service runs with minimal permissions
2. **Defense in Depth**: Multiple overlapping security controls
3. **Secure Defaults**: Everything locked down by default
4. **Local-First**: Security works without internet
5. **No Blind Trust**: AI is advisory, not authoritative
6. **Fail Secure**: System fails to protected state

## Threat Model

### Assets Protected
- Network traffic metadata
- Device behavioral profiles
- Security incidents and evidence
- System configuration
- Cryptographic secrets

### Threat Actors
- External network attackers
- Compromised devices on LAN
- Insider threats (physical access)
- Supply chain attacks (updates)

### Attack Vectors
| Vector | Mitigation |
|---|---|
| Network scanning | Firewall DROP policy, rate limiting |
| Brute force SSH | Key-only auth, lockout, rate limit |
| Service exploitation | systemd sandboxing, AppArmor |
| Privilege escalation | NoNewPrivileges, capability bounding |
| Data exfiltration | Outbound traffic monitoring |
| Persistence | Read-only root (production), integrity checks |
| Tampering | Signed updates, secrets encryption |
| AI manipulation | Structured evidence only, no raw access |

## Security Controls

### Network Security
- **nftables firewall**: DROP by default, explicit allow-list
- **Rate limiting**: SSH (3/min), ICMP (5/s), connection flood protection
- **Input validation**: All API inputs validated
- **TLS 1.2+**: Dashboard encrypted, secure cookies
- **No exposed management**: Dashboard requires authentication

### Process Security
- **systemd sandboxing**: PrivateTmp, ProtectSystem=strict, ProtectHome
- **Capability bounding**: CAP_NET_RAW (engine only), CAP_NET_ADMIN (enforcer, health only)
- **No root services**: All services run as dedicated users
- **Syscall filtering**: SystemCallFilter=@system-service
- **Namespace restriction**: No user/pid/net namespaces

### Filesystem Security
- **AppArmor profiles**: Per-service, least-privilege
- **Secrets**: 700 root-only, 600 for key files
- **Config**: 644 root-owned, read-only to services
- **Logs**: 640 per-service owner, rotated
- **File permissions**: Strict ownership and permissions per service

### Authentication Security
- **PBKDF2-SHA256**: 100K iterations, random salt
- **Session tokens**: 32 bytes, URL-safe, HttpOnly, Secure, SameSite=Strict
- **Account lockout**: 5 failed attempts → 15 minute lockout
- **Rate limiting**: Login (20/min), API (100/min)
- **No default passwords**: Generated on first boot

### Update Security
- **Ed25519 signatures**: Cryptographic verification
- **SHA-256 integrity**: Hash verification
- **Version verification**: No downgrades allowed
- **Automatic backup**: Before any update
- **Health check**: After update
- **Auto-rollback**: On failure

### AI Security
- **Structured evidence only**: No raw data sent to AI
- **IP anonymization**: Partial IP masking
- **No credentials/keys**: Never sent to AI
- **No command execution**: AI cannot run commands
- **Graceful degradation**: System works without AI
- **Advisory only**: AI does not control enforcement

### Kernel Security
- **ASLR**: Full randomization (2)
- **SYN cookies**: Flood protection
- **No source routing**: Prevents spoofing
- **No ICMP redirects**: Prevents MITM
- **dmesg restriction**: Hidden from non-root
- **BPF restriction**: Unprivileged BPF disabled

## Privilege Analysis

| Service | User | Capabilities | Justification |
|---|---|---|---|
| engine | falconx-engine | CAP_NET_RAW | Scapy packet capture |
| web | falconx-web | (none) | HTTP only |
| enforcer | root | CAP_NET_ADMIN | nftables enforcement |
| health | root | CAP_NET_ADMIN | nftables health check |
| first-boot | root | full | System setup (one-time) |

## Security Exceptions

| Exception | Component | Risk | Justification |
|---|---|---|---|
| MemoryDenyWriteExecute=false | All Python services | Low | Python JIT/eval incompatible |
| CAP_NET_RAW | Engine | Medium | Required for Scapy raw sockets |
| CAP_NET_ADMIN | Health check, Enforcer | Low | Required for nftables operations |
| NoNewPrivileges=false | Health check | Low | Only runs nftables commands |

## Security Verification

Automated testing covers:
- Firewall rules and policies
- SSH hardening configuration
- User permissions and shells
- systemd sandboxing directives
- Kernel hardening parameters
- Secret file permissions
- Service health endpoints
- Open port verification
- Log integrity

Score is based on weighted checks, not arbitrary metrics.
