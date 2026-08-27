#!/bin/bash
# FALCON-X First Boot Setup
# Idempotent initialization of the FALCON-X security appliance
# Uses nftables exclusively — no iptables
#
# Exit codes:
#   0 = success or already completed
#   1 = critical failure

set -euo pipefail

FALCONX_HOME="/opt/falconx"
FALCONX_ETC="/etc/falconx"
FALCONX_VAR="/var/lib/falconx"
FALCONX_LOG="/var/log/falconx"
FALCONX_MARKER="/var/lib/falconx/.first-boot-done"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

STEP_COUNT=0
STEP_PASSED=0
STEP_FAILED=0
CRITICAL_FAILED=0

log()   { echo -e "${CYAN}[FALCON-X]${NC} $*"; }
ok()    { echo -e "${GREEN}[FALCON-X]${NC} $*"; ((STEP_PASSED++)); }
warn()  { echo -e "${YELLOW}[FALCON-X]${NC} $*"; }
err()   { echo -e "${RED}[FALCON-X]${NC} $*" >&2; ((STEP_FAILED++)); }

step() {
    ((STEP_COUNT++))
    echo -e "\n${BOLD}Step $STEP_COUNT: $*${NC}"
}

critical_step() {
    step "$1"
    shift
    if "$@"; then
        ok "$1 completed"
    else
        err "$1 FAILED — critical"
        ((CRITICAL_FAILED++))
        return 1
    fi
}

check_root() {
    [[ $EUID -eq 0 ]] || { err "Must run as root"; exit 1; }
}

check_already_done() {
    if [[ -f "$FALCONX_MARKER" ]]; then
        log "First boot already completed at $(cat "$FALCONX_MARKER")"
        log "To re-run: rm $FALCONX_MARKER && $0"
        exit 0
    fi
}

# ── Step 1: Directories ──────────────────────────────────────────

create_directories() {
    mkdir -p "$FALCONX_HOME"/{engine,dashboard,models,scripts,config,bin}
    mkdir -p "$FALCONX_ETC"/{secrets,nftables}
    mkdir -p "$FALCONX_VAR"/{baseline,incidents}
    mkdir -p "$FALCONX_LOG"/security
    mkdir -p /run/falconx
}

# ── Step 2: Device Identity ──────────────────────────────────────

generate_device_identity() {
    local id_file="$FALCONX_VAR/device-id"
    if [[ ! -f "$id_file" ]]; then
        local device_id
        device_id=$(cat /proc/sys/kernel/random/uuid | cut -d'-' -f1)
        echo "$device_id" > "$id_file"
        chmod 644 "$id_file"
        log "Device ID: $device_id"
    else
        log "Device ID exists: $(cat "$id_file")"
    fi
}

# ── Step 3: Service Users ────────────────────────────────────────

create_service_users() {
    local users=("falconx-engine" "falconx-web")
    local groups=("falconx-engine" "falconx-web")

    for g in "${groups[@]}"; do
        getent group "$g" > /dev/null 2>&1 || groupadd --system "$g"
    done

    for u in "${users[@]}"; do
        if ! id "$u" > /dev/null 2>&1; then
            useradd --system --gid "$u" --home-dir "$FALCONX_HOME" \
                --shell /usr/sbin/nologin --no-create-home "$u"
            log "Created user: $u"
        fi
    done

    # Supplementary groups
    usermod -aG falconx-engine,falconx-status falconx-engine 2>/dev/null || true
    usermod -aG falconx-web,falconx-status,falconx-log falconx-web 2>/dev/null || true

    # Admin group for SSH
    getent group falconx-admin > /dev/null 2>&1 || groupadd falconx-admin
    getent group ssh-users > /dev/null 2>&1 || groupadd ssh-users
}

# ── Step 4: Configuration ────────────────────────────────────────

initialize_configuration() {
    local config_file="$FALCONX_ETC/falconx.yaml"
    if [[ ! -f "$config_file" ]]; then
        err "Config missing: $config_file"
        return 1
    fi

    local device_id
    device_id=$(cat "$FALCONX_VAR/device-id" 2>/dev/null || echo "unknown")

    if command -v python3 > /dev/null 2>&1; then
        python3 -c "
import yaml, sys
try:
    with open('$config_file') as f:
        c = yaml.safe_load(f) or {}
    if not c.get('identity',{}).get('device_id'):
        c.setdefault('identity',{})['device_id'] = '$device_id'
        c['identity']['hostname'] = 'falconx-${device_id:0:8}'
        with open('$config_file','w') as f:
            yaml.dump(c, f, default_flow_style=False, sort_keys=False)
except Exception as e:
    print(f'Config init warning: {e}', file=sys.stderr)
" 2>/dev/null || warn "Config auto-update skipped"
    fi
}

# ── Step 5: Hostname ─────────────────────────────────────────────

set_hostname() {
    local device_id
    device_id=$(cat "$FALCONX_VAR/device-id" 2>/dev/null | head -c 8)
    local new_hostname="falconx-${device_id}"

    if [[ "$(hostname)" != "$new_hostname" ]]; then
        hostnamectl set-hostname "$new_hostname" 2>/dev/null || true
        echo "127.0.0.1 localhost $new_hostname" > /etc/hosts
        log "Hostname: $new_hostname"
    fi
}

# ── Step 6: Network ──────────────────────────────────────────────

configure_network() {
    if command -v systemctl > /dev/null 2>&1; then
        systemctl enable systemd-networkd 2>/dev/null || true
        systemctl enable systemd-resolved 2>/dev/null || true
        systemctl start systemd-networkd 2>/dev/null || true
        systemctl start systemd-resolved 2>/dev/null || true

        [[ -L /etc/resolv.conf ]] || \
            ln -sf /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf 2>/dev/null || true

        systemctl enable systemd-timesyncd 2>/dev/null || true
        systemctl start systemd-timesyncd 2>/dev/null || true
    fi
}

# ── Step 7: TLS ──────────────────────────────────────────────────

generate_tls_certificate() {
    local cert="$FALCONX_ETC/secrets/server.crt"
    local key="$FALCONX_ETC/secrets/server.key"

    if [[ -f "$cert" && -f "$key" ]]; then
        log "TLS certificate exists"
        return 0
    fi

    if ! command -v openssl > /dev/null 2>&1; then
        warn "openssl not found — TLS not configured"
        return 0
    fi

    local hostname
    hostname=$(hostname 2>/dev/null || echo "falconx")

    openssl req -x509 -newkey rsa:2048 -nodes \
        -keyout "$key" -out "$cert" -days 365 \
        -subj "/C=US/ST=Security/L=FALCON-X/O=FALCON-X/CN=${hostname}" \
        -addext "subjectAltName=DNS:${hostname},DNS:localhost,IP:127.0.0.1" \
        2>/dev/null

    chmod 600 "$key"
    chmod 644 "$cert"
    chown root:root "$cert" "$key"
}

# ── Step 8: Dashboard Credentials ────────────────────────────────

generate_dashboard_credentials() {
    local users_file="$FALCONX_ETC/web-users.json"
    local pw_file="$FALCONX_ETC/initial-password.txt"

    if [[ -f "$users_file" ]]; then
        log "Dashboard credentials exist"
        return 0
    fi

    if ! command -v python3 > /dev/null 2>&1; then
        warn "Python3 not available — skip dashboard credentials"
        return 0
    fi

    # Generate password — NEVER print to stdout/logs
    python3 -c "
import secrets, hashlib, json, os, sys

password = secrets.token_urlsafe(12)
salt = secrets.token_hex(16)
hashed = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000).hex()

users = {'admin': {
    'password_hash': hashed,
    'salt': salt,
    'created': int(__import__('time').time()),
    'last_login': 0,
    'role': 'admin'
}}

users_path = '$users_file'
with open(users_path, 'w') as f:
    json.dump(users, f, indent=2)
os.chmod(users_path, 0o600)

# Write initial password to file — NOT to stdout
pw_path = '$pw_file'
with open(pw_path, 'w') as f:
    f.write(f'admin:{password}\n')
os.chmod(pw_path, 0o600)

# Confirm success without revealing password
print('Credentials generated successfully')
" 2>/dev/null || warn "Dashboard credential generation skipped"
}

# ── Step 9: nftables ─────────────────────────────────────────────

configure_firewall() {
    if ! command -v nft > /dev/null 2>&1; then
        err "nftables not found"
        return 1
    fi

    local rules_file="$FALCONX_ETC/nftables/falconx-monitor.nft"
    if [[ ! -f "$rules_file" ]]; then
        err "Firewall rules not found: $rules_file"
        return 1
    fi

    # Validate rules before applying
    if ! nft -c -f "$rules_file" 2>/dev/null; then
        err "Firewall rules validation failed"
        return 1
    fi

    # Apply rules
    nft flush ruleset 2>/dev/null || true
    if nft -f "$rules_file"; then
        log "nftables firewall configured (monitor mode)"
    else
        err "Failed to apply nftables rules"
        return 1
    fi

    mkdir -p "$FALCONX_VAR"
    echo "monitor" > "$FALCONX_VAR/firewall-mode"
    systemctl enable nftables 2>/dev/null || true
}

# ── Step 10: Permissions ─────────────────────────────────────────

set_permissions() {
    # Application ownership
    chown -R root:root "$FALCONX_HOME"
    chown -R root:root "$FALCONX_ETC"

    # Scripts executable
    find "$FALCONX_HOME" -name "*.py" -exec chmod 755 {} \;
    find "$FALCONX_HOME" -name "*.sh" -exec chmod 755 {} \;
    chmod +x "$FALCONX_HOME/bin/falconx" 2>/dev/null || true

    # Config files — readable, root-writable
    find "$FALCONX_ETC" -name "*.yaml" -exec chmod 644 {} \;
    chmod 644 "$FALCONX_ETC/banner.txt" 2>/dev/null || true

    # Secrets — root only
    chmod 700 "$FALCONX_ETC/secrets"
    find "$FALCONX_ETC/secrets" -type f -exec chmod 600 {} \; 2>/dev/null || true

    # Logs — writable by engine user
    chown -R falconx-engine:falconx-engine "$FALCONX_LOG" 2>/dev/null || true
    chmod 755 "$FALCONX_LOG"
    chmod 755 "$FALCONX_LOG/security" 2>/dev/null || true

    # Runtime data
    chown -R root:root "$FALCONX_VAR"
    chmod 755 "$FALCONX_VAR"
}

# ── Step 11: AppArmor ────────────────────────────────────────────

configure_apparmor() {
    if ! command -v apparmor_parser > /dev/null 2>&1; then
        warn "AppArmor not available — skipping"
        return 0
    fi

    local profile_dir="$FALCONX_ETC/../apparmor.d"
    [[ -d /etc/apparmor.d ]] && profile_dir="/etc/apparmor.d"

    for profile in falconx-engine falconx-web falconx-enforcer; do
        local profile_file="$profile_dir/$profile"
        if [[ -f "$profile_file" ]]; then
            # Validate profile syntax
            if apparmor_parser -Q "$profile_file" 2>/dev/null; then
                # Load profile
                apparmor_parser -r "$profile_file" 2>/dev/null && \
                    log "Loaded AppArmor profile: $profile" || \
                    warn "Could not load profile: $profile"
            else
                warn "AppArmor profile syntax error: $profile"
            fi
        fi
    done

    # Set profiles to enforce if aa-enforce is available
    if command -v aa-enforce > /dev/null 2>&1; then
        for profile in falconx-engine falconx-web falconx-enforcer; do
            aa-enforce "$profile" 2>/dev/null || true
        done
        log "AppArmor profiles set to enforce"
    fi
}

# ── Step 12: Sysctl ──────────────────────────────────────────────

apply_sysctl() {
    local sysctl_file="$FALCONX_ETC/../sysctl.d/99-falconx-hardening.conf"
    [[ -f /etc/sysctl.d/99-falconx-hardening.conf ]] && \
        sysctl_file="/etc/sysctl.d/99-falconx-hardening.conf"

    if [[ -f "$sysctl_file" ]]; then
        sysctl --system 2>/dev/null || true
        log "Sysctl configuration applied"
    else
        warn "Sysctl config not found"
    fi
}

# ── Step 13: systemd Services ────────────────────────────────────

install_systemd_services() {
    if [[ -d /etc/systemd/system ]]; then
        for svc in falconx-engine falconx-web falconx-health falconx-enforcer; do
            if [[ -f "/etc/systemd/system/${svc}.service" ]]; then
                systemctl enable "${svc}.service" 2>/dev/null || true
            fi
        done
        systemctl daemon-reload
    fi
}

# ── Step 14: Start Services ──────────────────────────────────────

start_services() {
    if command -v systemctl > /dev/null 2>&1; then
        systemctl start falconx-engine.service 2>/dev/null || warn "Engine start failed"
        systemctl start falconx-web.service 2>/dev/null || warn "Web start failed"
        systemctl start falconx-health.service 2>/dev/null || warn "Health start failed"
        systemctl start falconx-enforcer.service 2>/dev/null || warn "Enforcer start failed"
    fi
}

# ── Step 15: Health Check ────────────────────────────────────────

run_health_check() {
    # Wait for services to initialize
    sleep 3

    local all_ok=true

    # Check engine
    if curl -sf http://127.0.0.1:9100/health > /dev/null 2>&1; then
        log "Engine: healthy"
    else
        warn "Engine: not responding yet"
        all_ok=false
    fi

    # Check web
    if curl -sf http://127.0.0.1:8443/health > /dev/null 2>&1; then
        log "Dashboard: healthy"
    else
        warn "Dashboard: not responding yet"
        all_ok=false
    fi

    # Check nftables
    if nft list ruleset 2>/dev/null | grep -q "falconx_filter"; then
        log "Firewall: active"
    else
        warn "Firewall: rules not loaded"
        all_ok=false
    fi

    $all_ok
}

# ── Step 16: Mark Complete ───────────────────────────────────────

mark_complete() {
    echo "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$FALCONX_MARKER"
    chmod 644 "$FALCONX_MARKER"
}

# ── Summary ──────────────────────────────────────────────────────

print_summary() {
    local device_id
    device_id=$(cat "$FALCONX_VAR/device-id" 2>/dev/null || echo "unknown")
    echo ""
    echo -e "${GREEN}╔══════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║    FALCON-X First Boot Complete               ║${NC}"
    echo -e "${GREEN}╠══════════════════════════════════════════════╣${NC}"
    echo -e "${GREEN}║                                              ║${NC}"
    echo -e "${GREEN}║  Device:     $device_id                       ║${NC}"
    echo -e "${GREEN}║  Hostname:   $(hostname 2>/dev/null)             ║${NC}"
    echo -e "${GREEN}║  Firewall:   nftables (monitor mode)         ║${NC}"
    echo -e "${GREEN}║  AppArmor:   loaded                          ║${NC}"
    echo -e "${GREEN}║  Sysctl:     applied                         ║${NC}"
    echo -e "${GREEN}║  Dashboard:  https://$(hostname 2>/dev/null):8443     ║${NC}"
    echo -e "${GREEN}║  CLI:        falconx status                   ║${NC}"
    echo -e "${GREEN}║                                              ║${NC}"
    echo -e "${GREEN}║  Steps:      $STEP_COUNT total, $STEP_PASSED passed, $STEP_FAILED failed ║${NC}"
    echo -e "${GREEN}║                                              ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════╝${NC}"
    echo ""
}

# ── Main ─────────────────────────────────────────────────────────

main() {
    echo -e "${CYAN}"
    echo "  FALCON-X First Boot Setup"
    echo -e "${NC}"

    check_root
    check_already_done

    critical_step "Creating directories" create_directories
    critical_step "Generating device identity" generate_device_identity
    critical_step "Creating service users" create_service_users
    critical_step "Initializing configuration" initialize_configuration
    critical_step "Setting hostname" set_hostname
    critical_step "Configuring network" configure_network
    critical_step "Generating TLS certificate" generate_tls_certificate
    critical_step "Generating dashboard credentials" generate_dashboard_credentials
    critical_step "Configuring nftables firewall" configure_firewall
    critical_step "Setting permissions" set_permissions
    critical_step "Configuring AppArmor" configure_apparmor
    critical_step "Applying sysctl" apply_sysctl
    critical_step "Installing systemd services" install_systemd_services
    critical_step "Starting services" start_services
    critical_step "Running health check" run_health_check

    # Only mark complete if no critical failures
    if [[ $CRITICAL_FAILED -eq 0 ]]; then
        critical_step "Marking first boot complete" mark_complete
        print_summary
    else
        err "First boot FAILED — $CRITICAL_FAILED critical step(s) failed"
        err "Fix the issues and re-run: rm $FALCONX_MARKER && $0"
        exit 1
    fi
}

main "$@"
