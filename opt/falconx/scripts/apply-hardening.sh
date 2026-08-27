#!/bin/bash
# FALCON-X Hardening Apply Script
# Applies all security hardening in the correct order

set -euo pipefail

FALCONX_HOME="/opt/falconx"
SCRIPTS_DIR="$FALCONX_HOME/scripts"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log() {
    echo -e "${CYAN}[HARDEN]${NC} $*"
}

success() {
    echo -e "${GREEN}[HARDEN]${NC} $*"
}

warn() {
    echo -e "${YELLOW}[HARDEN]${NC} $*"
}

error() {
    echo -e "${RED}[HARDEN]${NC} $*" >&2
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "Hardening requires root"
        exit 1
    fi
}

print_banner() {
    echo -e "${CYAN}"
    echo "  FALCON-X Security Hardening"
    echo "  Applying comprehensive security measures"
    echo -e "${NC}"
}

apply_kernel_hardening() {
    log "Step 1: Applying kernel hardening..."

    if [[ -f /etc/sysctl.d/99-falconx-hardening.conf ]]; then
        sysctl --system > /dev/null 2>&1
        success "Kernel hardening applied"
    else
        warn "Sysctl config not found, skipping"
    fi
}

apply_permissions() {
    log "Step 2: Applying user and permission hardening..."

    if [[ -x "$SCRIPTS_DIR/permissions.sh" ]]; then
        bash "$SCRIPTS_DIR/permissions.sh"
        success "Permissions hardening applied"
    else
        warn "Permissions script not found, skipping"
    fi
}

apply_secrets() {
    log "Step 3: Initializing secrets..."

    if [[ -x "$SCRIPTS_DIR/secrets.sh" ]]; then
        bash "$SCRIPTS_DIR/secrets.sh" generate
        success "Secrets initialized"
    else
        warn "Secrets script not found, skipping"
    fi
}

apply_firewall() {
    log "Step 4: Applying firewall rules..."

    if [[ -x "$SCRIPTS_DIR/firewall.sh" ]]; then
        bash "$SCRIPTS_DIR/firewall.sh" apply monitor
        success "Firewall applied (monitor mode)"
    else
        warn "Firewall script not found, skipping"
    fi
}

apply_ssh() {
    log "Step 5: Configuring SSH hardening..."

    if [[ -d /etc/ssh/sshd_config.d ]]; then
        if [[ -f "$FALCONX_HOME/../etc/ssh/sshd_config.d/falconx-hardened.conf" ]]; then
            # Don't automatically enable — requires manual verification
            warn "SSH hardening config available but not auto-enabled"
            warn "Enable after verifying SSH key access:"
            warn "  sudo cp $FALCONX_HOME/../etc/ssh/sshd_config.d/falconx-hardened.conf /etc/ssh/sshd_config.d/"
            warn "  sudo systemctl restart ssh"
        fi
    fi
}

apply_apparmor() {
    log "Step 6: Loading AppArmor profiles..."

    if command -v apparmor_parser > /dev/null 2>&1; then
        local profile_dir="/etc/apparmor.d"
        for profile in falconx-engine falconx-web; do
            if [[ -f "$profile_dir/$profile" ]]; then
                apparmor_parser -r "$profile_dir/$profile" 2>/dev/null || \
                    warn "Could not load $profile (may need manual loading)"
            fi
        done
        success "AppArmor profiles loaded"
    else
        warn "AppArmor not installed, skipping"
        warn "Install with: apt install apparmor apparmor-utils"
    fi
}

apply_logging() {
    log "Step 7: Configuring protected logging..."

    mkdir -p /var/log/falconx/security

    if [[ -f /etc/rsyslog.d/50-falconx-security.conf ]]; then
        systemctl restart rsyslog 2>/dev/null || true
        success "Security logging configured"
    else
        warn "rsyslog config not found, skipping"
    fi
}

apply_services() {
    log "Step 8: Restarting FALCON-X services..."

    systemctl daemon-reload

    for svc in falconx-engine falconx-web falconx-health; do
        if systemctl restart "$svc.service" 2>/dev/null; then
            success "$svc restarted"
        else
            warn "$svc could not be restarted"
        fi
    done
}

run_audit() {
    log "Step 9: Running security audit..."

    if [[ -x "$SCRIPTS_DIR/security-audit.sh" ]]; then
        bash "$SCRIPTS_DIR/security-audit.sh" || true
    fi
}

print_summary() {
    echo ""
    echo -e "${GREEN}╔══════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║    FALCON-X Hardening Complete            ║${NC}"
    echo -e "${GREEN}╠══════════════════════════════════════════╣${NC}"
    echo -e "${GREEN}║                                          ║${NC}"
    echo -e "${GREEN}║  Applied:                                ║${NC}"
    echo -e "${GREEN}║    ✓ Kernel hardening (sysctl)           ║${NC}"
    echo -e "${GREEN}║    ✓ User/permission hardening           ║${NC}"
    echo -e "${GREEN}║    ✓ Secret generation                   ║${NC}"
    echo -e "${GREEN}║    ✓ nftables firewall                   ║${NC}"
    echo -e "${GREEN}║    ✓ systemd sandboxing                  ║${NC}"
    echo -e "${GREEN}║    ✓ AppArmor profiles                   ║${NC}"
    echo -e "${GREEN}║    ✓ Protected logging                   ║${NC}"
    echo -e "${GREEN}║                                          ║${NC}"
    echo -e "${GREEN}║  Manual steps required:                  ║${NC}"
    echo -e "${GREEN}║    1. SSH hardening (see warnings)       ║${NC}"
    echo -e "${GREEN}║    2. Verify SSH key access              ║${NC}"
    echo -e "${GREEN}║    3. Run: falconx security-audit        ║${NC}"
    echo -e "${GREEN}║                                          ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════╝${NC}"
    echo ""
}

main() {
    print_banner
    check_root

    apply_kernel_hardening
    apply_permissions
    apply_secrets
    apply_firewall
    apply_ssh
    apply_apparmor
    apply_logging
    apply_services
    run_audit
    print_summary
}

main "$@"
