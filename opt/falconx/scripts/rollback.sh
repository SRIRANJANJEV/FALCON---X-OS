#!/bin/bash
# FALCON-X Hardening Rollback Procedure
# Reverts security hardening to default/base state

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log() {
    echo -e "${CYAN}[ROLLBACK]${NC} $*"
}

warn() {
    echo -e "${YELLOW}[ROLLBACK]${NC} $*"
}

error() {
    echo -e "${RED}[ROLLBACK]${NC} $*" >&2
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "Rollback requires root"
        exit 1
    fi
}

confirm() {
    echo -e "\n${YELLOW}WARNING: This will revert security hardening!${NC}"
    echo -e "${YELLOW}This action should only be performed for troubleshooting.${NC}"
    echo ""
    read -p "Type 'ROLLBACK' to confirm: " confirm
    if [[ "$confirm" != "ROLLBACK" ]]; then
        echo "Aborted."
        exit 1
    fi
}

backup_current() {
    local backup_dir="/var/lib/falconx/rollback-backup-$(date +%Y%m%d-%H%M%S)"
    mkdir -p "$backup_dir"

    log "Backing up current configuration to $backup_dir..."

    # Backup configs
    cp -r /etc/falconx/ "$backup_dir/etc-falconx/" 2>/dev/null || true
    cp -r /etc/ssh/sshd_config.d/ "$backup_dir/ssh-config/" 2>/dev/null || true
    cp /etc/sysctl.d/99-falconx-hardening.conf "$backup_dir/" 2>/dev/null || true

    # Backup systemd services
    cp /etc/systemd/system/falconx-*.service "$backup_dir/" 2>/dev/null || true

    # Backup nftables
    cp -r /etc/nftables/ "$backup_dir/nftables/" 2>/dev/null || true

    # Backup rsyslog
    cp /etc/rsyslog.d/50-falconx-security.conf "$backup_dir/" 2>/dev/null || true

    # Save current nftables rules
    nft list ruleset > "$backup_dir/nftables-ruleset.txt" 2>/dev/null || true

    log "Backup saved to: $backup_dir"
}

rollback_firewall() {
    log "Rolling back firewall..."

    # Flush all nftables rules (nftables is the only firewall)
    if command -v nft > /dev/null 2>&1; then
        nft flush ruleset 2>/dev/null || true
        log "nftables rules flushed"
    fi

    log "Firewall rolled back to permissive"
}

rollback_ssh() {
    log "Rolling back SSH configuration..."

    # Remove hardening config
    rm -f /etc/ssh/sshd_config.d/falconx-hardened.conf

    # Restart SSH
    systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null || true

    log "SSH rolled back to defaults"
}

rollback_systemd() {
    log "Rolling back systemd services..."

    local service_dir="/etc/systemd/system"

    for svc in falconx-engine falconx-web falconx-health; do
        local file="$service_dir/${svc}.service"
        if [[ -f "$file" ]]; then
            # Remove sandboxing directives
            sed -i '/^PrivateTmp=/d' "$file"
            sed -i '/^ProtectSystem=/d' "$file"
            sed -i '/^ProtectHome=/d' "$file"
            sed -i '/^NoNewPrivileges=/d' "$file"
            sed -i '/^ProtectKernelTunables=/d' "$file"
            sed -i '/^ProtectKernelModules=/d' "$file"
            sed -i '/^ProtectKernelLogs=/d' "$file"
            sed -i '/^ProtectControlGroups=/d' "$file"
            sed -i '/^ProtectClock=/d' "$file"
            sed -i '/^ProtectHostname=/d' "$file"
            sed -i '/^CapabilityBoundingSet=/d' "$file"
            sed -i '/^AmbientCapabilities=/d' "$file"
            sed -i '/^SystemCallArchitectures=/d' "$file"
            sed -i '/^SystemCallFilter=/d' "$file"
            sed -i '/^MemoryDenyWriteExecute=/d' "$file"
            sed -i '/^LockPersonality=/d' "$file"
            sed -i '/^RestrictRealtime=/d' "$file"
            sed -i '/^RestrictSUIDSGID=/d' "$file"
            sed -i '/^RestrictNamespaces=/d' "$file"
            sed -i '/^RestrictAddressFamilies=/d' "$file"
            sed -i '/^PrivateDevices=/d' "$file"
        fi
    done

    systemctl daemon-reload
    log "Systemd sandboxing removed"
}

rollback_kernel() {
    log "Rolling back kernel hardening..."

    # Remove sysctl config
    rm -f /etc/sysctl.d/99-falconx-hardening.conf

    # Reset to defaults
    sysctl -w kernel.randomize_va_space=2 2>/dev/null || true
    sysctl -w kernel.dmesg_restrict=0 2>/dev/null || true
    sysctl -w net.ipv4.ip_forward=1 2>/dev/null || true
    sysctl -w net.ipv4.tcp_syncookies=1 2>/dev/null || true
    sysctl -w net.ipv4.conf.all.accept_source_route=1 2>/dev/null || true
    sysctl -w net.ipv4.conf.all.accept_redirects=1 2>/dev/null || true

    log "Kernel settings rolled back"
}

rollback_users() {
    log "Rolling back user permissions..."

    # Make secrets world-readable (INSECURE — for rollback only)
    chmod 755 /etc/falconx/secrets 2>/dev/null || true
    find /etc/falconx/secrets -type f -exec chmod 644 {} \; 2>/dev/null || true

    log "Permissions rolled back (INSECURE)"
}

rollback_logging() {
    log "Rolling back logging configuration..."

    # Remove security rsyslog config
    rm -f /etc/rsyslog.d/50-falconx-security.conf

    # Restart rsyslog
    systemctl restart rsyslog 2>/dev/null || true

    log "Logging configuration rolled back"
}

print_summary() {
    echo ""
    echo -e "${YELLOW}╔══════════════════════════════════════════╗${NC}"
    echo -e "${YELLOW}║    Rollback Complete                      ║${NC}"
    echo -e "${YELLOW}╠══════════════════════════════════════════╣${NC}"
    echo -e "${YELLOW}║                                          ║${NC}"
    echo -e "${YELLOW}║  Firewall:  permissive (ACCEPT)          ║${NC}"
    echo -e "${YELLOW}║  SSH:       defaults restored             ║${NC}"
    echo -e "${YELLOW}║  Systemd:   sandboxing removed           ║${NC}"
    echo -e "${YELLOW}║  Kernel:    settings reset                ║${NC}"
    echo -e "${YELLOW}║  Logging:   security logging removed     ║${NC}"
    echo -e "${YELLOW}║                                          ║${NC}"
    echo -e "${YELLOW}║  ⚠  SYSTEM IS NOW INSECURE  ⚠           ║${NC}"
    echo -e "${YELLOW}║  Re-run hardening to restore security    ║${NC}"
    echo -e "${YELLOW}║                                          ║${NC}"
    echo -e "${YELLOW}╚══════════════════════════════════════════╝${NC}"
    echo ""
}

main() {
    check_root
    confirm

    backup_current
    rollback_firewall
    rollback_ssh
    rollback_systemd
    rollback_kernel
    rollback_users
    rollback_logging
    print_summary
}

main "$@"
