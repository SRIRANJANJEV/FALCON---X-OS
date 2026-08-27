#!/bin/bash
# FALCON-X Factory Reset
# Safely resets the appliance to factory defaults

set -euo pipefail

FALCONX_HOME="/opt/falconx"
FALCONX_ETC="/etc/falconx"
FALCONX_VAR="/var/lib/falconx"
FALCONX_LOG="/var/log/falconx"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log() { echo -e "${CYAN}[RESET]${NC} $*"; }
warn() { echo -e "${YELLOW}[RESET]${NC} $*"; }
err() { echo -e "${RED}[RESET]${NC} $*" >&2; }

check_root() {
    if [[ $EUID -ne 0 ]]; then
        err "Factory reset requires root"
        exit 1
    fi
}

confirm_reset() {
    echo ""
    echo -e "${RED}╔══════════════════════════════════════════════╗${NC}"
    echo -e "${RED}║         FACTORY RESET WARNING                ║${NC}"
    echo -e "${RED}╠══════════════════════════════════════════════╣${NC}"
    echo -e "${RED}║                                              ║${NC}"
    echo -e "${RED}║  This will PERMANENTLY remove:               ║${NC}"
    echo -e "${RED}║    • Device identity and configuration       ║${NC}"
    echo -e "${RED}║    • Administrator credentials               ║${NC}"
    echo -e "${RED}║    • Network configuration                   ║${NC}"
    echo -e "${RED}║    • Baseline data                           ║${NC}"
    echo -e "${RED}║    • Incidents and logs                      ║${NC}"
    echo -e "${RED}║    • AI models                               ║${NC}"
    echo -e "${RED}║    • TLS certificates                        ║${NC}"
    echo -e "${RED}║                                              ║${NC}"
    echo -e "${RED}║  The system will reboot after reset.         ║${NC}"
    echo -e "${RED}║                                              ║${NC}"
    echo -e "${RED}╚══════════════════════════════════════════════╝${NC}"
    echo ""

    read -p "Type 'FACTORY RESET' to confirm: " confirm
    if [[ "$confirm" != "FACTORY RESET" ]]; then
        echo "Aborted."
        exit 0
    fi

    echo ""
    read -p "Enter device serial/ID to confirm: " serial
    local device_id
    device_id=$(cat "$FALCONX_VAR/device-id" 2>/dev/null || echo "unknown")
    if [[ "$serial" != "$device_id" && "$serial" != "CONFIRM" ]]; then
        err "Serial mismatch. Use device ID or 'CONFIRM' to proceed."
        exit 1
    fi
}

stop_services() {
    log "Stopping FALCON-X services..."
    for svc in falconx-web falconx-engine falconx-health; do
        systemctl stop "$svc.service" 2>/dev/null || true
    done
    log "Services stopped"
}

reset_device_identity() {
    log "Resetting device identity..."
    rm -f "$FALCONX_VAR/device-id"
    rm -f "$FALCONX_VAR/protection-state.json"
    rm -f "$FALCONX_VAR/.first-boot-done"
    log "Device identity removed"
}

reset_credentials() {
    log "Resetting credentials..."
    rm -f "$FALCONX_ETC/web-users.json"
    rm -f "$FALCONX_ETC/initial-password.txt"
    log "Credentials removed"
}

reset_configuration() {
    log "Resetting configuration..."

    # Reset config files to defaults
    local config_dir="$FALCONX_ETC"
    for conf in falconx.yaml network.yaml security.yaml web.yaml engine.yaml; do
        if [[ -f "$config_dir/$conf.default" ]]; then
            cp "$config_dir/$conf.default" "$config_dir/$conf"
        fi
    done

    # Reset secrets (regenerate on next boot)
    rm -f "$FALCONX_ETC/secrets/"*.key
    rm -f "$FALCONX_ETC/secrets/"*.crt
    rm -f "$FALCONX_ETC/secrets/"*.pub

    log "Configuration reset"
}

reset_network() {
    log "Resetting network configuration..."
    rm -f /etc/systemd/network/*.network 2>/dev/null || true
    rm -f /etc/udev/rules.d/70-persistent-net.rules 2>/dev/null || true
    hostnamectl set-hostname "falconx" 2>/dev/null || true
    log "Network reset"
}

reset_data() {
    log "Resetting runtime data..."

    # Clear baseline
    rm -rf "$FALCONX_VAR/baseline"/*

    # Clear incidents
    rm -rf "$FALCONX_VAR/incidents"/*

    # Clear status files
    rm -f "$FALCONX_VAR/"*.status

    # Clear logs but keep directory
    rm -rf "$FALCONX_LOG/"*
    mkdir -p "$FALCONX_LOG/security"

    # Clear AI models
    rm -rf "$FALCONX_HOME/models/"*.pkl
    rm -rf "$FALCONX_HOME/models/"*.json

    # Clear temporary files
    rm -rf /tmp/falconx-*

    log "Runtime data cleared"
}

reset_firewall() {
    log "Resetting firewall..."
    nft flush ruleset 2>/dev/null || true
    log "Firewall reset"
}

reset_permissions() {
    log "Resetting permissions..."
    # Re-run permission setup
    if [[ -x "$FALCONX_HOME/scripts/permissions.sh" ]]; then
        bash "$FALCONX_HOME/scripts/permissions.sh" 2>/dev/null || true
    fi
    log "Permissions reset"
}

reboot_system() {
    log "System will reboot in 10 seconds..."
    log "After reboot, first-boot setup will run automatically."
    sleep 10
    reboot
}

print_summary() {
    echo ""
    echo -e "${GREEN}╔══════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║    Factory Reset Complete                     ║${NC}"
    echo -e "${GREEN}╠══════════════════════════════════════════════╣${NC}"
    echo -e "${GREEN}║                                              ║${NC}"
    echo -e "${GREEN}║  ✓ Device identity removed                   ║${NC}"
    echo -e "${GREEN}║  ✓ Credentials removed                       ║${NC}"
    echo -e "${GREEN}║  ✓ Configuration reset                       ║${NC}"
    echo -e "${GREEN}║  ✓ Network reset                             ║${NC}"
    echo -e "${GREEN}║  ✓ Runtime data cleared                      ║${NC}"
    echo -e "${GREEN}║  ✓ Firewall reset                            ║${NC}"
    echo -e "${GREEN}║                                              ║${NC}"
    echo -e "${GREEN}║  System will reboot automatically.           ║${NC}"
    echo -e "${GREEN}║  First-boot setup will run on next boot.     ║${NC}"
    echo -e "${GREEN}║                                              ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════╝${NC}"
    echo ""
}

main() {
    check_root
    confirm_reset
    stop_services
    reset_device_identity
    reset_credentials
    reset_configuration
    reset_network
    reset_data
    reset_firewall
    reset_permissions
    print_summary
    reboot_system
}

main "$@"
