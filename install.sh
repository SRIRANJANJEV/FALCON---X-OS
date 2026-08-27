#!/bin/bash
# FALCON-X Installation Script
# Installs FALCON-X OS components onto a Raspberry Pi OS system

set -euo pipefail

FALCONX_VERSION="0.1.0"
FALCONX_HOME="/opt/falconx"
FALCONX_ETC="/etc/falconx"
FALCONX_VAR="/var/lib/falconx"
FALCONX_LOG="/var/log/falconx"
SOURCE_DIR="$(cd "$(dirname "$0")" && pwd)"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log() {
    echo -e "${CYAN}[FALCON-X]${NC} $*"
}

success() {
    echo -e "${GREEN}[FALCON-X]${NC} $*"
}

warn() {
    echo -e "${YELLOW}[FALCON-X]${NC} $*"
}

error() {
    echo -e "${RED}[FALCON-X]${NC} $*" >&2
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "Installation must run as root"
        error "Run: sudo $0"
        exit 1
    fi
}

detect_platform() {
    ARCH=$(uname -m)
    log "Detected architecture: $ARCH"

    if [[ "$ARCH" != "aarch64" && "$ARCH" != "armv7l" ]]; then
        warn "FALCON-X is designed for Raspberry Pi (ARM). Current arch: $ARCH"
        warn "Continuing anyway for development/testing..."
    fi
}

install_dependencies() {
    log "Installing dependencies..."

    # Update package list
    apt-get update -qq

    # Core dependencies
    apt-get install -y -qq \
        python3 \
        python3-pip \
        python3-venv \
        python3-yaml \
        nftables \
        iproute2 \
        systemd \
        curl \
        wget \
        net-tools \
        dnsutils \
        ntp \
        logrotate \
        jq

    # Python packages
    pip3 install --break-system-packages pyyaml requests 2>/dev/null || \
        pip3 install pyyaml requests

    success "Dependencies installed"
}

install_falconx() {
    log "Installing FALCON-X v${FALCONX_VERSION}..."

    # Create directories
    mkdir -p "$FALCONX_HOME"/{engine,dashboard,models,scripts,config,bin}
    mkdir -p "$FALCONX_ETC/secrets"
    mkdir -p "$FALCONX_VAR"
    mkdir -p "$FALCONX_LOG"

    # Copy application files
    if [[ -d "$SOURCE_DIR/opt/falconx" ]]; then
        cp -r "$SOURCE_DIR/opt/falconx/"* "$FALCONX_HOME/"
    fi

    # Copy configuration files
    if [[ -d "$SOURCE_DIR/etc/falconx" ]]; then
        cp -r "$SOURCE_DIR/etc/falconx/"* "$FALCONX_ETC/"
    fi

    # Copy systemd service files
    if [[ -d "$SOURCE_DIR/etc/systemd/system" ]]; then
        cp "$SOURCE_DIR/etc/systemd/system/"falconx-*.service /etc/systemd/system/
    fi

    success "FALCON-X files installed"
}

setup_permissions() {
    log "Setting up permissions..."

    # Make scripts executable
    chmod +x "$FALCONX_HOME/bin/falconx"
    chmod +x "$FALCONX_HOME/scripts/"*.py 2>/dev/null || true
    chmod +x "$FALCONX_HOME/scripts/"*.sh 2>/dev/null || true
    chmod +x "$FALCONX_HOME/engine/"*.py 2>/dev/null || true
    chmod +x "$FALCONX_HOME/dashboard/"*.py 2>/dev/null || true

    # Secure secrets
    chmod 700 "$FALCONX_ETC/secrets"

    # Set ownership (will be refined in first-boot)
    chown -R root:root "$FALCONX_HOME"
    chown -R root:root "$FALCONX_ETC"

    success "Permissions configured"
}

setup_cli() {
    log "Setting up CLI..."

    # Create symlink for falconx command
    ln -sf "$FALCONX_HOME/bin/falconx" /usr/local/bin/falconx

    success "CLI available as: falconx"
}

install_services() {
    log "Installing systemd services..."

    systemctl daemon-reload

        for service in falconx-engine falconx-web falconx-health; do
        systemctl enable "${service}.service" 2>/dev/null || true
    done

    success "Services installed (not yet started)"
}

run_first_boot() {
    log "Running first boot setup..."

    if [[ -x "$FALCONX_HOME/scripts/first-boot.sh" ]]; then
        bash "$FALCONX_HOME/scripts/first-boot.sh"
    else
        warn "First boot script not found, skipping"
    fi
}

print_summary() {
    echo ""
    echo -e "${GREEN}╔══════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║    FALCON-X Installation Complete!       ║${NC}"
    echo -e "${GREEN}╠══════════════════════════════════════════╣${NC}"
    echo -e "${GREEN}║                                          ║${NC}"
    echo -e "${GREEN}║  Version:    ${CYAN}${FALCONX_VERSION}${GREEN}                      ║${NC}"
    echo -e "${GREEN}║  Location:   ${CYAN}/opt/falconx${GREEN}               ║${NC}"
    echo -e "${GREEN}║  Config:     ${CYAN}/etc/falconx${GREEN}               ║${NC}"
    echo -e "${GREEN}║  CLI:        ${CYAN}falconx status${GREEN}             ║${NC}"
    echo -e "${GREEN}║  Dashboard:  ${CYAN}https://$(hostname):8443${GREEN}   ║${NC}"
    echo -e "${GREEN}║                                          ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════╝${NC}"
    echo ""
}

main() {
    echo -e "${CYAN}"
    echo "  Installing FALCON-X Security Appliance v${FALCONX_VERSION}"
    echo -e "${NC}"

    check_root
    detect_platform
    install_dependencies
    install_falconx
    setup_permissions
    setup_cli
    install_services
    run_first_boot
    print_summary
}

main "$@"
