#!/bin/bash
# FALCON-X Permissions Hardening Script
# Sets secure ownership and permissions across the FALCON-X filesystem

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log() {
    echo -e "${CYAN}[PERMS]${NC} $*"
}

warn() {
    echo -e "${YELLOW}[PERMS]${NC} $*"
}

error() {
    echo -e "${RED}[PERMS]${NC} $*" >&2
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "Permissions hardening requires root"
        exit 1
    fi
}

setup_users() {
    log "Creating/verifying service users..."

    local users=("falconx-engine" "falconx-web")
    local groups=("falconx-engine" "falconx-web")

    for group in "${groups[@]}"; do
        if ! getent group "$group" > /dev/null 2>&1; then
            groupadd --system "$group"
            log "Created group: $group"
        fi
    done

    for user in "${users[@]}"; do
        if ! id "$user" > /dev/null 2>&1; then
            useradd --system \
                --gid "$user" \
                --home-dir /opt/falconx \
                --shell /usr/sbin/nologin \
                --no-create-home \
                "$user"
            log "Created user: $user"
        else
            log "User $user exists"
        fi
    done

    # Create admin group for SSH access
    if ! getent group falconx-admin > /dev/null 2>&1; then
        groupadd falconx-admin
        log "Created group: falconx-admin"
    fi

    # Create ssh-users group for SSH access
    if ! getent group ssh-users > /dev/null 2>&1; then
        groupadd ssh-users
        log "Created group: ssh-users"
    fi

    success "Service users ready"
}

setup_app_permissions() {
    log "Setting application permissions..."

    # /opt/falconx — application directory
    chown -R root:root /opt/falconx
    chmod 755 /opt/falconx
    chmod -R 755 /opt/falconx/bin
    chmod -R 755 /opt/falconx/scripts
    chmod 755 /opt/falconx/engine
    chmod 755 /opt/falconx/dashboard
    chmod 755 /opt/falconx/models
    chmod 755 /opt/falconx/config

    # Python scripts — executable but not writable by service users
    find /opt/falconx -name "*.py" -exec chmod 755 {} \;
    find /opt/falconx -name "*.sh" -exec chmod 755 {} \;

    # Application code — owned by root, read-only to services
    chown -R root:root /opt/falconx/engine
    chown -R root:root /opt/falconx/dashboard

    log "Application permissions set"
}

setup_config_permissions() {
    log "Setting configuration permissions..."

    # /etc/falconx — configuration directory
    chown -R root:root /etc/falconx
    chmod 755 /etc/falconx

    # Config files — readable by all, writable only by root
    chmod 644 /etc/falconx/*.yaml
    chmod 644 /etc/falconx/banner.txt

    # Secrets directory — root only, no group/other access
    chmod 700 /etc/falconx/secrets
    chown -R root:root /etc/falconx/secrets

    # Secret files — root read/write only
    find /etc/falconx/secrets -type f -exec chmod 600 {} \; 2>/dev/null || true

    log "Configuration permissions set"
}

setup_data_permissions() {
    log "Setting data directory permissions..."

    # /var/lib/falconx — runtime data
    chown -R root:root /var/lib/falconx
    chmod 755 /var/lib/falconx

    # Status files — readable by web service, writable by respective services
    # Create a shared group for status file access
    if ! getent group falconx-status > /dev/null 2>&1; then
        groupadd falconx-status
        log "Created group: falconx-status"
    fi

    # Add web user to status group (needs to read all status files)
    usermod -aG falconx-status falconx-web 2>/dev/null || true
    # Add engine user to status group (engine and detector share this)
    usermod -aG falconx-status falconx-engine 2>/dev/null || true

    # Set group ownership on status files
    chown root:falconx-status /var/lib/falconx/*.status 2>/dev/null || true
    chmod 644 /var/lib/falconx/*.status 2>/dev/null || true

    # Device ID — readable by all services
    chown root:falconx-status /var/lib/falconx/device-id 2>/dev/null || true
    chmod 644 /var/lib/falconx/device-id 2>/dev/null || true

    log "Data permissions set"
}

setup_log_permissions() {
    log "Setting log permissions..."

    # /var/log/falconx — log directory
    chown -R root:root /var/log/falconx
    chmod 755 /var/log/falconx

    # Log files — writable only by respective service users
    for svc in engine web; do
        local logfile="/var/log/falconx/${svc}.log"
        if [[ -f "$logfile" ]]; then
            chown "falconx-${svc}:" "$logfile" 2>/dev/null || true
            chmod 640 "$logfile"
        fi
    done

    # Create a shared group for log reading
    if ! getent group falconx-log > /dev/null 2>&1; then
        groupadd falconx-log
        log "Created group: falconx-log"
    fi

    # Add web user to log group (dashboard may show logs)
    usermod -aG falconx-log falconx-web 2>/dev/null || true

    # Set directory group
    chown root:falconx-log /var/log/falconx

    log "Log permissions set"
}

setup_ssh_hardening() {
    log "Setting up SSH hardening..."

    # Create SSH config directory
    mkdir -p /etc/ssh/sshd_config.d

    # Install hardening config
    if [[ -f /etc/ssh/sshd_config.d/falconx-hardened.conf ]]; then
        chmod 600 /etc/ssh/sshd_config.d/falconx-hardened.conf
        chown root:root /etc/ssh/sshd_config.d/falconx-hardened.conf
    fi

    log "SSH hardening configured"
    warn "NOTE: SSH hardening requires manual activation:"
    warn "  1. Add your SSH public key to /home/pi/.ssh/authorized_keys"
    warn "  2. Add your user to 'falconx-admin' or 'ssh-users' group"
    warn "  3. Test SSH key login"
    warn "  4. Then apply: sudo cp /etc/ssh/sshd_config.d/falconx-hardened.conf /etc/ssh/sshd_config.d/"
    warn "  5. Restart SSH: sudo systemctl restart ssh"
}

setup_kernel_modules() {
    log "Auditing kernel modules..."

    # List currently loaded modules
    local modules_file="/var/lib/falconx/loaded-modules.txt"
    lsmod > "$modules_file" 2>/dev/null || true
    chmod 644 "$modules_file"

    # Required modules for FALCON-X operation
    # Document these explicitly
    cat > /var/lib/falconx/required-modules.txt << 'EOF'
# FALCON-X Required Kernel Modules
# These modules are required for FALCON-X operation

# Network stack
af_packet          # Raw packet access (Scapy)
nf_conntrack       # Connection tracking (firewall)
nf_nat             # NAT (gateway mode)
nft_chain_nat      # nftables NAT
nft_ct             # nftables connection tracking
nft_dup            # nftables packet duplication
nft_fwd_redir      # nftables forwarding/redirection
nft_limit          # nftables rate limiting
nft_log            # nftables logging
nft_masq           # nftables masquerade
nft_redir          # nftables redirection
nftReject          # nftables reject

# Filesystem
ext4               # SD card filesystem
vfat               # Boot partition
fat32              # Boot partition

# USB (for debugging/updates)
usbcore
usbhid

# GPIO (for future hardware integration)
gpio_bcm2835       # Raspberry Pi GPIO

# I2C/SPI (for future sensor integration)
i2c_bcm2835
spi_bcm2835
EOF
    chmod 644 /var/lib/falconx/required-modules.txt

    log "Module audit complete"
    log "Required modules documented in /var/lib/falconx/required-modules.txt"
}

success() {
    echo -e "${GREEN}[PERMS]${NC} $*"
}

print_summary() {
    echo ""
    echo -e "${GREEN}╔══════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║    Permissions Hardening Complete         ║${NC}"
    echo -e "${GREEN}╠══════════════════════════════════════════╣${NC}"
    echo -e "${GREEN}║                                          ║${NC}"
    echo -e "${GREEN}║  Users:                                  ║${NC}"
    echo -e "${GREEN}║    falconx-engine  (engine pipeline)     ║${NC}"
    echo -e "${GREEN}║    falconx-web    (dashboard)            ║${NC}"
    echo -e "${GREEN}║                                          ║${NC}"
    echo -e "${GREEN}║  Groups:                                 ║${NC}"
    echo -e "${GREEN}║    falconx-admin  (SSH access)           ║${NC}"
    echo -e "${GREEN}║    ssh-users      (SSH access)           ║${NC}"
    echo -e "${GREEN}║    falconx-status (status file access)   ║${NC}"
    echo -e "${GREEN}║    falconx-log    (log file access)      ║${NC}"
    echo -e "${GREEN}║                                          ║${NC}"
    echo -e "${GREEN}║  Secrets: 600 root:root only             ║${NC}"
    echo -e "${GREEN}║  Config:   644 root:root (read-only)     ║${NC}"
    echo -e "${GREEN}║  Logs:     640 per-service owner         ║${NC}"
    echo -e "${GREEN}║                                          ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════╝${NC}"
    echo ""
}

main() {
    check_root
    setup_users
    setup_app_permissions
    setup_config_permissions
    setup_data_permissions
    setup_log_permissions
    setup_ssh_hardening
    setup_kernel_modules
    print_summary
}

main "$@"
