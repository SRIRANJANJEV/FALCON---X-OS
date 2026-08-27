#!/bin/bash
# FALCON-X Firewall Manager
# Manages nftables firewall modes and rules

set -euo pipefail

FALCONX_NFT_DIR="/etc/nftables"
FALCONX_STATE_DIR="/var/lib/falconx"
FALCONX_MODE_FILE="$FALCONX_STATE_DIR/firewall-mode"
FALCONX_LOG="/var/log/falconx/firewall.log"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log() {
    local msg="[$(date -u +%Y-%m-%dT%H:%M:%SZ)] $*"
    echo -e "${CYAN}[FIREWALL]${NC} $*"
    echo "$msg" >> "$FALCONX_LOG" 2>/dev/null || true
}

error() {
    echo -e "${RED}[FIREWALL]${NC} $*" >&2
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "Firewall management requires root"
        exit 1
    fi
}

check_nft() {
    if ! command -v nft > /dev/null 2>&1; then
        error "nftables not found. Install with: apt install nftables"
        exit 1
    fi
}

get_current_mode() {
    if [[ -f "$FALCONX_MODE_FILE" ]]; then
        cat "$FALCONX_MODE_FILE"
    else
        echo "monitor"
    fi
}

set_mode() {
    local mode="$1"
    mkdir -p "$FALCONX_STATE_DIR"
    echo "$mode" > "$FALCONX_MODE_FILE"
}

apply_rules() {
    local mode="$1"
    local rules_file="$FALCONX_NFT_DIR/falconx-${mode}.nft"

    if [[ ! -f "$rules_file" ]]; then
        error "Rules file not found: $rules_file"
        exit 1
    fi

    log "Applying $mode firewall rules..."

    # Validate rules first
    if ! nft -c -f "$rules_file" 2>/dev/null; then
        error "Rules validation failed for $rules_file"
        exit 1
    fi

    # Apply rules
    if nft -f "$rules_file"; then
        log "Firewall rules applied successfully (mode: $mode)"
        set_mode "$mode"
    else
        error "Failed to apply firewall rules"
        exit 1
    fi
}

enable_ip_forwarding() {
    log "Enabling IP forwarding..."
    sysctl -w net.ipv4.ip_forward=1
    sysctl -w net.ipv6.conf.all.forwarding=1
    log "IP forwarding enabled"
}

disable_ip_forwarding() {
    log "Disabling IP forwarding..."
    sysctl -w net.ipv4.ip_forward=0
    sysctl -w net.ipv6.conf.all.forwarding=0
    log "IP forwarding disabled"
}

show_status() {
    local mode
    mode=$(get_current_mode)

    echo -e "\n${CYAN}FALCON-X Firewall Status${NC}\n"
    echo -e "  Mode:      ${GREEN}$mode${NC}"
    echo -e "  Rules:     $FALCONX_NFT_DIR/falconx-${mode}.nft"

    if command -v nft > /dev/null 2>&1; then
        echo -e "\n  Active rules:"
        nft list ruleset 2>/dev/null | head -30
        echo "  ..."
    fi

    echo -e "\n  IP forwarding:"
    echo -e "    IPv4: $(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo 'unknown')"
    echo -e "    IPv6: $(sysctl -n net.ipv6.conf.all.forwarding 2>/dev/null || echo 'unknown')"
    echo ""
}

show_rules() {
    local mode
    mode=$(get_current_mode)
    cat "$FALCONX_NFT_DIR/falconx-${mode}.nft"
}

list_modes() {
    echo "Available modes:"
    for f in "$FALCONX_NFT_DIR"/falconx-*.nft; do
        local name
        name=$(basename "$f" .nft | sed 's/falconx-//')
        echo "  - $name"
    done
}

flush_rules() {
    log "Flushing all nftables rules..."
    nft flush ruleset
    log "All rules flushed"
}

usage() {
    echo "Usage: $0 <command> [options]"
    echo ""
    echo "Commands:"
    echo "  apply <mode>     Apply firewall rules for mode (monitor|gateway)"
    echo "  status           Show current firewall status"
    echo "  rules            Show current active rules"
    echo "  modes            List available firewall modes"
    echo "  flush            Flush all rules (WARNING: opens firewall)"
    echo "  enable-forward   Enable IP forwarding (gateway mode)"
    echo "  disable-forward  Disable IP forwarding"
    echo ""
    echo "Examples:"
    echo "  $0 apply monitor   # Apply monitor mode (default)"
    echo "  $0 apply gateway   # Apply gateway mode with NAT"
    echo "  $0 status          # Show current status"
}

main() {
    local cmd="${1:-}"
    shift || true

    check_root
    check_nft

    case "$cmd" in
        apply)
            local mode="${1:-}"
            if [[ -z "$mode" ]]; then
                error "Mode required: monitor or gateway"
                usage
                exit 1
            fi
            apply_rules "$mode"
            if [[ "$mode" == "gateway" ]]; then
                enable_ip_forwarding
            else
                disable_ip_forwarding
            fi
            ;;
        status)
            show_status
            ;;
        rules)
            show_rules
            ;;
        modes)
            list_modes
            ;;
        flush)
            flush_rules
            ;;
        enable-forward)
            enable_ip_forwarding
            ;;
        disable-forward)
            disable_ip_forwarding
            ;;
        *)
            usage
            exit 1
            ;;
    esac
}

main "$@"
