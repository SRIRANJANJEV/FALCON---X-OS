#!/bin/bash
# FALCON-X Secrets Management
# Generates and manages cryptographic secrets for FALCON-X

set -euo pipefail

SECRETS_DIR="/etc/falconx/secrets"
STATE_DIR="/var/lib/falconx"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log() {
    echo -e "${CYAN}[SECRETS]${NC} $*"
}

warn() {
    echo -e "${YELLOW}[SECRETS]${NC} $*"
}

error() {
    echo -e "${RED}[SECRETS]${NC} $*" >&2
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "Secrets management requires root"
        exit 1
    fi
}

init_secrets() {
    log "Initializing secrets directory..."

    mkdir -p "$SECRETS_DIR"
    chmod 700 "$SECRETS_DIR"
    chown root:root "$SECRETS_DIR"

    log "Secrets directory ready"
}

generate_master_key() {
    local key_file="$SECRETS_DIR/master.key"

    if [[ -f "$key_file" ]]; then
        warn "Master key already exists. Skipping."
        warn "To regenerate: rm $key_file && $0 generate"
        return 0
    fi

    log "Generating master key (AES-256)..."

    # Generate 256-bit (32 byte) random key
    openssl rand -hex 32 > "$key_file"
    chmod 600 "$key_file"
    chown root:root "$key_file"

    log "Master key generated: $key_file"
}

generate_tls_certificate() {
    local cert_file="$SECRETS_DIR/server.crt"
    local key_file="$SECRETS_DIR/server.key"

    if [[ -f "$cert_file" && -f "$key_file" ]]; then
        warn "TLS certificate already exists. Skipping."
        return 0
    fi

    log "Generating self-signed TLS certificate..."

    local hostname
    hostname=$(hostname 2>/dev/null || echo "falconx")

    openssl req -x509 -newkey rsa:2048 -nodes \
        -keyout "$key_file" \
        -out "$cert_file" \
        -days 365 \
        -subj "/C=US/ST=Security/L=FALCON-X/O=FALCON-X Security Appliance/CN=${hostname}" \
        -addext "subjectAltName=DNS:${hostname},DNS:localhost,IP:127.0.0.1" \
        2>/dev/null

    chmod 600 "$key_file"
    chmod 644 "$cert_file"
    chown root:root "$cert_file" "$key_file"

    log "TLS certificate generated"
    log "  Certificate: $cert_file"
    log "  Private key: $key_file"
}

generate_api_key() {
    local api_file="$SECRETS_DIR/api.key"

    if [[ -f "$api_file" ]]; then
        warn "API key already exists. Skipping."
        return 0
    fi

    log "Generating API key..."

    openssl rand -hex 32 > "$api_file"
    chmod 600 "$api_file"
    chown root:root "$api_file"

    log "API key generated: $api_file"
}

generate_signing_key() {
    local key_file="$SECRETS_DIR/signing.key"
    local pub_file="$SECRETS_DIR/signing.pub"

    if [[ -f "$key_file" ]]; then
        warn "Signing key already exists. Skipping."
        return 0
    fi

    log "Generating Ed25519 signing key for update verification..."

    openssl genpkey -algorithm Ed25519 -out "$key_file" 2>/dev/null
    openssl pkey -in "$key_file" -pubout -out "$pub_file" 2>/dev/null

    chmod 600 "$key_file"
    chmod 644 "$pub_file"
    chown root:root "$key_file" "$pub_file"

    log "Signing key generated"
    log "  Private: $key_file"
    log "  Public:  $pub_file"
    log "  Distribute the public key for update verification"
}

rotate_secrets() {
    log "Checking secret rotation..."

    local master_key="$SECRETS_DIR/master.key"
    local max_age_days=90

    if [[ ! -f "$master_key" ]]; then
        warn "No master key found. Generating..."
        generate_master_key
        return 0
    fi

    local key_age
    key_age=$(( ($(date +%s) - $(stat -c %Y "$master_key" 2>/dev/null || stat -f %m "$master_key" 2>/dev/null)) / 86400 ))

    if [[ $key_age -gt $max_age_days ]]; then
        warn "Master key is $key_age days old (max: $max_age_days)"
        warn "Rotation recommended. Run: $0 rotate"
    else
        log "Master key age: $key_age days (max: $max_age_days)"
    fi
}

verify_secrets() {
    log "Verifying secrets..."

    local issues=0

    # Check master key
    if [[ -f "$SECRETS_DIR/master.key" ]]; then
        local key_size
        key_size=$(wc -c < "$SECRETS_DIR/master.key" | tr -d ' ')
        if [[ $key_size -ge 32 ]]; then
            log "  Master key: OK ($key_size bytes)"
        else
            warn "  Master key: TOO SHORT ($key_size bytes, need 32)"
            ((issues++))
        fi
    else
        warn "  Master key: MISSING"
        ((issues++))
    fi

    # Check TLS cert
    if [[ -f "$SECRETS_DIR/server.crt" ]]; then
        if openssl x509 -in "$SECRETS_DIR/server.crt" -noout 2>/dev/null; then
            local expiry
            expiry=$(openssl x509 -in "$SECRETS_DIR/server.crt" -noout -enddate 2>/dev/null | cut -d= -f2)
            log "  TLS cert: OK (expires: $expiry)"
        else
            warn "  TLS cert: INVALID"
            ((issues++))
        fi
    else
        warn "  TLS cert: MISSING"
        ((issues++))
    fi

    # Check TLS key
    if [[ -f "$SECRETS_DIR/server.key" ]]; then
        if openssl rsa -in "$SECRETS_DIR/server.key" -check -noout 2>/dev/null; then
            log "  TLS key: OK"
        else
            warn "  TLS key: INVALID"
            ((issues++))
        fi
    else
        warn "  TLS key: MISSING"
        ((issues++))
    fi

    # Check signing key
    if [[ -f "$SECRETS_DIR/signing.key" ]] && [[ -f "$SECRETS_DIR/signing.pub" ]]; then
        log "  Signing keypair: OK"
    else
        warn "  Signing keypair: MISSING (needed for update verification)"
        ((issues++))
    fi

    if [[ $issues -eq 0 ]]; then
        log "All secrets verified successfully"
    else
        warn "$issues issue(s) found"
    fi

    return $issues
}

list_secrets() {
    log "Secrets inventory:"
    echo ""

    for f in "$SECRETS_DIR"/*; do
        if [[ -f "$f" ]]; then
            local name
            name=$(basename "$f")
            local perms
            perms=$(stat -c "%a %U:%G" "$f" 2>/dev/null || stat -p "%Lp %Su:%Sg" "$f" 2>/dev/null)
            echo "  $name ($perms)"
        fi
    done
    echo ""
}

usage() {
    echo "Usage: $0 <command>"
    echo ""
    echo "Commands:"
    echo "  init      Initialize secrets directory"
    echo "  generate  Generate all required secrets"
    echo "  verify    Verify secret integrity"
    echo "  rotate    Check rotation status"
    echo "  list      List all secrets"
    echo ""
}

main() {
    local cmd="${1:-}"
    shift || true

    check_root

    case "$cmd" in
        init)
            init_secrets
            ;;
        generate)
            init_secrets
            generate_master_key
            generate_tls_certificate
            generate_api_key
            generate_signing_key
            ;;
        verify)
            verify_secrets
            ;;
        rotate)
            rotate_secrets
            ;;
        list)
            list_secrets
            ;;
        *)
            usage
            exit 1
            ;;
    esac
}

main "$@"
