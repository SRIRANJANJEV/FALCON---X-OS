#!/bin/bash
# FALCON-X Update System
# Secure update mechanism with signature verification and rollback

set -euo pipefail

FALCONX_HOME="/opt/falconx"
FALCONX_ETC="/etc/falconx"
FALCONX_VAR="/var/lib/falconx"
UPDATE_DIR="$FALCONX_VAR/updates"
BACKUP_DIR="$FALCONX_VAR/backups"
SIGNING_PUB="$FALCONX_ETC/secrets/signing.pub"
VERSION_FILE="$FALCONX_VAR/version"
UPDATE_LOG="/var/log/falconx/security/update.log"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log() {
    local msg="[$(date -u +%Y-%m-%dT%H:%M:%SZ)] $*"
    echo -e "${CYAN}[UPDATE]${NC} $*"
    echo "$msg" >> "$UPDATE_LOG" 2>/dev/null || true
}

warn() {
    echo -e "${YELLOW}[UPDATE]${NC} $*" >&2
}

err() {
    echo -e "${RED}[UPDATE]${NC} $*" >&2
    echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] ERROR: $*" >> "$UPDATE_LOG" 2>/dev/null || true
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        err "Update requires root"
        exit 1
    fi
}

get_current_version() {
    cat "$VERSION_FILE" 2>/dev/null || echo "0.0.0"
}

# ── Step 1: Download ─────────────────────────────────────────────

download_update() {
    local url="$1"
    local dest="$UPDATE_DIR"

    mkdir -p "$dest"

    log "Downloading update from: $url"

    local filename
    filename=$(basename "$url")
    local filepath="$dest/$filename"

    if ! curl -fsSL -o "$filepath" "$url"; then
        err "Download failed"
        return 1
    fi

    log "Downloaded: $filepath"
    echo "$filepath"
}

# ── Step 2: Signature Verification ───────────────────────────────

verify_signature() {
    local package="$1"
    local signature="$2"

    if [[ ! -f "$SIGNING_PUB" ]]; then
        err "Signing public key not found: $SIGNING_PUB"
        return 1
    fi

    if [[ ! -f "$signature" ]]; then
        err "Signature file not found: $signature"
        return 1
    fi

    log "Verifying cryptographic signature..."

    if openssl pkeyutl -verify \
        -pubin -inkey "$SIGNING_PUB" \
        -sigfile "$signature" \
        -in "$package" 2>/dev/null; then
        log "Signature verification: PASSED"
        return 0
    else
        err "Signature verification: FAILED"
        err "Package may have been tampered with"
        return 1
    fi
}

# ── Step 3: Integrity Verification ───────────────────────────────

verify_integrity() {
    local package="$1"
    local expected_hash="$2"

    log "Verifying integrity (SHA-256)..."

    local actual_hash
    actual_hash=$(sha256sum "$package" | cut -d' ' -f1)

    if [[ "$actual_hash" == "$expected_hash" ]]; then
        log "Integrity verification: PASSED"
        return 0
    else
        err "Integrity verification: FAILED"
        err "Expected: $expected_hash"
        err "Actual:   $actual_hash"
        return 1
    fi
}

# ── Step 4: Version Check ────────────────────────────────────────

verify_version() {
    local new_version="$1"
    local current_version
    current_version=$(get_current_version)

    log "Version check: $current_version → $new_version"

    if printf '%s\n%s' "$current_version" "$new_version" | sort -V | tail -n1 | grep -q "$new_version"; then
        if [[ "$current_version" == "$new_version" ]]; then
            log "Same version — reinstall"
        else
            log "Upgrade confirmed"
        fi
        return 0
    else
        err "Downgrade detected: $current_version → $new_version (not allowed)"
        return 1
    fi
}

# ── Step 5: Backup ───────────────────────────────────────────────

create_backup() {
    local version
    version=$(get_current_version)
    local backup_path="$BACKUP_DIR/backup-${version}-$(date +%Y%m%d%H%M%S)"

    log "Creating backup: $backup_path"

    mkdir -p "$backup_path"

    # Backup critical files
    tar -czf "$backup_path/etc-falconx.tar.gz" -C / etc/falconx/ 2>/dev/null || true
    tar -czf "$backup_path/opt-falconx.tar.gz" -C / opt/falconx/ 2>/dev/null || true
    tar -czf "$backup_path/systemd-falconx.tar.gz" -C / etc/systemd/system/ 'falconx-*' 2>/dev/null || true

    # Save current version
    echo "$version" > "$backup_path/version"

    log "Backup created: $backup_path"
    echo "$backup_path"
}

# ── Step 6: Install ──────────────────────────────────────────────

install_update() {
    local package="$1"
    local new_version="$2"

    log "Installing update v${new_version}..."

    # Extract package to temp directory
    local tmpdir
    tmpdir=$(mktemp -d)

    tar -xzf "$package" -C "$tmpdir" 2>/dev/null || {
        err "Failed to extract update package"
        rm -rf "$tmpdir"
        return 1
    }

    # Stop services
    log "Stopping FALCON-X services..."
    for svc in falconx-web falconx-engine; do
        systemctl stop "$svc.service" 2>/dev/null || true
    done

    # Install files
    log "Installing files..."
    if [[ -d "$tmpdir/opt/falconx" ]]; then
        rsync -a --delete "$tmpdir/opt/falconx/" "$FALCONX_HOME/"
    fi

    if [[ -d "$tmpdir/etc/falconx" ]]; then
        rsync -a "$tmpdir/etc/falconx/" "$FALCONX_ETC/"
    fi

    if [[ -d "$tmpdir/etc/systemd/system" ]]; then
        cp "$tmpdir/etc/systemd/system/"falconx-*.service /etc/systemd/system/ 2>/dev/null || true
    fi

    # Update version
    echo "$new_version" > "$VERSION_FILE"

    # Make scripts executable
    find "$FALCONX_HOME" -name "*.py" -exec chmod 755 {} \;
    find "$FALCONX_HOME" -name "*.sh" -exec chmod 755 {} \;
    chmod +x "$FALCONX_HOME/bin/falconx" 2>/dev/null || true

    # Reload systemd
    systemctl daemon-reload

    rm -rf "$tmpdir"

    log "Update installed"
}

# ── Step 7: Health Check ─────────────────────────────────────────

post_update_health_check() {
    log "Running post-update health check..."

    # Start services
    log "Starting FALCON-X services..."
    for svc in falconx-engine falconx-web; do
        systemctl start "$svc.service" 2>/dev/null || true
    done

    # Wait for services to start
    sleep 5

    # Check engine health
    local healthy=true
    for port in 9100 8443; do
        if ! curl -sf "http://127.0.0.1:${port}/health" > /dev/null 2>&1; then
            err "Service on port $port not responding"
            healthy=false
        fi
    done

    if $healthy; then
        log "Health check: PASSED"
        return 0
    else
        err "Health check: FAILED"
        return 1
    fi
}

# ── Rollback ─────────────────────────────────────────────────────

rollback() {
    local backup_path="$1"

    if [[ ! -d "$backup_path" ]]; then
        err "Backup not found: $backup_path"
        return 1
    fi

    log "Rolling back to: $backup_path"

    # Stop services
    for svc in falconx-web falconx-engine; do
        systemctl stop "$svc.service" 2>/dev/null || true
    done

    # Restore from backup
    if [[ -f "$backup_path/etc-falconx.tar.gz" ]]; then
        tar -xzf "$backup_path/etc-falconx.tar.gz" -C / 2>/dev/null || true
    fi
    if [[ -f "$backup_path/opt-falconx.tar.gz" ]]; then
        tar -xzf "$backup_path/opt-falconx.tar.gz" -C / 2>/dev/null || true
    fi
    if [[ -f "$backup_path/systemd-falconx.tar.gz" ]]; then
        tar -xzf "$backup_path/systemd-falconx.tar.gz" -C /etc/systemd/system/ 2>/dev/null || true
    fi

    # Restore version
    if [[ -f "$backup_path/version" ]]; then
        cp "$backup_path/version" "$VERSION_FILE"
    fi

    systemctl daemon-reload

    # Restart services
    for svc in falconx-engine falconx-web; do
        systemctl start "$svc.service" 2>/dev/null || true
    done

    log "Rollback complete"
}

# ── Full Update Pipeline ─────────────────────────────────────────

perform_update() {
    local url="$1"
    local signature_url="${url}.sig"
    local hash="$2"
    local new_version="$3"

    log "═══════════════════════════════════════════════"
    log "Starting update pipeline"
    log "═══════════════════════════════════════════════"

    # 1. Download
    local package
    package=$(download_update "$url") || return 1

    # 2. Download signature
    local sig_file="${package}.sig"
    curl -fsSL -o "$sig_file" "$signature_url" 2>/dev/null || {
        warn "No signature available"
        sig_file=""
    }

    # 3. Verify signature
    if [[ -n "$sig_file" && -f "$sig_file" ]]; then
        verify_signature "$package" "$sig_file" || return 1
    fi

    # 4. Verify integrity
    if [[ -n "$hash" ]]; then
        verify_integrity "$package" "$hash" || return 1
    fi

    # 5. Verify version
    verify_version "$new_version" || return 1

    # 6. Backup
    local backup_path
    backup_path=$(create_backup)

    # 7. Install
    install_update "$package" "$new_version" || {
        err "Installation failed — rolling back"
        rollback "$backup_path"
        return 1
    }

    # 8. Health check
    if ! post_update_health_check; then
        err "Health check failed — rolling back"
        rollback "$backup_path"
        return 1
    fi

    log "═══════════════════════════════════════════════"
    log "Update successful: v$(get_current_version) → v${new_version}"
    log "═══════════════════════════════════════════════"

    return 0
}

usage() {
    echo "Usage: $0 <command> [args]"
    echo ""
    echo "Commands:"
    echo "  update <url> <hash> <version>   Perform a full update"
    echo "  rollback <backup_path>          Rollback to a backup"
    echo "  version                         Show current version"
    echo "  verify <package> <sig> <hash>   Verify an update package"
    echo "  backups                         List available backups"
    echo ""
}

main() {
    local cmd="${1:-}"
    shift || true

    check_root

    case "$cmd" in
        update)
            local url="${1:-}"
            local hash="${2:-}"
            local version="${3:-}"
            if [[ -z "$url" || -z "$version" ]]; then
                err "URL and version required"
                usage
                exit 1
            fi
            perform_update "$url" "$hash" "$version"
            ;;
        rollback)
            local backup="${1:-}"
            if [[ -z "$backup" ]]; then
                err "Backup path required"
                exit 1
            fi
            rollback "$backup"
            ;;
        version)
            echo "FALCON-X v$(get_current_version)"
            ;;
        verify)
            local pkg="${1:-}" sig="${2:-}" hash="${3:-}"
            if [[ -z "$pkg" ]]; then
                err "Package path required"
                exit 1
            fi
            if [[ -n "$sig" ]]; then
                verify_signature "$pkg" "$sig" || exit 1
            fi
            if [[ -n "$hash" ]]; then
                verify_integrity "$pkg" "$hash" || exit 1
            fi
            log "Verification passed"
            ;;
        backups)
            if [[ -d "$BACKUP_DIR" ]]; then
                ls -la "$BACKUP_DIR/"
            else
                log "No backups found"
            fi
            ;;
        *)
            usage
            exit 1
            ;;
    esac
}

main "$@"
