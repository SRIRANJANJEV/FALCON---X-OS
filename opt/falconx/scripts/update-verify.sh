#!/bin/bash
# FALCON-X Update Verification
# Verifies integrity and authenticity of FALCON-X updates

set -euo pipefail

FALCONX_HOME="/opt/falconx"
SECRETS_DIR="/etc/falconx/secrets"
STATE_DIR="/var/lib/falconx"
SIGNING_PUB="$SECRETS_DIR/signing.pub"
VERIFY_LOG="/var/log/falconx/security/update-verify.log"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log() {
    local msg="[$(date -u +%Y-%m-%dT%H:%M:%SZ)] $*"
    echo -e "${CYAN}[UPDATE]${NC} $*"
    echo "$msg" >> "$VERIFY_LOG" 2>/dev/null || true
}

warn() {
    echo -e "${YELLOW}[UPDATE]${NC} $*"
}

error() {
    echo -e "${RED}[UPDATE]${NC} $*" >&2
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "Update verification requires root"
        exit 1
    fi
}

# ── Step 1: Signature Verification ────────────────────────────────
verify_signature() {
    local package="$1"
    local signature="$2"

    if [[ ! -f "$SIGNING_PUB" ]]; then
        error "Signing public key not found: $SIGNING_PUB"
        error "Cannot verify update without signing key"
        return 1
    fi

    log "Verifying signature..."

    if openssl pkeyutl -verify \
        -pubin -inkey "$SIGNING_PUB" \
        -sigfile "$signature" \
        -in "$package" 2>/dev/null; then
        log "Signature verification: PASSED"
        return 0
    else
        error "Signature verification: FAILED"
        error "Package may have been tampered with"
        return 1
    fi
}

# ── Step 2: SHA-256 Integrity Verification ────────────────────────
verify_integrity() {
    local package="$1"
    local expected_hash="$2"

    log "Verifying integrity (SHA-256)..."

    local actual_hash
    actual_hash=$(sha256sum "$package" | cut -d' ' -f1)

    if [[ "$actual_hash" == "$expected_hash" ]]; then
        log "Integrity verification: PASSED"
        log "Hash: $actual_hash"
        return 0
    else
        error "Integrity verification: FAILED"
        error "Expected: $expected_hash"
        error "Actual:   $actual_hash"
        return 1
    fi
}

# ── Step 3: Version Verification ──────────────────────────────────
verify_version() {
    local package_version="$1"
    local current_version
    current_version=$(cat "$STATE_DIR/version" 2>/dev/null || echo "0.0.0")

    log "Checking version: $current_version -> $package_version"

    # Simple version comparison
    if printf '%s\n%s' "$current_version" "$package_version" | sort -V | tail -n1 | grep -q "$package_version"; then
        if [[ "$current_version" == "$package_version" ]]; then
            warn "Same version as current"
            return 0
        fi
        log "Version check: UPGRADE available"
        return 0
    else
        error "Version check: DOWNGRADE detected (not allowed)"
        error "Current: $current_version, Package: $package_version"
        return 1
    fi
}

# ── Step 4: Tarball Integrity ─────────────────────────────────────
verify_tarball() {
    local tarball="$1"

    log "Verifying tarball integrity..."

    # Test archive integrity
    if tar -tzf "$tarball" > /dev/null 2>&1; then
        log "Tarball integrity: PASSED"
        return 0
    else
        error "Tarball integrity: FAILED (corrupted archive)"
        return 1
    fi
}

# ── Full Verification Pipeline ────────────────────────────────────
verify_update() {
    local package="$1"
    local signature="${2:-}"
    local hash="${3:-}"

    log "═══════════════════════════════════════════════"
    log "Starting full update verification"
    log "Package: $package"
    log "═══════════════════════════════════════════════"

    # Verify file exists
    if [[ ! -f "$package" ]]; then
        error "Package not found: $package"
        return 1
    fi

    local failed=0

    # 1. Signature verification (if provided)
    if [[ -n "$signature" ]]; then
        verify_signature "$package" "$signature" || ((failed++))
    else
        warn "No signature provided — skipping signature verification"
    fi

    # 2. Integrity verification (if hash provided)
    if [[ -n "$hash" ]]; then
        verify_integrity "$package" "$hash" || ((failed++))
    else
        warn "No hash provided — computing hash"
        local computed_hash
        computed_hash=$(sha256sum "$package" | cut -d' ' -f1)
        log "Computed SHA-256: $computed_hash"
    fi

    # 3. Tarball integrity
    verify_tarball "$package" || ((failed++))

    # Summary
    log "═══════════════════════════════════════════════"
    if [[ $failed -eq 0 ]]; then
        log "Update verification: PASSED"
        log "Safe to install"
    else
        error "Update verification: FAILED ($failed check(s) failed)"
        error "DO NOT install this update"
        return 1
    fi
    log "═══════════════════════════════════════════════"
}

# ── Create release manifest ───────────────────────────────────────
create_manifest() {
    local version="$1"
    local manifest_file="$FALCONX_HOME/manifest-${version}.json"

    log "Creating release manifest for v${version}..."

    # Create temporary tarball of current state
    local tmpdir
    tmpdir=$(mktemp -d)
    tar -czf "$tmpdir/falconx-${version}.tar.gz" \
        -C "$FALCONX_HOME" \
        --exclude='*.pyc' \
        --exclude='__pycache__' \
        .

    local hash
    hash=$(sha256sum "$tmpdir/falconx-${version}.tar.gz" | cut -d' ' -f1)
    local size
    size=$(stat -c%s "$tmpdir/falconx-${version}.tar.gz" 2>/dev/null || \
           stat -f%z "$tmpdir/falconx-${version}.tar.gz" 2>/dev/null)

    cat > "$manifest_file" << EOF
{
    "version": "$version",
    "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "package": "falconx-${version}.tar.gz",
    "sha256": "$hash",
    "size": $size,
    "files": $(find "$FALCONX_HOME" -type f | wc -l),
    "signing_key": "ed25519"
}
EOF

    rm -rf "$tmpdir"

    log "Manifest created: $manifest_file"
    log "Hash: $hash"
}

usage() {
    echo "Usage: $0 <command> [args]"
    echo ""
    echo "Commands:"
    echo "  verify <package> [signature] [hash]   Verify an update package"
    echo "  manifest <version>                    Create release manifest"
    echo "  sign <file>                           Sign a file with signing key"
    echo ""
    echo "Examples:"
    echo "  $0 verify falconx-0.2.0.tar.gz falconx-0.2.0.sig"
    echo "  $0 manifest 0.2.0"
}

main() {
    local cmd="${1:-}"
    shift || true

    check_root

    case "$cmd" in
        verify)
            local pkg="${1:-}"
            local sig="${2:-}"
            local hash="${3:-}"
            verify_update "$pkg" "$sig" "$hash"
            ;;
        manifest)
            local ver="${1:-}"
            if [[ -z "$ver" ]]; then
                error "Version required"
                exit 1
            fi
            create_manifest "$ver"
            ;;
        sign)
            local file="${1:-}"
            if [[ -z "$file" ]]; then
                error "File to sign required"
                exit 1
            fi
            if [[ ! -f "$SECRETS_DIR/signing.key" ]]; then
                error "Signing key not found"
                exit 1
            fi
            openssl pkeyutl -sign \
                -inkey "$SECRETS_DIR/signing.key" \
                -in "$file" \
                -out "${file}.sig"
            log "Signed: ${file}.sig"
            ;;
        *)
            usage
            exit 1
            ;;
    esac
}

main "$@"
