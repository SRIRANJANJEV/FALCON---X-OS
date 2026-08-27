#!/bin/bash
# FALCON-X Image Builder
# Builds a reproducible Raspberry Pi OS image with FALCON-X pre-installed
#
# Usage:
#   sudo ./build-image.sh [--dev] [--output falconx-os.img] [--base <path>]
#   sudo ./build-image.sh --validate falconx-os.img
#
# Build host: Linux (Debian/Ubuntu), root required
# Target: Raspberry Pi 4, ARM64, Raspberry Pi OS Lite 64-bit

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BUILD_DIR="/tmp/falconx-build"
OUTPUT_DIR="${PROJECT_ROOT}/output"
OUTPUT_IMG="falconx-os.img"
DEV_MODE=false
VALIDATE_IMG=""
SKIP_DOWNLOAD=false
BASE_IMAGE=""
FALCONX_VERSION="0.2.0"

# Loop device tracking for cleanup
LOOP_DEV=""
MOUNT_POINT=""

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

log()  { echo -e "${CYAN}[BUILD]${NC} $*"; }
ok()   { echo -e "${GREEN}[BUILD]${NC} $*"; }
warn() { echo -e "${YELLOW}[BUILD]${NC} $*"; }
err()  { echo -e "${RED}[BUILD]${NC} $*" >&2; }

# ── Cleanup on failure ────────────────────────────────────────────

cleanup_on_exit() {
    local exit_code=$?
    if [[ $exit_code -ne 0 ]]; then
        err "Build failed (exit code $exit_code)"
    fi

    # Unmount if mounted
    if [[ -n "$MOUNT_POINT" ]]; then
        sync 2>/dev/null || true
        umount "$MOUNT_POINT/root" 2>/dev/null || true
        umount "$MOUNT_POINT/boot" 2>/dev/null || true
        rm -rf "$MOUNT_POINT" 2>/dev/null || true
    fi

    # Detach loop device
    if [[ -n "$LOOP_DEV" ]]; then
        losetup -d "$LOOP_DEV" 2>/dev/null || true
    fi

    # Clean build dir
    rm -rf "$BUILD_DIR" 2>/dev/null || true
}

trap cleanup_on_exit EXIT

# ── Usage ─────────────────────────────────────────────────────────

usage() {
    cat << EOF
FALCON-X Image Builder v${FALCONX_VERSION}

Usage: sudo $0 [options]

Options:
  --dev               Build in development mode (writable root)
  --output <path>     Output image path (default: output/falconx-os.img)
  --base <path>       Use local base image (.img or .img.xz)
  --validate <img>    Validate an existing image
  -h, --help          Show this help

Build Host Requirements (Debian/Ubuntu):
  sudo apt install parted losetup e2fsprogs dosfstools \\
      qemu-user-static binfmt-support rsync xz-utils

Example:
  # Download Raspberry Pi OS Lite 64-bit from:
  # https://www.raspberrypi.com/software/operating-systems/
  # Place .img.xz in /tmp/falconx-build/

  sudo $0 --base /tmp/falconx-build/2024-03-15-raspios-bookworm-arm64-lite.img.xz
  sudo $0 --validate output/falconx-os.img
EOF
}

# ── Dependency check ──────────────────────────────────────────────

check_dependencies() {
    local missing=0
    local deps=("parted" "losetup" "mkfs.vfat" "mkfs.ext4" "rsync" "sha256sum" "xz")

    for dep in "${deps[@]}"; do
        if ! command -v "$dep" > /dev/null 2>&1; then
            err "Required dependency missing: $dep"
            ((missing++))
        fi
    done

    if [[ $missing -gt 0 ]]; then
        err "Install missing dependencies:"
        err "  sudo apt install parted e2fsprogs dosfstools rsync xz-utils"
        exit 1
    fi

    # Optional but recommended
    for dep in qemu-user-static binfmt-support; do
        if ! command -v "$dep" > /dev/null 2>&1; then
            warn "Optional dependency missing: $dep (needed for chroot)"
        fi
    done
}

# ── Architecture validation ───────────────────────────────────────

validate_image_arch() {
    local img="$1"
    log "Validating image architecture..."

    # Check file magic to identify image type
    local magic
    magic=$(file -b "$img" 2>/dev/null | head -1)

    if echo "$magic" | grep -qi "arm\|aarch64\|raw disk\|boot sector"; then
        ok "Image appears valid: $magic"
    else
        warn "Image type: $magic — cannot verify ARM64 without inspection"
    fi

    # Check minimum size (Raspberry Pi OS Lite is ~1GB)
    local size
    size=$(stat -c%s "$img" 2>/dev/null || echo "0")
    if [[ $size -lt 500000000 ]]; then
        err "Image too small (${size} bytes) — not a valid Raspberry Pi OS image"
        exit 1
    fi

    ok "Image size: $((size / 1024 / 1024))MB"
}

# ── Base image preparation ────────────────────────────────────────

prepare_base_image() {
    log "Preparing base image..."

    mkdir -p "$BUILD_DIR"
    local img_path="$BUILD_DIR/falconx-base.img"

    # If --base specified, use that
    if [[ -n "$BASE_IMAGE" ]]; then
        if [[ ! -f "$BASE_IMAGE" ]]; then
            err "Base image not found: $BASE_IMAGE"
            exit 1
        fi
        log "Using provided base image: $BASE_IMAGE"

        # Decompress if needed
        if [[ "$BASE_IMAGE" == *.xz ]]; then
            log "Decompressing..."
            xz -dk "$BASE_IMAGE"
            BASE_IMAGE="${BASE_IMAGE%.xz}"
        fi

        validate_image_arch "$BASE_IMAGE"
        cp "$BASE_IMAGE" "$img_path"
        echo "$img_path"
        return
    fi

    # Look for existing image in build dir
    local found
    found=$(find "$BUILD_DIR" -maxdepth 1 -name "*.img" -o -name "*.img.xz" 2>/dev/null | head -1)

    if [[ -n "$found" ]]; then
        log "Found base image: $found"
        if [[ "$found" == *.xz ]]; then
            log "Decompressing..."
            xz -dk "$found"
            found="${found%.xz}"
        fi
        validate_image_arch "$found"
        cp "$found" "$img_path"
        echo "$img_path"
        return
    fi

    if [[ "$SKIP_DOWNLOAD" == "true" ]]; then
        err "No base image available and download skipped"
        exit 1
    fi

    err "No base image found."
    err ""
    err "Please download Raspberry Pi OS Lite 64-bit from:"
    err "  https://www.raspberrypi.com/software/operating-systems/"
    err ""
    err "Place the .img.xz file in: $BUILD_DIR/"
    err "Or use: $0 --base <path-to-image>"
    exit 1
}

# ── Partition setup ───────────────────────────────────────────────

setup_partitions() {
    local img="$1"
    log "Creating partition table..."

    # Resize image to 4GB
    truncate -s 4G "$img"

    # Create MBR partition table
    parted -s "$img" mklabel msdos

    # Boot partition: 256MB FAT32
    parted -s "$img" mkpart primary fat32 1MiB 256MiB

    # Root partition: remaining ext4
    parted -s "$img" mkpart primary ext4 256MiB 100%

    log "Partitions created"

    # Setup loop device
    LOOP_DEV=$(losetup -fP --show "$img")
    if [[ -z "$LOOP_DEV" ]]; then
        err "Failed to setup loop device"
        exit 1
    fi

    log "Loop device: $LOOP_DEV"

    # Wait for partition devices to appear
    local retries=10
    while [[ $retries -gt 0 ]]; do
        if [[ -b "${LOOP_DEV}p1" && -b "${LOOP_DEV}p2" ]]; then
            break
        fi
        sleep 1
        ((retries--))
    done

    if [[ ! -b "${LOOP_DEV}p1" || ! -b "${LOOP_DEV}p2" ]]; then
        err "Partition devices not found after waiting"
        exit 1
    fi

    # Format partitions
    log "Formatting boot partition (FAT32)..."
    mkfs.vfat -F 32 -n BOOT "${LOOP_DEV}p1"

    log "Formatting root partition (ext4)..."
    mkfs.ext4 -F -L rootfs "${LOOP_DEV}p2"

    log "Partitions formatted"
}

# ── Mount ─────────────────────────────────────────────────────────

mount_image() {
    local loop_dev="$1"
    MOUNT_POINT="$BUILD_DIR/mount"

    log "Mounting partitions..."
    mkdir -p "$MOUNT_POINT/boot" "$MOUNT_POINT/root"

    mount "${loop_dev}p1" "$MOUNT_POINT/boot" || {
        err "Failed to mount boot partition"
        exit 1
    }

    mount "${loop_dev}p2" "$MOUNT_POINT/root" || {
        err "Failed to mount root partition"
        umount "$MOUNT_POINT/boot" 2>/dev/null || true
        exit 1
    }

    log "Partitions mounted"
}

# ── FALCON-X installation ────────────────────────────────────────

install_falconx() {
    local root="$1"
    log "Installing FALCON-X..."

    # Application directories
    mkdir -p "$root/opt/falconx"/{engine,dashboard/static,models,scripts,config,bin}
    mkdir -p "$root/etc/falconx"/{secrets,nftables,ssh/sshd_config.d,sysctl.d,apparmor.d,logrotate.d,rsyslog.d}
    mkdir -p "$root/etc/systemd/system"
    mkdir -p "$root/var/lib/falconx"/{baseline,incidents}
    mkdir -p "$root/var/log/falconx/security"
    mkdir -p "$root/usr/local/bin"
    mkdir -p "$root/run/falconx"

    # Copy application files
    rsync -a "$PROJECT_ROOT/opt/falconx/" "$root/opt/falconx/"

    # Copy configuration
    rsync -a "$PROJECT_ROOT/etc/falconx/" "$root/etc/falconx/"

    # System configuration
    cp "$PROJECT_ROOT/etc/systemd/system/"falconx-*.service "$root/etc/systemd/system/" 2>/dev/null || true
    cp "$PROJECT_ROOT/etc/nftables/"*.nft "$root/etc/nftables/" 2>/dev/null || true
    cp "$PROJECT_ROOT/etc/apparmor.d/"falconx-* "$root/etc/apparmor.d/" 2>/dev/null || true
    cp "$PROJECT_ROOT/etc/sysctl.d/"*.conf "$root/etc/sysctl.d/" 2>/dev/null || true
    cp "$PROJECT_ROOT/etc/ssh/sshd_config.d/"*.conf "$root/etc/ssh/sshd_config.d/" 2>/dev/null || true
    cp "$PROJECT_ROOT/etc/logrotate.d/"falconx "$root/etc/logrotate.d/" 2>/dev/null || true
    cp "$PROJECT_ROOT/etc/rsyslog.d/"*.conf "$root/etc/rsyslog.d/" 2>/dev/null || true

    # Scripts
    cp "$PROJECT_ROOT/opt/falconx/scripts/"*.sh "$root/opt/falconx/scripts/" 2>/dev/null || true
    cp "$PROJECT_ROOT/opt/falconx/scripts/"*.py "$root/opt/falconx/scripts/" 2>/dev/null || true

    # CLI
    cp "$PROJECT_ROOT/opt/falconx/bin/falconx" "$root/usr/local/bin/falconx"
    chmod +x "$root/usr/local/bin/falconx"

    # Set permissions
    find "$root/opt/falconx" -name "*.py" -exec chmod 755 {} \;
    find "$root/opt/falconx" -name "*.sh" -exec chmod 755 {} \;

    ok "FALCON-X files installed"
}

# ── OS configuration ──────────────────────────────────────────────

configure_os() {
    local root="$1"
    log "Configuring OS..."

    echo "falconx" > "$root/etc/hostname"
    echo "UTC" > "$root/etc/timezone"

    # Disable unnecessary services
    for svc in bluetooth cups avahi-daemon triggerhappy; do
        mkdir -p "$root/etc/systemd/system/${svc}.service.d"
        cat > "$root/etc/systemd/system/${svc}.service.d/disable.conf" << 'EOF'
[Install]
WantedBy=
EOF
    done

    # Enable FALCON-X services
    for svc in falconx-engine falconx-web falconx-health falconx-enforcer; do
        if [[ -f "$root/etc/systemd/system/${svc}.service" ]]; then
            ln -sf "/etc/systemd/system/${svc}.service" \
                "$root/etc/systemd/system/multi-user.target.wants/${svc}.service" 2>/dev/null || true
        fi
    done

    ok "OS configured"
}

# ── First boot ────────────────────────────────────────────────────

setup_first_boot() {
    local root="$1"
    log "Setting up first boot..."

    # Install first-boot service
    if [[ -f "$PROJECT_ROOT/etc/systemd/system/falconx-first-boot.service" ]]; then
        cp "$PROJECT_ROOT/etc/systemd/system/falconx-first-boot.service" "$root/etc/systemd/system/"
    else
        cat > "$root/etc/systemd/system/falconx-first-boot.service" << 'EOF'
[Unit]
Description=FALCON-X First Boot Setup
After=network-online.target
Wants=network-online.target
Before=falconx-engine.service falconx-web.service falconx-health.service falconx-enforcer.service

[Service]
Type=oneshot
ExecStart=/opt/falconx/scripts/first-boot.sh
RemainAfterExit=yes
StandardOutput=journal
StandardError=journal
SyslogIdentifier=falconx-first-boot

ProtectHome=true
ProtectSystem=full
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF
    fi

    ln -sf "/etc/systemd/system/falconx-first-boot.service" \
        "$root/etc/systemd/system/multi-user.target.wants/falconx-first-boot.service"

    ok "First boot configured"
}

# ── Cleanup build artifacts ───────────────────────────────────────

cleanup_build() {
    local loop_dev="$1"
    local mount_point="$2"

    log "Cleaning up..."
    sync

    umount "$mount_point/root" 2>/dev/null || true
    umount "$mount_point/boot" 2>/dev/null || true
    rm -rf "$mount_point" 2>/dev/null || true
    losetup -d "$loop_dev" 2>/dev/null || true

    LOOP_DEV=""
    MOUNT_POINT=""

    ok "Cleanup complete"
}

# ── Image generation ──────────────────────────────────────────────

generate_image() {
    local img="$1"
    local output="$OUTPUT_DIR/$OUTPUT_IMG"

    mkdir -p "$OUTPUT_DIR"

    log "Generating final image..."
    cp "$img" "$output"

    # Generate checksums
    log "Generating checksums..."
    cd "$OUTPUT_DIR"
    sha256sum "$OUTPUT_IMG" > "${OUTPUT_IMG}.sha256"
    sha512sum "$OUTPUT_IMG" > "${OUTPUT_IMG}.sha512"

    # Generate version metadata
    cat > "${OUTPUT_IMG}.meta.json" << EOF
{
    "version": "${FALCONX_VERSION}",
    "build_time": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "base_image": "Raspberry Pi OS Lite 64-bit Bookworm",
    "target": "Raspberry Pi 4 ARM64",
    "size_bytes": $(stat -c%s "$OUTPUT_IMG"),
    "sha256": "$(cut -d' ' -f1 "${OUTPUT_IMG}.sha256")",
    "dev_mode": $DEV_MODE,
    "builder": "falconx-os image builder v${FALCONX_VERSION}"
}
EOF

    local size
    size=$(du -h "$output" | cut -f1)

    ok "Image: $output ($size)"
    ok "SHA256: $(cut -d' ' -f1 "${OUTPUT_IMG}.sha256")"
    ok "Metadata: ${OUTPUT_IMG}.meta.json"

    echo ""
    echo -e "${GREEN}╔══════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║    FALCON-X Image Build Complete             ║${NC}"
    echo -e "${GREEN}╠══════════════════════════════════════════════╣${NC}"
    echo -e "${GREEN}║  Image:   $output                           ║${NC}"
    echo -e "${GREEN}║  Size:    $size                              ║${NC}"
    echo -e "${GREEN}║  Version: ${FALCONX_VERSION}                           ║${NC}"
    echo -e "${GREEN}║  Mode:    $([ "$DEV_MODE" = true ] && echo "Development" || echo "Production")                     ║${NC}"
    echo -e "${GREEN}║                                              ║${NC}"
    echo -e "${GREEN}║  Flash: sudo dd if=$output of=/dev/sdX bs=4M ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════╝${NC}"
    echo ""
}

# ── Image validation ──────────────────────────────────────────────

validate_image() {
    local img="$1"
    local pass=0 fail=0

    if [[ ! -f "$img" ]]; then
        err "Image not found: $img"
        return 1
    fi

    echo -e "\n${BOLD}Validating: $img${NC}\n"

    # 1. File size
    local size
    size=$(stat -c%s "$img" 2>/dev/null || echo "0")
    if [[ $size -gt 500000000 ]]; then
        echo -e "  ${GREEN}✓${NC} Size: $((size / 1024 / 1024))MB"
        ((pass++))
    else
        echo -e "  ${RED}✗${NC} Too small: ${size} bytes"
        ((fail++))
    fi

    # 2. Partition table
    if command -v parted > /dev/null 2>&1; then
        local parts
        parts=$(parted -s "$img" print 2>/dev/null | grep -c "primary" || echo "0")
        if [[ $parts -ge 2 ]]; then
            echo -e "  ${GREEN}✓${NC} Partitions: $parts"
            ((pass++))
        else
            echo -e "  ${RED}✗${NC} Expected 2+ partitions, found $parts"
            ((fail++))
        fi
    fi

    # 3. SHA256 checksum
    if [[ -f "${img}.sha256" ]]; then
        local expected actual
        expected=$(cut -d' ' -f1 "${img}.sha256")
        actual=$(sha256sum "$img" | cut -d' ' -f1)
        if [[ "$expected" == "$actual" ]]; then
            echo -e "  ${GREEN}✓${NC} SHA256 valid"
            ((pass++))
        else
            echo -e "  ${RED}✗${NC} SHA256 mismatch"
            ((fail++))
        fi
    fi

    # 4. Mount and check contents
    local vloop vmnt
    vloop=$(losetup -fP --show "$img" 2>/dev/null) || true
    if [[ -n "$vloop" ]]; then
        vmnt="/tmp/falconx-validate-$$"
        mkdir -p "$vmnt"
        mount "${vloop}p2" "$vmnt" 2>/dev/null || { warn "Could not mount for validation"; return $fail; }

        echo ""
        echo -e "${BOLD}Contents check:${NC}"

        # Required files
        for f in \
            /opt/falconx/engine/main.py \
            /opt/falconx/bin/falconx \
            /etc/falconx/falconx.yaml \
            /etc/nftables/falconx-monitor.nft \
            /etc/sysctl.d/99-falconx-hardening.conf \
            /etc/apparmor.d/falconx-engine \
            /etc/apparmor.d/falconx-web \
            /etc/ssh/sshd_config.d/falconx-hardened.conf \
            /opt/falconx/scripts/first-boot.sh \
            /etc/systemd/system/falconx-first-boot.service; do
            if [[ -f "$vmnt$f" ]]; then
                echo -e "  ${GREEN}✓${NC} $f"
                ((pass++))
            else
                echo -e "  ${RED}✗${NC} Missing: $f"
                ((fail++))
            fi
        done

        # Systemd services
        echo ""
        echo -e "${BOLD}Systemd services:${NC}"
        for svc in falconx-engine falconx-web falconx-health falconx-enforcer falconx-first-boot; do
            if [[ -f "$vmnt/etc/systemd/system/${svc}.service" ]]; then
                echo -e "  ${GREEN}✓${NC} ${svc}.service"
                ((pass++))
            else
                echo -e "  ${RED}✗${NC} Missing: ${svc}.service"
                ((fail++))
            fi
        done

        # No stub services
        echo ""
        echo -e "${BOLD}Stub service check:${NC}"
        for stub in falconx-detector.service falconx-ai.service; do
            if [[ -f "$vmnt/etc/systemd/system/$stub" ]]; then
                echo -e "  ${YELLOW}!${NC} Stub present: $stub (should be removed)"
                ((fail++))
            else
                echo -e "  ${GREEN}✓${NC} No stub: $stub"
                ((pass++))
            fi
        done

        # Check first-boot marker does NOT exist
        echo ""
        echo -e "${BOLD}First boot check:${NC}"
        if [[ ! -f "$vmnt/var/lib/falconx/.first-boot-done" ]]; then
            echo -e "  ${GREEN}✓${NC} First-boot marker absent (correct)"
            ((pass++))
        else
            echo -e "  ${RED}✗${NC} First-boot marker exists (should be absent)"
            ((fail++))
        fi

        umount "$vmnt" 2>/dev/null
        rmdir "$vmnt" 2>/dev/null
        losetup -d "$vloop" 2>/dev/null
    fi

    echo ""
    echo -e "${BOLD}═══════════════════════════════════════════════${NC}"
    echo -e "${BOLD}  Validation: $pass passed, $fail failed${NC}"
    echo -e "${BOLD}═══════════════════════════════════════════════${NC}"

    if [[ $fail -eq 0 ]]; then
        echo -e "${GREEN}Image validation: PASS${NC}"
    else
        echo -e "${RED}Image validation: FAIL${NC}"
    fi

    return $fail
}

# ── Argument parsing ──────────────────────────────────────────────

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --dev) DEV_MODE=true; shift ;;
            --output) OUTPUT_IMG="$2"; shift 2 ;;
            --base) BASE_IMAGE="$2"; shift 2 ;;
            --skip-download) SKIP_DOWNLOAD=true; shift ;;
            --validate) VALIDATE_IMG="$2"; shift 2 ;;
            -h|--help) usage; exit 0 ;;
            *) err "Unknown option: $1"; usage; exit 1 ;;
        esac
    done
}

# ── Main ──────────────────────────────────────────────────────────

main() {
    parse_args "$@"

    # Validation mode
    if [[ -n "$VALIDATE_IMG" ]]; then
        validate_image "$VALIDATE_IMG"
        exit $?
    fi

    check_root
    check_dependencies

    echo -e "${CYAN}${BOLD}"
    echo "  FALCON-X Image Builder v${FALCONX_VERSION}"
    echo "  Target: Raspberry Pi 4 ARM64"
    echo -e "${NC}"

    local img_path
    img_path=$(prepare_base_image)

    setup_partitions "$img_path"
    mount_image "$LOOP_DEV"

    install_falconx "$MOUNT_POINT/root"
    configure_os "$MOUNT_POINT/root"
    setup_first_boot "$MOUNT_POINT/root"

    cleanup_build "$LOOP_DEV" "$MOUNT_POINT"
    generate_image "$img_path"

    # Cleanup
    rm -rf "$BUILD_DIR"
}

main "$@"
