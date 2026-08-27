#!/bin/bash
# FALCON-X First Boot Validation
# Validates that first-boot completed successfully

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

PASS=0
FAIL=0
WARN=0

pass() { echo -e "  ${GREEN}✓${NC} $*"; ((PASS++)); }
fail() { echo -e "  ${RED}✗${NC} $*"; ((FAIL++)); }
warn() { echo -e "  ${YELLOW}!${NC} $*"; ((WARN++)); }

echo "FALCON-X First Boot Validation"
echo "=============================="
echo ""

# ── Marker ────────────────────────────────────────────────────────
echo "1. First Boot Marker"
if [[ -f /var/lib/falconx/.first-boot-done ]]; then
    pass "Marker exists ($(cat /var/lib/falconx/.first-boot-done))"
else
    fail "Marker missing — first boot not completed"
fi

# ── Device Identity ──────────────────────────────────────────────
echo "2. Device Identity"
if [[ -f /var/lib/falconx/device-id ]]; then
    local device_id
    device_id=$(cat /var/lib/falconx/device-id)
    if [[ ${#device_id} -ge 8 ]]; then
        pass "Device ID: $device_id"
    else
        fail "Device ID too short: $device_id"
    fi
else
    fail "Device ID missing"
fi

# ── Service Users ────────────────────────────────────────────────
echo "3. Service Users"
for user in falconx-engine falconx-web; do
    if id "$user" > /dev/null 2>&1; then
        local shell
        shell=$(getent passwd "$user" | cut -d: -f7)
        if [[ "$shell" == "/usr/sbin/nologin" ]]; then
            pass "$user (nologin)"
        else
            fail "$user shell is $shell (should be nologin)"
        fi
    else
        fail "User $user missing"
    fi
done

# ── Directories ──────────────────────────────────────────────────
echo "4. Directories"
for dir in /opt/falconx /etc/falconx /var/lib/falconx /var/log/falconx /etc/falconx/secrets; do
    if [[ -d "$dir" ]]; then
        pass "$dir exists"
    else
        fail "$dir missing"
    fi
done

# ── Permissions ──────────────────────────────────────────────────
echo "5. Permissions"
# Secrets directory
local perms
perms=$(stat -c "%a" /etc/falconx/secrets 2>/dev/null || echo "xxx")
if [[ "$perms" == "700" ]]; then
    pass "Secrets: 700"
else
    fail "Secrets: $perms (should be 700)"
fi

# Config files
local config_ok=true
for f in /etc/falconx/*.yaml; do
    [[ -f "$f" ]] || continue
    perms=$(stat -c "%a" "$f" 2>/dev/null || echo "xxx")
    if [[ "$perms" != "644" ]]; then
        config_ok=false
    fi
done
$config_ok && pass "Config files: 644" || fail "Config files: incorrect permissions"

# Secret files
local secret_ok=true
for f in /etc/falconx/secrets/*; do
    [[ -f "$f" ]] || continue
    perms=$(stat -c "%a" "$f" 2>/dev/null || echo "xxx")
    if [[ "$perms" != "600" ]]; then
        secret_ok=false
    fi
done
$secret_ok && pass "Secret files: 600" || fail "Secret files: incorrect permissions"

# ── TLS ──────────────────────────────────────────────────────────
echo "6. TLS"
if [[ -f /etc/falconx/secrets/server.crt && -f /etc/falconx/secrets/server.key ]]; then
    pass "TLS certificate and key exist"
    # Check key permissions
    perms=$(stat -c "%a" /etc/falconx/secrets/server.key 2>/dev/null || echo "xxx")
    [[ "$perms" == "600" ]] && pass "TLS key: 600" || fail "TLS key: $perms"
else
    warn "TLS certificate not generated"
fi

# ── Dashboard Credentials ────────────────────────────────────────
echo "7. Dashboard Credentials"
if [[ -f /etc/falconx/web-users.json ]]; then
    pass "User file exists"
    perms=$(stat -c "%a" /etc/falconx/web-users.json 2>/dev/null || echo "xxx")
    [[ "$perms" == "600" ]] && pass "User file: 600" || fail "User file: $perms"
else
    fail "User file missing"
fi

if [[ -f /etc/falconx/initial-password.txt ]]; then
    pass "Initial password file exists"
    perms=$(stat -c "%a" /etc/falconx/initial-password.txt 2>/dev/null || echo "xxx")
    [[ "$perms" == "600" ]] && pass "Password file: 600" || fail "Password file: $perms"
else
    fail "Initial password file missing"
fi

# ── nftables ─────────────────────────────────────────────────────
echo "8. Firewall"
if command -v nft > /dev/null 2>&1; then
    if nft list ruleset 2>/dev/null | grep -q "falconx_filter"; then
        pass "nftables rules loaded"
    else
        fail "nftables rules not loaded"
    fi

    if nft list ruleset 2>/dev/null | grep -q "policy drop"; then
        pass "INPUT policy: DROP"
    else
        fail "INPUT policy: not DROP"
    fi
else
    warn "nftables not available"
fi

# ── AppArmor ─────────────────────────────────────────────────────
echo "9. AppArmor"
if command -v apparmor_parser > /dev/null 2>&1; then
    for profile in falconx-engine falconx-web; do
        if [[ -f "/etc/apparmor.d/$profile" ]]; then
            pass "Profile $profile exists"
        else
            warn "Profile $profile missing"
        fi
    done
else
    warn "AppArmor not available"
fi

# ── Sysctl ───────────────────────────────────────────────────────
echo "10. Sysctl"
if [[ -f /etc/sysctl.d/99-falconx-hardening.conf ]]; then
    pass "Sysctl config exists"
else
    warn "Sysctl config missing"
fi

# ── systemd Services ─────────────────────────────────────────────
echo "11. Services"
for svc in falconx-engine falconx-web falconx-health falconx-enforcer; do
    if systemctl is-enabled "${svc}.service" > /dev/null 2>&1; then
        pass "$svc enabled"
    else
        fail "$svc not enabled"
    fi
done

# ── Health ───────────────────────────────────────────────────────
echo "12. Health"
if curl -sf http://127.0.0.1:9100/health > /dev/null 2>&1; then
    pass "Engine responding"
else
    warn "Engine not responding"
fi

if curl -sf http://127.0.0.1:8443/health > /dev/null 2>&1; then
    pass "Dashboard responding"
else
    warn "Dashboard not responding"
fi

# ── Summary ──────────────────────────────────────────────────────
echo ""
echo "=============================="
echo "Results: $PASS passed, $FAIL failed, $WARN warnings"
echo ""

if [[ $FAIL -eq 0 ]]; then
    echo -e "${GREEN}First boot validation: PASS${NC}"
else
    echo -e "${RED}First boot validation: FAIL ($FAIL issues)${NC}"
fi

exit $FAIL
