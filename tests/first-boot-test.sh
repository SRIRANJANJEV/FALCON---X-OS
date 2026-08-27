#!/bin/bash
# FALCON-X First Boot Tests
# Tests first-boot logic without requiring root or hardware

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

PASS=0
FAIL=0
SKIP=0

pass() { echo -e "  ${GREEN}✓ PASS${NC} $*"; ((PASS++)); }
fail() { echo -e "  ${RED}✗ FAIL${NC} $*"; ((FAIL++)); }
skip() { echo -e "  ${YELLOW}— SKIP${NC} $*"; ((SKIP++)); }

echo "FALCON-X First Boot Tests"
echo "========================="
echo ""

# ── 1. Script Syntax ─────────────────────────────────────────────
echo "1. Script Syntax"

if bash -n opt/falconx/scripts/first-boot.sh 2>/dev/null; then
    pass "first-boot.sh syntax valid"
else
    fail "first-boot.sh syntax error"
fi

if bash -n opt/falconx/scripts/first-boot-validate.sh 2>/dev/null; then
    pass "first-boot-validate.sh syntax valid"
else
    fail "first-boot-validate.sh syntax error"
fi

# ── 2. No iptables References ────────────────────────────────────
echo "2. No iptables in first-boot"

if ! grep -q "iptables" opt/falconx/scripts/first-boot.sh; then
    pass "No iptables in first-boot.sh"
else
    fail "iptables found in first-boot.sh"
fi

# ── 3. nftables Only ─────────────────────────────────────────────
echo "3. nftables Configuration"

if grep -q "nft" opt/falconx/scripts/first-boot.sh; then
    pass "nftables referenced in first-boot.sh"
else
    fail "nftables not referenced"
fi

if [[ -f etc/nftables/falconx-monitor.nft ]]; then
    pass "Monitor firewall rules exist"
else
    fail "Monitor firewall rules missing"
fi

if grep -q "policy drop" etc/nftables/falconx-monitor.nft; then
    pass "Firewall: INPUT DROP policy"
else
    fail "Firewall: missing INPUT DROP"
fi

# ── 4. Systemd Service ──────────────────────────────────────────
echo "4. First Boot Service"

if [[ -f etc/systemd/system/falconx-first-boot.service ]]; then
    pass "first-boot.service exists"

    if grep -q "Type=oneshot" etc/systemd/system/falconx-first-boot.service; then
        pass "Service type: oneshot"
    else
        fail "Service type not oneshot"
    fi

    if grep -q "Before=falconx-engine.service" etc/systemd/system/falconx-first-boot.service; then
        pass "Service starts before engine"
    else
        fail "Service ordering missing"
    fi

    if grep -q "RemainAfterExit=yes" etc/systemd/system/falconx-first-boot.service; then
        pass "Service remains after exit"
    else
        fail "Service RemainAfterExit not set"
    fi
else
    fail "first-boot.service missing"
fi

# ── 5. Idempotency ───────────────────────────────────────────────
echo "5. Idempotency"

if grep -q "check_already_done" opt/falconx/scripts/first-boot.sh; then
    pass "Idempotency check present"
else
    fail "Idempotency check missing"
fi

if grep -q "FALCONX_MARKER" opt/falconx/scripts/first-boot.sh; then
    pass "Marker file referenced"
else
    fail "Marker file not referenced"
fi

# ── 6. Error Handling ────────────────────────────────────────────
echo "6. Error Handling"

if grep -q "critical_step" opt/falconx/scripts/first-boot.sh; then
    pass "Critical step function defined"
else
    fail "Critical step function missing"
fi

if grep -q "CRITICAL_FAILED" opt/falconx/scripts/first-boot.sh; then
    pass "Critical failure tracking"
else
    fail "Critical failure tracking missing"
fi

if grep -q "exit 1" opt/falconx/scripts/first-boot.sh; then
    pass "Exit on critical failure"
else
    fail "No exit on critical failure"
fi

# ── 7. Security ──────────────────────────────────────────────────
echo "7. Security"

# Check no password in stdout
if ! grep -q "Generated admin password" opt/falconx/scripts/first-boot.sh; then
    pass "No password printed to stdout"
else
    fail "Password printed to stdout (security issue)"
fi

# Check secrets are 600
if grep -q "chmod 600" opt/falconx/scripts/first-boot.sh; then
    pass "Secrets set to 600"
else
    fail "Secrets permissions not set"
fi

# Check secrets dir is 700
if grep -q "chmod 700.*secrets" opt/falconx/scripts/first-boot.sh; then
    pass "Secrets directory set to 700"
else
    fail "Secrets directory permissions not set"
fi

# ── 8. AppArmor ──────────────────────────────────────────────────
echo "8. AppArmor Integration"

if grep -q "configure_apparmor" opt/falconx/scripts/first-boot.sh; then
    pass "AppArmor configuration in first-boot"
else
    fail "AppArmor not configured in first-boot"
fi

if grep -q "apparmor_parser" opt/falconx/scripts/first-boot.sh; then
    pass "AppArmor parser used"
else
    fail "AppArmor parser not used"
fi

# ── 9. Sysctl ────────────────────────────────────────────────────
echo "9. Sysctl Integration"

if grep -q "apply_sysctl" opt/falconx/scripts/first-boot.sh; then
    pass "Sysctl application in first-boot"
else
    fail "Sysctl not applied in first-boot"
fi

if [[ -f etc/sysctl.d/99-falconx-hardening.conf ]]; then
    pass "Sysctl hardening config exists"
else
    fail "Sysctl hardening config missing"
fi

# ── 10. Health Check ─────────────────────────────────────────────
echo "10. Health Check"

if grep -q "run_health_check" opt/falconx/scripts/first-boot.sh; then
    pass "Health check in first-boot"
else
    fail "Health check not in first-boot"
fi

# ── 11. Service Users ────────────────────────────────────────────
echo "11. Service Users"

if grep -q "nologin" opt/falconx/scripts/first-boot.sh; then
    pass "Service users use nologin"
else
    fail "Service users may have login shell"
fi

# ── 12. TLS Generation ──────────────────────────────────────────
echo "12. TLS Generation"

if grep -q "generate_tls_certificate" opt/falconx/scripts/first-boot.sh; then
    pass "TLS generation in first-boot"
else
    fail "TLS generation not in first-boot"
fi

if grep -q "openssl" opt/falconx/scripts/first-boot.sh; then
    pass "OpenSSL used for TLS"
else
    fail "OpenSSL not used"
fi

# ── Summary ──────────────────────────────────────────────────────
echo ""
echo "=============================="
echo "Results: $PASS passed, $FAIL failed, $SKIP skipped"
echo ""

if [[ $FAIL -eq 0 ]]; then
    echo -e "${GREEN}All first-boot tests passed!${NC}"
else
    echo -e "${RED}$FAIL test(s) failed${NC}"
fi

exit $FAIL
