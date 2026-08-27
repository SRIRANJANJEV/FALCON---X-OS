#!/bin/bash
# FALCON-X Network Lab Tests
# Safe synthetic traffic tests using localhost
# NEVER tests against public systems

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

PASS=0 FAIL=0 SKIP=0

pass() { echo -e "  ${GREEN}✓${NC} $*"; ((PASS++)); }
fail() { echo -e "  ${RED}✗${NC} $*"; ((FAIL++)); }
skip() { echo -e "  ${YELLOW}—${NC} $*"; ((SKIP++)); }

echo "FALCON-X Network Lab Tests (localhost only)"
echo "============================================="
echo ""

# ── Pre-flight ────────────────────────────────────────────────────
echo "Pre-flight"
if command -v python3 > /dev/null 2>&1; then
    pass "python3 available"
else
    skip "python3 not available"
    echo "Cannot run network tests without python3"
    exit 0
fi

if command -v curl > /dev/null 2>&1; then
    pass "curl available"
else
    skip "curl not available"
fi

# ── 1. Engine Health ──────────────────────────────────────────────
echo "1. Engine Health"
if curl -sf http://127.0.0.1:9100/health > /dev/null 2>&1; then
    pass "Engine health endpoint responding"
    local health
    health=$(curl -sf http://127.0.0.1:9100/health 2>/dev/null)
    echo "$health" | grep -q '"status"' && pass "Engine status field present" || fail "Engine status field missing"
    echo "$health" | grep -q '"protection_state"' && pass "Protection state in health" || fail "Protection state missing"
else
    skip "Engine not running"
fi

# ── 2. Engine Stats ──────────────────────────────────────────────
echo "2. Engine Stats"
if curl -sf http://127.0.0.1:9100/stats > /dev/null 2>&1; then
    local stats
    stats=$(curl -sf http://127.0.0.1:9100/stats 2>/dev/null)
    echo "$stats" | grep -q '"capture"' && pass "Capture stats present" || fail "Capture stats missing"
    echo "$stats" | grep -q '"features"' && pass "Features stats present" || fail "Features stats missing"
    echo "$stats" | grep -q '"baseline"' && pass "Baseline stats present" || fail "Baseline stats missing"
    echo "$stats" | grep -q '"rules"' && pass "Rules stats present" || fail "Rules stats missing"
    echo "$stats" | grep -q '"ml"' && pass "ML stats present" || fail "ML stats missing"
    echo "$stats" | grep -q '"enforcement"' && pass "Enforcement stats present" || fail "Enforcement stats missing"
    echo "$stats" | grep -q '"protection_state"' && pass "Protection state in stats" || fail "Protection state missing"
else
    skip "Engine not running"
fi

# ── 3. Dashboard Health ──────────────────────────────────────────
echo "3. Dashboard Health"
if curl -sf http://127.0.0.1:8443/health --insecure > /dev/null 2>&1; then
    pass "Dashboard health endpoint responding"
else
    skip "Dashboard not running"
fi

# ── 4. Dashboard Login ───────────────────────────────────────────
echo "4. Dashboard Authentication"
if curl -sf https://127.0.0.1:8443/ --insecure > /dev/null 2>&1; then
    pass "Dashboard login page accessible"
    local login_page
    login_page=$(curl -sf https://127.0.0.1:8443/ --insecure 2>/dev/null)
    echo "$login_page" | grep -q "FALCON-X" && pass "Login page contains FALCON-X" || fail "Login page missing FALCON-X"
else
    skip "Dashboard not running"
fi

# ── 5. API Authentication ────────────────────────────────────────
echo "5. API Authentication"
if curl -sf https://127.0.0.1:8443/api/status --insecure > /dev/null 2>&1; then
    fail "API accessible without auth (should require login)"
else
    pass "API requires authentication"
fi

# ── 6. Incident Endpoint ─────────────────────────────────────────
echo "6. Incident Endpoint"
if curl -sf http://127.0.0.1:9100/incidents > /dev/null 2>&1; then
    pass "Incidents endpoint responding"
    local incidents
    incidents=$(curl -sf http://127.0.0.1:9100/incidents 2>/dev/null)
    echo "$incidents" | grep -q "incident_id\|risk_score\|severity" && pass "Incident fields present" || fail "Incident fields missing"
else
    skip "Engine not running"
fi

# ── 7. Firewall Active ───────────────────────────────────────────
echo "7. Firewall"
if command -v nft > /dev/null 2>&1; then
    nft list ruleset 2>/dev/null | grep -q "falconx_filter" && pass "nftables falconx_filter active" || fail "nftables falconx_filter not active"
else
    skip "nftables not available"
fi

# ── 8. Protection State ──────────────────────────────────────────
echo "8. Protection State"
if [[ -f /var/lib/falconx/protection-state.json ]]; then
    pass "Protection state file exists"
    local ps
    ps=$(cat /var/lib/falconx/protection-state.json 2>/dev/null)
    echo "$ps" | grep -q '"state"' && pass "State field present" || fail "State field missing"
else
    skip "Protection state file not found"
fi

# ── Summary ───────────────────────────────────────────────────────
echo ""
echo "=============================="
echo "Results: $PASS passed, $FAIL failed, $SKIP skipped"
echo ""

if [[ $FAIL -eq 0 ]] && [[ $PASS -gt 0 ]]; then
    echo -e "${GREEN}All network tests passed!${NC}"
elif [[ $PASS -eq 0 ]]; then
    echo -e "${YELLOW}All tests skipped (services not running)${NC}"
else
    echo -e "${RED}$FAIL test(s) failed${NC}"
fi

exit $FAIL
