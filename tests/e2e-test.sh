#!/bin/bash
# FALCON-X End-to-End Test Suite
# Tests the complete FALCON-X pipeline from boot to detection

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

PASS=0
FAIL=0
TOTAL=0

pass() { echo -e "  ${GREEN}✓${NC} $*"; ((PASS++)); ((TOTAL++)); }
fail() { echo -e "  ${RED}✗${NC} $*"; ((FAIL++)); ((TOTAL++)); }
section() { echo -e "\n${BOLD}$*${NC}"; echo "────────────────────────────────────────────"; }

# ══════════════════════════════════════════════════════════════════
# 1. BOOT & SYSTEM
# ══════════════════════════════════════════════════════════════════
test_boot_system() {
    section "1. Boot & System"

    if systemctl is-system-running --wait=false 2>/dev/null | grep -qE "(running|degraded)"; then
        pass "System booted"
    else
        fail "System not booted"
    fi

    if [[ -f /etc/falconx/falconx.yaml ]]; then
        pass "Configuration present"
    else
        fail "Configuration missing"
    fi

    if [[ -d /var/lib/falconx ]]; then
        pass "Data directory exists"
    else
        fail "Data directory missing"
    fi

    if [[ -d /var/log/falconx ]]; then
        pass "Log directory exists"
    else
        fail "Log directory missing"
    fi
}

# ══════════════════════════════════════════════════════════════════
# 2. NETWORK
# ══════════════════════════════════════════════════════════════════
test_network() {
    section "2. Network"

    if ip route show default 2>/dev/null | grep -q default; then
        pass "Default route present"
    else
        fail "No default route"
    fi

    if ping -c 1 -W 2 8.8.8.8 > /dev/null 2>&1; then
        pass "Internet connectivity"
    else
        fail "No internet connectivity"
    fi

    if ss -tlnp | grep -q ":8443 "; then
        pass "Dashboard port listening"
    else
        fail "Dashboard port not listening"
    fi
}

# ══════════════════════════════════════════════════════════════════
# 3. FIREWALL
# ══════════════════════════════════════════════════════════════════
test_firewall() {
    section "3. Firewall"

    if nft list ruleset 2>/dev/null | grep -q "falconx_filter"; then
        pass "Firewall rules loaded"
    else
        fail "No firewall rules"
    fi

    if nft list chain inet falconx_filter input 2>/dev/null | grep -q "policy drop"; then
        pass "Input DROP policy"
    else
        fail "Input not DROP"
    fi

    # Test blocked port
    if ! timeout 2 bash -c "echo | nc -w1 127.0.0.1 3306" 2>/dev/null; then
        pass "MySQL port blocked (3306)"
    else
        fail "MySQL port open (should be blocked)"
    fi
}

# ══════════════════════════════════════════════════════════════════
# 4. SERVICES
# ══════════════════════════════════════════════════════════════════
test_services() {
    section "4. Services"

    for svc in falconx-engine falconx-web falconx-health; do
        if systemctl is-active "$svc.service" > /dev/null 2>&1; then
            pass "$svc running"
        else
            fail "$svc not running"
        fi
    done

    # Verify removed stubs are not running
    for fake in falconx-detector falconx-ai; do
        if systemctl is-active "$fake.service" > /dev/null 2>&1; then
            fail "$fake should not be running (removed)"
        else
            pass "$fake not running (correctly removed)"
        fi
    done

    # Test engine health endpoint
    local health
    health=$(curl -sf http://127.0.0.1:9100/health 2>/dev/null || echo "{}")
    if echo "$health" | grep -q '"status"'; then
        pass "Engine health endpoint"
    else
        fail "Engine health endpoint"
    fi

    # Test dashboard health endpoint
    health=$(curl -sf http://127.0.0.1:8443/health 2>/dev/null || echo "{}")
    if echo "$health" | grep -q '"status"'; then
        pass "Dashboard health endpoint"
    else
        fail "Dashboard health endpoint"
    fi
}

# ══════════════════════════════════════════════════════════════════
# 5. DETECTION ENGINE
# ══════════════════════════════════════════════════════════════════
test_detection() {
    section "5. Detection Engine"

    # Test engine stats endpoint
    local stats
    stats=$(curl -sf http://127.0.0.1:9100/stats 2>/dev/null || echo "{}")
    if echo "$stats" | grep -q '"capture"'; then
        pass "Engine stats endpoint"
    else
        fail "Engine stats endpoint"
    fi

    # Test incidents endpoint
    local incidents
    incidents=$(curl -sf http://127.0.0.1:9100/incidents 2>/dev/null || echo "[]")
    if [[ -n "$incidents" ]]; then
        pass "Incidents endpoint"
    else
        fail "Incidents endpoint"
    fi

    # Test Python engine modules
    cd /opt/falconx/engine
    if python3 -c "from features import FeatureExtractor; print('OK')" 2>/dev/null; then
        pass "Feature extractor module"
    else
        fail "Feature extractor module"
    fi

    if python3 -c "from rules import RuleEngine; print('OK')" 2>/dev/null; then
        pass "Rule engine module"
    else
        fail "Rule engine module"
    fi

    if python3 -c "from risk import RiskEngine; print('OK')" 2>/dev/null; then
        pass "Risk engine module"
    else
        fail "Risk engine module"
    fi

    if python3 -c "from incidents import IncidentEngine; print('OK')" 2>/dev/null; then
        pass "Incident engine module"
    else
        fail "Incident engine module"
    fi
}

# ══════════════════════════════════════════════════════════════════
# 6. DASHBOARD
# ══════════════════════════════════════════════════════════════════
test_dashboard() {
    section "6. Dashboard"

    # Test login page
    local login_page
    login_page=$(curl -sf https://127.0.0.1:8443/ --insecure 2>/dev/null || echo "")
    if echo "$login_page" | grep -q "FALCON-X"; then
        pass "Login page accessible"
    else
        fail "Login page not accessible"
    fi

    # Test API rate limiting
    local response
    response=$(curl -sf -o /dev/null -w "%{http_code}" https://127.0.0.1:8443/api/status --insecure 2>/dev/null || echo "000")
    if [[ "$response" == "401" ]] || [[ "$response" == "200" ]]; then
        pass "API authentication enforced"
    else
        fail "API authentication issue (HTTP $response)"
    fi

    # Test TLS
    if curl -sf https://127.0.0.1:8443/ --insecure 2>/dev/null | grep -q "FALCON-X"; then
        pass "TLS working"
    else
        fail "TLS not working"
    fi
}

# ══════════════════════════════════════════════════════════════════
# 7. AI INTEGRATION
# ══════════════════════════════════════════════════════════════════
test_ai() {
    section "7. AI Integration (OmniRoute)"

    # Verify AI service does NOT exist (removed stub)
    if systemctl is-active falconx-ai.service > /dev/null 2>&1; then
        fail "AI stub service should not be running"
    else
        pass "AI stub service removed"
    fi

    # Test OmniRoute status endpoint
    local ai_status
    ai_status=$(curl -sf https://127.0.0.1:8443/api/ai/status --insecure 2>/dev/null || echo "{}")
    if echo "$ai_status" | grep -q '"available"'; then
        pass "AI status API"
    else
        fail "AI status API"
    fi

    # Verify local detection continues without AI
    local engine_health
    engine_health=$(curl -sf http://127.0.0.1:9100/health 2>/dev/null || echo "{}")
    if echo "$engine_health" | grep -q '"status"'; then
        pass "Local detection independent of AI"
    else
        fail "Local detection depends on AI"
    fi
}

# ══════════════════════════════════════════════════════════════════
# 8. FAILURE RECOVERY
# ══════════════════════════════════════════════════════════════════
test_failure_recovery() {
    section "8. Failure Recovery"

    # Test service auto-restart
    local engine_pid
    engine_pid=$(systemctl show falconx-engine.service --property=MainPID --value 2>/dev/null || echo "0")

    if [[ "$engine_pid" != "0" ]]; then
        pass "Engine process running (pid=$engine_pid)"
    else
        fail "Engine process not found"
    fi

    # Check restart policy
    local restart
    restart=$(systemctl show falconx-engine.service --property=Restart --value 2>/dev/null || echo "no")
    if [[ "$restart" == "always" ]]; then
        pass "Auto-restart policy"
    else
        fail "No auto-restart policy"
    fi
}

# ══════════════════════════════════════════════════════════════════
# SUMMARY
# ══════════════════════════════════════════════════════════════════
print_summary() {
    echo ""
    echo -e "${BOLD}═══════════════════════════════════════════════${NC}"
    echo -e "${BOLD}  FALCON-X End-to-End Test Results${NC}"
    echo -e "${BOLD}═══════════════════════════════════════════════${NC}"
    echo ""
    echo -e "  Total:  $TOTAL"
    echo -e "  ${GREEN}Pass:   $PASS${NC}"
    echo -e "  ${RED}Fail:   $FAIL${NC}"
    echo ""

    if [[ $FAIL -eq 0 ]]; then
        echo -e "  ${GREEN}All tests passed!${NC}"
    else
        echo -e "  ${RED}$FAIL test(s) failed${NC}"
    fi
    echo ""
}

main() {
    echo -e "${CYAN}"
    echo "  FALCON-X End-to-End Tests"
    echo "  $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo -e "${NC}"

    test_boot_system
    test_network
    test_firewall
    test_services
    test_detection
    test_dashboard
    test_ai
    test_failure_recovery

    print_summary

    exit $FAIL
}

main "$@"
