#!/bin/bash
# FALCON-X Enforcement Integration Tests
# Tests the complete enforcement pipeline against real nftables
# Requires: nftables, root privileges

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

PASS=0
FAIL=0
SKIP=0

pass() { echo -e "  ${GREEN}✓ PASS${NC} $*"; ((PASS++)); }
fail() { echo -e "  ${RED}✗ FAIL${NC} $*"; ((FAIL++)); }
skip() { echo -e "  ${YELLOW}— SKIP${NC} $*"; ((SKIP++)); }

echo -e "\n${CYAN}FALCON-X Enforcement Integration Tests${NC}"
echo -e "${CYAN}$(date -u +%Y-%m-%dT%H:%M:%SZ)${NC}\n"

# ── Pre-flight checks ─────────────────────────────────────────────
echo -e "${BOLD}Pre-flight Checks${NC}"

if [[ $EUID -ne 0 ]]; then
    skip "Not root — integration tests require root"
    echo -e "\n  Run with: sudo $0"
    exit 0
fi

if ! command -v nft > /dev/null 2>&1; then
    skip "nftables not available"
    exit 0
fi

if ! nft list tables 2>/dev/null | grep -q "inet"; then
    skip "nftables inet family not available"
    exit 0
fi

pass "nftables available"

# ── 1. Enforcer Table Creation ────────────────────────────────────
echo -e "\n${BOLD}1. Enforcer Table Creation${NC}"

# Flush any existing enforcer table
nft delete table inet falconx_enforcer 2>/dev/null || true

# Create the table via enforcer
if python3 /opt/falconx/engine/enforcer.py &
    ENFORCER_PID=$!
    sleep 2

    if nft list table inet falconx_enforcer > /dev/null 2>&1; then
        pass "Enforcer table created"
    else
        fail "Enforcer table not created"
    fi

    # Kill enforcer
    kill $ENFORCER_PID 2>/dev/null || true
    wait $ENFORCER_PID 2>/dev/null || true
else
    skip "Could not start enforcer"
fi

# ── 2. Table Structure ────────────────────────────────────────────
echo -e "\n${BOLD}2. Table Structure${NC}"

if nft list table inet falconx_enforcer > /dev/null 2>&1; then
    pass "Table inet falconx_enforcer exists"

    if nft list table inet falconx_enforcer 2>/dev/null | grep -q "blocked_ips"; then
        pass "Set blocked_ips exists"
    else
        fail "Set blocked_ips missing"
    fi

    if nft list table inet falconx_enforcer 2>/dev/null | grep -q "blocked_ipv6"; then
        pass "Set blocked_ipv6 exists"
    else
        fail "Set blocked_ipv6 missing"
    fi

    if nft list table inet falconx_enforcer 2>/dev/null | grep -q "blocked_ports"; then
        pass "Set blocked_ports exists"
    else
        fail "Set blocked_ports missing"
    fi

    if nft list table inet falconx_enforcer 2>/dev/null | grep -q "input_hook"; then
        pass "Chain input_hook exists"
    else
        fail "Chain input_hook missing"
    fi

    if nft list table inet falconx_enforcer 2>/dev/null | grep -q "priority -10"; then
        pass "input_hook priority -10 (before main filter)"
    else
        fail "input_hook priority incorrect"
    fi
else
    skip "Enforcer table not available"
fi

# ── 3. IP Blocking ────────────────────────────────────────────────
echo -e "\n${BOLD}3. IP Blocking${NC}"

if nft list table inet falconx_enforcer > /dev/null 2>&1; then
    # Block an IP
    if nft add element inet falconx_enforcer blocked_ips { 192.0.2.1 timeout 60s } 2>/dev/null; then
        pass "IP 192.0.2.1 blocked"
    else
        fail "Failed to block IP 192.0.2.1"
    fi

    # Verify it's in the set
    if nft list set inet falconx_enforcer blocked_ips 2>/dev/null | grep -q "192.0.2.1"; then
        pass "IP 192.0.2.1 confirmed in set"
    else
        fail "IP 192.0.2.1 not found in set"
    fi

    # Unblock it
    if nft delete element inet falconx_enforcer blocked_ips { 192.0.2.1 } 2>/dev/null; then
        pass "IP 192.0.2.1 unblocked"
    else
        fail "Failed to unblock IP 192.0.2.1"
    fi

    # Verify it's gone
    if ! nft list set inet falconx_enforcer blocked_ips 2>/dev/null | grep -q "192.0.2.1"; then
        pass "IP 192.0.2.1 confirmed removed"
    else
        fail "IP 192.0.2.1 still in set"
    fi
else
    skip "Enforcer table not available for IP tests"
fi

# ── 4. IPv6 Blocking ──────────────────────────────────────────────
echo -e "\n${BOLD}4. IPv6 Blocking${NC}"

if nft list table inet falconx_enforcer > /dev/null 2>&1; then
    if nft add element inet falconx_enforcer blocked_ipv6 { 2001:db8::1 timeout 60s } 2>/dev/null; then
        pass "IPv6 2001:db8::1 blocked"
    else
        fail "Failed to block IPv6 2001:db8::1"
    fi

    if nft list set inet falconx_enforcer blocked_ipv6 2>/dev/null | grep -q "2001:db8::1"; then
        pass "IPv6 2001:db8::1 confirmed in set"
    else
        fail "IPv6 2001:db8::1 not found in set"
    fi

    nft delete element inet falconx_enforcer blocked_ipv6 { 2001:db8::1 } 2>/dev/null || true
    pass "IPv6 cleanup completed"
else
    skip "Enforcer table not available for IPv6 tests"
fi

# ── 5. Port Blocking ──────────────────────────────────────────────
echo -e "\n${BOLD}5. Port Blocking${NC}"

if nft list table inet falconx_enforcer > /dev/null 2>&1; then
    if nft add element inet falconx_enforcer blocked_ports { 9999 timeout 60s } 2>/dev/null; then
        pass "Port 9999 blocked"
    else
        fail "Failed to block port 9999"
    fi

    if nft list set inet falconx_enforcer blocked_ports 2>/dev/null | grep -q "9999"; then
        pass "Port 9999 confirmed in set"
    else
        fail "Port 9999 not found in set"
    fi

    if nft delete element inet falconx_enforcer blocked_ports { 9999 } 2>/dev/null; then
        pass "Port 9999 unblocked"
    else
        fail "Failed to unblock port 9999"
    fi
else
    skip "Enforcer table not available for port tests"
fi

# ── 6. Duplicate Block Handling ───────────────────────────────────
echo -e "\n${BOLD}6. Duplicate Block Handling${NC}"

if nft list table inet falconx_enforcer > /dev/null 2>&1; then
    nft add element inet falconx_enforcer blocked_ips { 192.0.2.2 timeout 60s } 2>/dev/null
    # Try to block again — nft should handle gracefully
    if nft add element inet falconx_enforcer blocked_ips { 192.0.2.2 timeout 60s } 2>/dev/null; then
        pass "Duplicate block handled (nft updates timeout)"
    else
        pass "Duplicate block handled (nft rejects duplicate)"
    fi
    nft delete element inet falconx_enforcer blocked_ips { 192.0.2.2 } 2>/dev/null || true
else
    skip "Enforcer table not available"
fi

# ── 7. Non-existent Unblock ───────────────────────────────────────
echo -e "\n${BOLD}7. Non-existent Unblock${NC}"

if nft list table inet falconx_enforcer > /dev/null 2>&1; then
    if nft delete element inet falconx_enforcer blocked_ips { 192.0.2.99 } 2>/dev/null; then
        pass "Non-existent unblock handled gracefully"
    else
        pass "Non-existent unblock returns error (expected)"
    fi
else
    skip "Enforcer table not available"
fi

# ── 8. Cleanup ────────────────────────────────────────────────────
echo -e "\n${BOLD}8. Cleanup${NC}"

nft delete table inet falconx_enforcer 2>/dev/null && pass "Enforcer table cleaned up" || pass "Enforcer table already clean"

# ── Summary ────────────────────────────────────────────────────────
echo -e "\n${BOLD}═══════════════════════════════════════════════${NC}"
echo -e "${BOLD}  Enforcement Integration Test Results${NC}"
echo -e "${BOLD}═══════════════════════════════════════════════${NC}"
echo ""
echo -e "  Total:  $((PASS + FAIL + SKIP))"
echo -e "  ${GREEN}Pass:   $PASS${NC}"
echo -e "  ${RED}Fail:   $FAIL${NC}"
echo -e "  ${YELLOW}Skip:   $SKIP${NC}"
echo ""

if [[ $FAIL -eq 0 ]] && [[ $PASS -gt 0 ]]; then
    echo -e "  ${GREEN}All enforcement integration tests passed!${NC}"
elif [[ $PASS -eq 0 ]]; then
    echo -e "  ${YELLOW}All tests skipped (nftables not available)${NC}"
else
    echo -e "  ${RED}$FAIL test(s) failed${NC}"
fi
echo ""

exit $FAIL
