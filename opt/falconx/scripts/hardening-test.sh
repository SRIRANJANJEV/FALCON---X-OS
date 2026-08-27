#!/bin/bash
# FALCON-X Hardening Test Script
# Automated tests to verify security hardening was applied correctly

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

test_pass() {
    echo -e "  ${GREEN}✓${NC} $*"
    ((PASS++))
    ((TOTAL++))
}

test_fail() {
    echo -e "  ${RED}✗${NC} $*"
    ((FAIL++))
    ((TOTAL++))
}

section() {
    echo -e "\n${BOLD}$*${NC}"
}

# ══════════════════════════════════════════════════════════════════
# FIREWALL TESTS
# ══════════════════════════════════════════════════════════════════
test_firewall() {
    section "Firewall Tests"

    # nftables installed
    if command -v nft > /dev/null 2>&1; then
        test_pass "nftables installed"
    else
        test_fail "nftables not installed"
    fi

    # Rules loaded
    if nft list ruleset 2>/dev/null | grep -q "falconx_filter"; then
        test_pass "FALCON-X filter table loaded"
    else
        test_fail "FALCON-X filter table not loaded"
    fi

    # Default DROP policy
    if nft list chain inet falconx_filter input 2>/dev/null | grep -q "policy drop"; then
        test_pass "Input chain: DROP policy"
    else
        test_fail "Input chain: not DROP policy"
    fi

    if nft list chain inet falconx_filter forward 2>/dev/null | grep -q "policy drop"; then
        test_pass "Forward chain: DROP policy"
    else
        test_fail "Forward chain: not DROP policy"
    fi

    # Loopback allowed
    if nft list ruleset 2>/dev/null | grep -q 'iif "lo" accept'; then
        test_pass "Loopback traffic allowed"
    else
        test_fail "Loopback traffic not explicitly allowed"
    fi

    # SSH rate limited
    if nft list ruleset 2>/dev/null | grep -q "ssh_ratelimit"; then
        test_pass "SSH rate limiting configured"
    else
        test_fail "SSH rate limiting not configured"
    fi

    # Internal services localhost-only
    if nft list ruleset 2>/dev/null | grep -q "iif \"lo\" tcp dport"; then
        test_pass "Internal services bound to localhost"
    else
        test_fail "Internal services not restricted to localhost"
    fi
}

# ══════════════════════════════════════════════════════════════════
# SSH TESTS
# ══════════════════════════════════════════════════════════════════
test_ssh() {
    section "SSH Hardening Tests"

    local config="/etc/ssh/sshd_config.d/falconx-hardened.conf"

    if [[ ! -f "$config" ]]; then
        test_fail "SSH hardening config not installed"
        return
    fi

    if grep -q "PermitRootLogin no" "$config"; then
        test_pass "Root login disabled"
    else
        test_fail "Root login not disabled"
    fi

    if grep -q "PasswordAuthentication no" "$config"; then
        test_pass "Password auth disabled"
    else
        test_fail "Password auth not disabled"
    fi

    if grep -q "AllowGroups" "$config"; then
        test_pass "SSH group restriction configured"
    else
        test_fail "SSH group restriction not configured"
    fi

    if grep -q "MaxAuthTries 3" "$config"; then
        test_pass "Max auth tries set to 3"
    else
        test_fail "Max auth tries not set to 3"
    fi

    if grep -q "X11Forwarding no" "$config"; then
        test_pass "X11 forwarding disabled"
    else
        test_fail "X11 forwarding not disabled"
    fi
}

# ══════════════════════════════════════════════════════════════════
# SYSTEMD TESTS
# ══════════════════════════════════════════════════════════════════
test_systemd() {
    section "Systemd Sandboxing Tests"

    local services=("falconx-engine" "falconx-web")
    local required_directives=("NoNewPrivileges=true" "PrivateTmp=true" "ProtectSystem=strict" "ProtectHome=true")

    for svc in "${services[@]}"; do
        local file="/etc/systemd/system/${svc}.service"
        if [[ ! -f "$file" ]]; then
            test_fail "$svc: service file not found"
            continue
        fi

        for directive in "${required_directives[@]}"; do
            if grep -q "$directive" "$file"; then
                test_pass "$svc: $directive"
            else
                test_fail "$svc: $directive missing"
            fi
        done

        # Check CapabilityBoundingSet
        if grep -q "CapabilityBoundingSet=" "$file"; then
            test_pass "$svc: CapabilityBoundingSet configured"
        else
            test_fail "$svc: CapabilityBoundingSet missing"
        fi
    done
}

# ══════════════════════════════════════════════════════════════════
# USER TESTS
# ══════════════════════════════════════════════════════════════════
test_users() {
    section "User Permission Tests"

    local users=("falconx-engine" "falconx-web")

    for user in "${users[@]}"; do
        if id "$user" > /dev/null 2>&1; then
            test_pass "User $user exists"

            local shell
            shell=$(getent passwd "$user" | cut -d: -f7)
            if [[ "$shell" == "/usr/sbin/nologin" ]] || [[ "$shell" == "/bin/false" ]]; then
                test_pass "$user: nologin shell"
            else
                test_fail "$user: login shell ($shell)"
            fi
        else
            test_fail "User $user does not exist"
        fi
    done

    # Secrets directory
    if [[ -d /etc/falconx/secrets ]]; then
        local perms
        perms=$(stat -c "%a" /etc/falconx/secrets 2>/dev/null || echo "unknown")
        if [[ "$perms" == "700" ]]; then
            test_pass "Secrets directory: 700"
        else
            test_fail "Secrets directory: $perms (should be 700)"
        fi
    fi

    # Config files
    local config_perms_ok=true
    for f in /etc/falconx/*.yaml; do
        if [[ -f "$f" ]]; then
            local perms
            perms=$(stat -c "%a" "$f" 2>/dev/null || echo "unknown")
            if [[ "$perms" != "644" ]]; then
                config_perms_ok=false
            fi
        fi
    done
    if $config_perms_ok; then
        test_pass "Config files: 644"
    else
        test_fail "Config files: incorrect permissions"
    fi
}

# ══════════════════════════════════════════════════════════════════
# KERNEL TESTS
# ══════════════════════════════════════════════════════════════════
test_kernel() {
    section "Kernel Hardening Tests"

    # ASLR
    local aslr
    aslr=$(sysctl -n kernel.randomize_va_space 2>/dev/null || echo "unknown")
    if [[ "$aslr" == "2" ]]; then
        test_pass "ASLR: full (2)"
    else
        test_fail "ASLR: $aslr (should be 2)"
    fi

    # dmesg
    local dmesg
    dmesg=$(sysctl -n kernel.dmesg_restrict 2>/dev/null || echo "unknown")
    if [[ "$dmesg" == "1" ]]; then
        test_pass "dmesg restricted"
    else
        test_fail "dmesg not restricted"
    fi

    # IP forwarding
    local fwd
    fwd=$(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo "unknown")
    if [[ "$fwd" == "0" ]]; then
        test_pass "IP forwarding disabled"
    else
        test_fail "IP forwarding enabled ($fwd)"
    fi

    # SYN cookies
    local syn
    syn=$(sysctl -n net.ipv4.tcp_syncookies 2>/dev/null || echo "unknown")
    if [[ "$syn" == "1" ]]; then
        test_pass "SYN cookies enabled"
    else
        test_fail "SYN cookies disabled"
    fi

    # Source routing
    local srcroute
    srcroute=$(sysctl -n net.ipv4.conf.all.accept_source_route 2>/dev/null || echo "unknown")
    if [[ "$srcroute" == "0" ]]; then
        test_pass "Source routing disabled"
    else
        test_fail "Source routing enabled"
    fi

    # ICMP redirects
    local redir
    redir=$(sysctl -n net.ipv4.conf.all.accept_redirects 2>/dev/null || echo "unknown")
    if [[ "$redir" == "0" ]]; then
        test_pass "ICMP redirects disabled"
    else
        test_fail "ICMP redirects enabled"
    fi
}

# ══════════════════════════════════════════════════════════════════
# NETWORK TESTS
# ══════════════════════════════════════════════════════════════════
test_network() {
    section "Network Security Tests"

    # Port check: only required ports should be listening
    local allowed_ports="22 8443 9100"

    local listening
    listening=$(ss -tlnp 2>/dev/null | grep LISTEN | awk '{print $4}' | grep -oE '[0-9]+$' | sort -un)

    for port in $listening; do
        if echo "$allowed_ports" | grep -qw "$port"; then
            test_pass "Port $port: allowed"
        else
            test_fail "Port $port: unexpected (not in allowed list)"
        fi
    done
}

# ══════════════════════════════════════════════════════════════════
# LOGGING TESTS
# ══════════════════════════════════════════════════════════════════
test_logging() {
    section "Logging Tests"

    if [[ -d /var/log/falconx ]]; then
        test_pass "Log directory exists"
    else
        test_fail "Log directory missing"
    fi

    if [[ -f /etc/logrotate.d/falconx ]]; then
        test_pass "Logrotate config installed"
    else
        test_fail "Logrotate config missing"
    fi
}

# ══════════════════════════════════════════════════════════════════
# SUMMARY
# ══════════════════════════════════════════════════════════════════
print_summary() {
    echo ""
    echo -e "${BOLD}═══════════════════════════════════════════════${NC}"
    echo -e "${BOLD}  FALCON-X Hardening Test Results${NC}"
    echo -e "${BOLD}═══════════════════════════════════════════════${NC}"
    echo ""
    echo -e "  Total:  $TOTAL"
    echo -e "  ${GREEN}Pass:   $PASS${NC}"
    echo -e "  ${RED}Fail:   $FAIL${NC}"
    echo ""

    if [[ $FAIL -eq 0 ]]; then
        echo -e "  ${GREEN}All hardening tests passed!${NC}"
    else
        echo -e "  ${RED}$FAIL test(s) failed — review above output${NC}"
    fi
    echo ""
}

main() {
    echo -e "${CYAN}"
    echo "  FALCON-X Hardening Verification Tests"
    echo "  $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo -e "${NC}"

    test_firewall
    test_ssh
    test_systemd
    test_users
    test_kernel
    test_network
    test_logging

    print_summary

    exit $FAIL
}

main "$@"
