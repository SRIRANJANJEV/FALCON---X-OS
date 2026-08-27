#!/bin/bash
# FALCON-X Comprehensive Security Verification
# Tests all security controls and produces a verifiable score

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

PASS=0
FAIL=0
WARN=0
TOTAL=0
SCORE=0
MAX_SCORE=0

pass() { echo -e "  ${GREEN}✓ PASS${NC} $*"; ((PASS++)); ((TOTAL++)); ((SCORE+=$2)); ((MAX_SCORE+=$2)); }
fail() { echo -e "  ${RED}✗ FAIL${NC} $*"; ((FAIL++)); ((TOTAL++)); ((MAX_SCORE+=$2)); }
warn() { echo -e "  ${YELLOW}! WARN${NC} $*"; ((WARN++)); ((TOTAL++)); ((MAX_SCORE+=$2)); ((SCORE+=$(( $2 / 2 )))); }

section() { echo -e "\n${BOLD}$*${NC}"; echo "────────────────────────────────────────────"; }

# ══════════════════════════════════════════════════════════════════
# 1. FIREWALL (15 points)
# ══════════════════════════════════════════════════════════════════
verify_firewall() {
    section "1. FIREWALL"

    if command -v nft > /dev/null 2>&1; then
        pass "nftables installed" 2
    else
        fail "nftables not installed" 2
        return
    fi

    local rules
    rules=$(nft list ruleset 2>/dev/null | wc -l)
    if [[ $rules -gt 10 ]]; then
        pass "Rules loaded ($rules lines)" 2
    else
        fail "No rules loaded" 2
    fi

    if nft list chain inet falconx_filter input 2>/dev/null | grep -q "policy drop"; then
        pass "INPUT: DROP policy" 3
    else
        fail "INPUT: not DROP" 3
    fi

    if nft list chain inet falconx_filter forward 2>/dev/null | grep -q "policy drop"; then
        pass "FORWARD: DROP policy" 3
    else
        fail "FORWARD: not DROP" 3
    fi

    if nft list ruleset 2>/dev/null | grep -q "limit rate"; then
        pass "Rate limiting active" 2
    else
        warn "No rate limiting" 2
    fi

    if nft list ruleset 2>/dev/null | grep -q "log prefix"; then
        pass "Firewall logging" 3
    else
        warn "No firewall logging" 3
    fi
}

# ══════════════════════════════════════════════════════════════════
# 2. SSH (10 points)
# ══════════════════════════════════════════════════════════════════
verify_ssh() {
    section "2. SSH"

    local cfg="/etc/ssh/sshd_config.d/falconx-hardened.conf"
    if [[ -f "$cfg" ]]; then
        pass "SSH config installed" 2
    else
        warn "SSH config not found" 2
        return
    fi

    if grep -q "PermitRootLogin no" "$cfg"; then
        pass "Root login disabled" 3
    else
        fail "Root login not disabled" 3
    fi

    if grep -q "PasswordAuthentication no" "$cfg"; then
        pass "Password auth disabled" 3
    else
        fail "Password auth not disabled" 3
    fi

    if grep -q "AllowGroups" "$cfg"; then
        pass "Group restriction" 2
    else
        fail "No group restriction" 2
    fi
}

# ══════════════════════════════════════════════════════════════════
# 3. USERS (10 points)
# ══════════════════════════════════════════════════════════════════
verify_users() {
    section "3. USERS & PERMISSIONS"

    for user in falconx-engine falconx-web; do
        if id "$user" > /dev/null 2>&1; then
            pass "User $user exists" 1
            local shell
            shell=$(getent passwd "$user" | cut -d: -f7)
            if [[ "$shell" == "/usr/sbin/nologin" ]] || [[ "$shell" == "/bin/false" ]]; then
                pass "$user: nologin shell" 1
            else
                fail "$user: login shell ($shell)" 1
            fi
        else
            fail "User $user missing" 2
        fi
    done

    if [[ -d /etc/falconx/secrets ]]; then
        local perms
        perms=$(stat -c "%a" /etc/falconx/secrets 2>/dev/null || echo "xxx")
        if [[ "$perms" == "700" ]]; then
            pass "Secrets dir: 700" 2
        else
            fail "Secrets dir: $perms (want 700)" 2
        fi
    fi
}

# ══════════════════════════════════════════════════════════════════
# 4. SYSTEMD (15 points)
# ══════════════════════════════════════════════════════════════════
verify_systemd() {
    section "4. SYSTEMD SANDBOXING"

    local services=("falconx-engine" "falconx-web" "falconx-health")

    for svc in "${services[@]}"; do
        local file="/etc/systemd/system/${svc}.service"
        if [[ ! -f "$file" ]]; then
            fail "$svc: service file missing" 4
            continue
        fi

        local score=0
        for directive in "NoNewPrivileges=true" "PrivateTmp=true" "ProtectSystem=strict" "ProtectHome=true"; do
            if grep -q "$directive" "$file"; then
                ((score++))
            fi
        done
        if [[ $score -eq 4 ]]; then
            pass "$svc: full sandboxing" 4
        elif [[ $score -ge 2 ]]; then
            warn "$svc: partial sandboxing ($score/4)" 4
        else
            fail "$svc: no sandboxing" 4
        fi
    done
}

# ══════════════════════════════════════════════════════════════════
# 5. KERNEL (10 points)
# ══════════════════════════════════════════════════════════════════
verify_kernel() {
    section "5. KERNEL HARDENING"

    local checks=("kernel.randomize_va_space:2" "kernel.dmesg_restrict:1" "net.ipv4.tcp_syncookies:1"
                   "net.ipv4.conf.all.accept_source_route:0" "net.ipv4.conf.all.accept_redirects:0")

    for check in "${checks[@]}"; do
        local param="${check%%:*}"
        local expected="${check##*:}"
        local actual
        actual=$(sysctl -n "$param" 2>/dev/null || echo "N/A")
        if [[ "$actual" == "$expected" ]]; then
            pass "$param = $expected" 2
        else
            fail "$param = $actual (want $expected)" 2
        fi
    done
}

# ══════════════════════════════════════════════════════════════════
# 6. SERVICES (15 points)
# ══════════════════════════════════════════════════════════════════
verify_services() {
    section "6. SERVICE STATUS"

    for svc in falconx-engine falconx-web falconx-health; do
        if systemctl is-active "$svc.service" > /dev/null 2>&1; then
            pass "$svc: running" 2
        else
            fail "$svc: not running" 2
        fi
    done

    for port in 9100 8443; do
        if ss -tlnp | grep -q ":${port} "; then
            pass "Port $port: listening" 1
        else
            warn "Port $port: not listening" 1
        fi
    done
}

# ══════════════════════════════════════════════════════════════════
# 7. SECRETS (10 points)
# ══════════════════════════════════════════════════════════════════
verify_secrets() {
    section "7. SECRETS"

    for secret in master.key server.crt server.key; do
        if [[ -f "/etc/falconx/secrets/$secret" ]]; then
            local perms
            perms=$(stat -c "%a" "/etc/falconx/secrets/$secret" 2>/dev/null || echo "xxx")
            if [[ "$secret" == "*.crt" ]] || [[ "$secret" == "server.crt" ]]; then
                pass "Secret $secret: exists ($perms)" 1
            elif [[ "$perms" == "600" ]]; then
                pass "Secret $secret: 600" 1
            else
                fail "Secret $secret: $perms (want 600)" 1
            fi
        else
            warn "Secret $secret: not generated" 1
        fi
    done
}

# ══════════════════════════════════════════════════════════════════
# 8. LOGGING (5 points)
# ══════════════════════════════════════════════════════════════════
verify_logging() {
    section "8. LOGGING"

    if [[ -d /var/log/falconx ]]; then
        pass "Log directory exists" 2
    else
        fail "Log directory missing" 2
    fi

    if [[ -f /etc/logrotate.d/falconx ]]; then
        pass "Logrotate configured" 2
    else
        warn "Logrotate missing" 2
    fi
}

# ══════════════════════════════════════════════════════════════════
# 9. NETWORK (10 points)
# ══════════════════════════════════════════════════════════════════
verify_network() {
    section "9. NETWORK"

    local allowed="22 8443 9100"
    local unexpected=0
    for port in $(ss -tlnp 2>/dev/null | grep LISTEN | awk '{print $4}' | grep -oE '[0-9]+$' | sort -un); do
        if ! echo "$allowed" | grep -qw "$port"; then
            fail "Unexpected port open: $port" 2
            ((unexpected++))
        fi
    done
    if [[ $unexpected -eq 0 ]]; then
        pass "No unexpected ports" 5
    fi

    if [[ -f /etc/resolv.conf ]] && grep -q nameserver /etc/resolv.conf; then
        pass "DNS configured" 3
    else
        warn "No DNS configured" 3
    fi

    if systemctl is-active systemd-timesyncd > /dev/null 2>&1; then
        pass "NTP active" 2
    else
        warn "NTP not active" 2
    fi
}

# ══════════════════════════════════════════════════════════════════
# SUMMARY
# ══════════════════════════════════════════════════════════════════
print_summary() {
    echo ""
    echo -e "${BOLD}═══════════════════════════════════════════════${NC}"
    echo -e "${BOLD}  FALCON-X Security Audit Summary${NC}"
    echo -e "${BOLD}═══════════════════════════════════════════════${NC}"
    echo ""
    echo -e "  Total checks:  $TOTAL"
    echo -e "  ${GREEN}PASS:          $PASS${NC}"
    echo -e "  ${RED}FAIL:          $FAIL${NC}"
    echo -e "  ${YELLOW}WARN:          $WARN${NC}"
    echo ""

    # Calculate percentage
    if [[ $MAX_SCORE -gt 0 ]]; then
        local pct=$(( SCORE * 100 / MAX_SCORE ))
    else
        local pct=0
    fi

    echo -e "  ${BOLD}Security Score: $SCORE / $MAX_SCORE ($pct%)${NC}"
    echo ""

    if [[ $pct -ge 90 ]]; then
        echo -e "  ${GREEN}Rating: EXCELLENT${NC}"
    elif [[ $pct -ge 75 ]]; then
        echo -e "  ${GREEN}Rating: GOOD${NC}"
    elif [[ $pct -ge 60 ]]; then
        echo -e "  ${YELLOW}Rating: FAIR${NC}"
    else
        echo -e "  ${RED}Rating: POOR — review failures above${NC}"
    fi
    echo ""
}

main() {
    echo -e "${CYAN}"
    echo "  FALCON-X Security Verification"
    echo "  $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo -e "${NC}"

    verify_firewall
    verify_ssh
    verify_users
    verify_systemd
    verify_kernel
    verify_services
    verify_secrets
    verify_logging
    verify_network

    print_summary

    exit $FAIL
}

main "$@"
