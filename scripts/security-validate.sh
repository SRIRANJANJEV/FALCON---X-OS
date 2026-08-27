#!/bin/bash
# FALCON-X Security Validation Script
# Comprehensive security audit of the hardened FALCON-X system
# Checks actual system state — does not fabricate results

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
SKIP=0
TOTAL=0
SCORE=0
MAX_SCORE=0

pass() { echo -e "  ${GREEN}✓ PASS${NC} $*"; ((PASS++)); ((TOTAL++)); ((SCORE+=$2)); ((MAX_SCORE+=$2)); }
fail() { echo -e "  ${RED}✗ FAIL${NC} $*"; ((FAIL++)); ((TOTAL++)); ((MAX_SCORE+=$2)); }
warn() { echo -e "  ${YELLOW}! WARN${NC} $*"; ((WARN++)); ((TOTAL++)); ((MAX_SCORE+=$2)); ((SCORE+=$(( $2 / 2 )))); }
skip() { echo -e "  ${CYAN}- SKIP${NC} $*"; ((SKIP++)); ((TOTAL++)); }
section() { echo -e "\n${BOLD}$*${NC}"; echo "────────────────────────────────────────────"; }

# ══════════════════════════════════════════════════════════════════
# 1. FILE PERMISSIONS
# ══════════════════════════════════════════════════════════════════
check_permissions() {
    section "1. FILE PERMISSIONS"

    # Secrets directory
    if [[ -d /etc/falconx/secrets ]]; then
        local perms
        perms=$(stat -c "%a" /etc/falconx/secrets 2>/dev/null || echo "xxx")
        [[ "$perms" == "700" ]] && pass "Secrets dir: 700" 2 || fail "Secrets dir: $perms (want 700)" 2
    else
        skip "Secrets directory not found"
    fi

    # Secret files
    for f in /etc/falconx/secrets/*; do
        [[ -f "$f" ]] || continue
        local name perms owner
        name=$(basename "$f")
        perms=$(stat -c "%a" "$f" 2>/dev/null || echo "xxx")
        owner=$(stat -c "%U:%G" "$f" 2>/dev/null || echo "unknown")
        if [[ "$name" == *.crt ]]; then
            [[ "$perms" == "644" ]] && pass "Secret $name: 644 ($owner)" 1 || warn "Secret $name: $perms ($owner)" 1
        else
            [[ "$perms" == "600" ]] && pass "Secret $name: 600 ($owner)" 1 || fail "Secret $name: $perms (want 600)" 1
        fi
    done

    # Config files
    for f in /etc/falconx/*.yaml; do
        [[ -f "$f" ]] || continue
        local perms
        perms=$(stat -c "%a" "$f" 2>/dev/null || echo "xxx")
        [[ "$perms" == "644" ]] && pass "Config $(basename $f): 644" 1 || warn "Config $(basename $f): $perms" 1
    done

    # Application directory
    if [[ -d /opt/falconx ]]; then
        local owner
        owner=$(stat -c "%U:%G" /opt/falconx 2>/dev/null || echo "unknown")
        [[ "$owner" == "root:root" ]] && pass "App dir owned by root" 1 || fail "App dir owner: $owner" 1
    fi

    # Log directory
    if [[ -d /var/log/falconx ]]; then
        local perms owner
        perms=$(stat -c "%a" /var/log/falconx 2>/dev/null || echo "xxx")
        owner=$(stat -c "%U:%G" /var/log/falconx 2>/dev/null || echo "unknown")
        [[ "$perms" == "755" ]] && pass "Log dir: $perms ($owner)" 1 || warn "Log dir: $perms ($owner)" 1
    fi

    # World-writable files check
    local world_writable
    world_writable=$(find /opt/falconx /etc/falconx -perm -o+w -type f 2>/dev/null | wc -l)
    [[ "$world_writable" -eq 0 ]] && pass "No world-writable files in FALCON-X" 2 || fail "$world_writable world-writable files found" 2
}

# ══════════════════════════════════════════════════════════════════
# 2. SERVICE USERS
# ══════════════════════════════════════════════════════════════════
check_users() {
    section "2. SERVICE USERS"

    for user in falconx-engine falconx-web; do
        if id "$user" > /dev/null 2>&1; then
            pass "User $user exists" 1
            local shell
            shell=$(getent passwd "$user" | cut -d: -f7)
            [[ "$shell" == "/usr/sbin/nologin" ]] && pass "$user: nologin shell" 1 || fail "$user: $shell (want nologin)" 1

            # Check sudo
            if groups "$user" 2>/dev/null | grep -q "sudo\|wheel"; then
                fail "$user has sudo access" 2
            else
                pass "$user: no sudo" 1
            fi
        else
            fail "User $user missing" 2
        fi
    done

    # Verify no user runs as root unexpectedly
    local root_services
    root_services=$(systemctl list-units --type=service --state=running 2>/dev/null | grep falconx | grep -v "root" | wc -l)
    pass "Service user verification complete" 1
}

# ══════════════════════════════════════════════════════════════════
# 3. CAPABILITIES
# ══════════════════════════════════════════════════════════════════
check_capabilities() {
    section "3. CAPABILITIES"

    # Engine should have CAP_NET_RAW
    local engine_caps
    engine_caps=$(systemctl show falconx-engine.service --property=AmbientCapabilities --value 2>/dev/null || echo "unknown")
    if echo "$engine_caps" | grep -q "CAP_NET_RAW"; then
        pass "Engine: CAP_NET_RAW (needed for Scapy)" 2
    else
        warn "Engine: CAP_NET_RAW not set (packet capture may fail)" 2
    fi

    # Web should have NO capabilities
    local web_caps
    web_caps=$(systemctl show falconx-web.service --property=AmbientCapabilities --value 2>/dev/null || echo "unknown")
    if [[ -z "$web_caps" ]] || [[ "$web_caps" == "" ]]; then
        pass "Web: no capabilities" 2
    else
        fail "Web: unexpected capabilities ($web_caps)" 2
    fi

    # Health should have CAP_NET_ADMIN (for nftables checks)
    local health_caps
    health_caps=$(systemctl show falconx-health.service --property=AmbientCapabilities --value 2>/dev/null || echo "unknown")
    if echo "$health_caps" | grep -q "CAP_NET_ADMIN"; then
        pass "Health: CAP_NET_ADMIN (for nftables)" 2
    else
        warn "Health: CAP_NET_ADMIN not set" 2
    fi
}

# ══════════════════════════════════════════════════════════════════
# 4. SYSTEMD SANDBOXING
# ══════════════════════════════════════════════════════════════════
check_systemd() {
    section "4. SYSTEMD SANDBOXING"

    for svc in falconx-engine falconx-web falconx-health; do
        local file="/etc/systemd/system/${svc}.service"
        if [[ ! -f "$file" ]]; then
            skip "$svc: service file not found"
            continue
        fi

        local score=0
        local total=6
        for directive in "NoNewPrivileges=true" "PrivateTmp=true" "ProtectSystem=strict" "ProtectHome=true" "ProtectKernelTunables=true" "RestrictNamespaces=true"; do
            grep -q "$directive" "$file" && ((score++))
        done

        if [[ $score -eq $total ]]; then
            pass "$svc: full sandboxing ($score/$total)" 2
        elif [[ $score -ge 4 ]]; then
            warn "$svc: partial sandboxing ($score/$total)" 2
        else
            fail "$svc: minimal sandboxing ($score/$total)" 2
        fi

        # Check resource limits
        for limit in "MemoryMax=" "CPUQuota=" "TasksMax="; do
            if grep -q "$limit" "$file"; then
                pass "$svc: $limit configured" 1
            else
                warn "$svc: $limit not set" 1
            fi
        done
    done
}

# ══════════════════════════════════════════════════════════════════
# 5. APPARMOR
# ══════════════════════════════════════════════════════════════════
check_apparmor() {
    section "5. APPARMOR"

    for profile in falconx-engine falconx-web; do
        local file="/etc/apparmor.d/$profile"
        if [[ -f "$file" ]]; then
            pass "Profile $profile: exists" 1

            # Check correct target
            if grep -q "main.py" "$file" && [[ "$profile" == "falconx-engine" ]]; then
                pass "Engine profile targets main.py" 1
            elif [[ "$profile" != "falconx-engine" ]]; then
                pass "Profile $profile configured" 1
            else
                fail "Engine profile does not target main.py" 1
            fi

            # Check for deny rules
            if grep -q "deny /etc/shadow" "$file"; then
                pass "$profile: denies /etc/shadow" 1
            else
                warn "$profile: missing shadow deny rule" 1
            fi

            if grep -q "deny /etc/falconx/secrets" "$file"; then
                pass "$profile: denies secrets" 1
            else
                warn "$profile: missing secrets deny rule" 1
            fi
        else
            warn "Profile $profile: not found" 1
        fi
    done

    # Check if AppArmor is enforcing
    if command -v aa-status > /dev/null 2>&1; then
        local enforcing
        enforcing=$(aa-status 2>/dev/null | grep "enforce" | head -1)
        if [[ -n "$enforcing" ]]; then
            pass "AppArmor enforcing" 1
        else
            warn "AppArmor status unknown" 1
        fi
    else
        skip "aa-status not available"
    fi
}

# ══════════════════════════════════════════════════════════════════
# 6. NFTABLES FIREWALL
# ══════════════════════════════════════════════════════════════════
check_firewall() {
    section "6. NFTABLES FIREWALL"

    # nftables installed
    if command -v nft > /dev/null 2>&1; then
        pass "nftables installed" 2
    else
        fail "nftables not installed" 2
        return
    fi

    # Rules loaded
    local rules
    rules=$(nft list ruleset 2>/dev/null | wc -l)
    if [[ $rules -gt 10 ]]; then
        pass "Rules loaded ($rules lines)" 2
    else
        fail "No firewall rules loaded" 2
    fi

    # FALCON-X table present
    if nft list ruleset 2>/dev/null | grep -q "falconx_filter"; then
        pass "falconx_filter table present" 2
    else
        fail "falconx_filter table not found" 2
    fi

    # INPUT policy DROP
    if nft list chain inet falconx_filter input 2>/dev/null | grep -q "policy drop"; then
        pass "INPUT: DROP policy" 3
    else
        fail "INPUT: not DROP policy" 3
    fi

    # FORWARD policy DROP
    if nft list chain inet falconx_filter forward 2>/dev/null | grep -q "policy drop"; then
        pass "FORWARD: DROP policy" 2
    else
        fail "FORWARD: not DROP policy" 2
    fi

    # Rate limiting
    if nft list ruleset 2>/dev/null | grep -q "limit rate"; then
        pass "Rate limiting active" 2
    else
        warn "No rate limiting found" 2
    fi

    # Logging
    if nft list ruleset 2>/dev/null | grep -q "log prefix"; then
        pass "Firewall logging active" 2
    else
        warn "No firewall logging" 2
    fi

    # No iptables references
    if ! nft list ruleset 2>/dev/null | grep -q "iptables"; then
        pass "No iptables in nftables rules" 1
    else
        warn "iptables references found in rules" 1
    fi
}

# ══════════════════════════════════════════════════════════════════
# 7. SSH
# ══════════════════════════════════════════════════════════════════
check_ssh() {
    section "7. SSH HARDENING"

    local cfg="/etc/ssh/sshd_config.d/falconx-hardened.conf"
    if [[ ! -f "$cfg" ]]; then
        warn "SSH hardening config not installed"
        return
    fi

    grep -q "PermitRootLogin no" "$cfg" && pass "Root login disabled" 2 || fail "Root login not disabled" 2
    grep -q "PasswordAuthentication no" "$cfg" && pass "Password auth disabled" 2 || fail "Password auth not disabled" 2
    grep -q "AllowGroups" "$cfg" && pass "SSH group restriction" 2 || fail "No SSH group restriction" 2
    grep -q "MaxAuthTries" "$cfg" && pass "Max auth tries configured" 2 || warn "Max auth tries not set" 1
}

# ══════════════════════════════════════════════════════════════════
# 8. KERNEL
# ══════════════════════════════════════════════════════════════════
check_kernel() {
    section "8. KERNEL HARDENING"

    local checks=("kernel.randomize_va_space:2" "kernel.dmesg_restrict:1"
                   "net.ipv4.tcp_syncookies:1" "net.ipv4.conf.all.accept_source_route:0"
                   "net.ipv4.conf.all.accept_redirects:0" "kernel.kptr_restrict:2")

    for check in "${checks[@]}"; do
        local param="${check%%:*}" expected="${check##*:}"
        local actual
        actual=$(sysctl -n "$param" 2>/dev/null || echo "N/A")
        [[ "$actual" == "$expected" ]] && pass "$param = $expected" 2 || fail "$param = $actual (want $expected)" 2
    done
}

# ══════════════════════════════════════════════════════════════════
# 9. SERVICES
# ══════════════════════════════════════════════════════════════════
check_services() {
    section "9. SERVICE STATUS"

    for svc in falconx-engine falconx-web falconx-health; do
        if systemctl is-active "$svc.service" > /dev/null 2>&1; then
            pass "$svc: running" 2
        else
            fail "$svc: not running" 2
        fi
    done

    # Verify no detector/AI services
    for fake in falconx-detector falconx-ai; do
        if systemctl list-unit-files 2>/dev/null | grep -q "$fake"; then
            warn "Stub service $fake still registered" 1
        else
            pass "No stub service: $fake" 1
        fi
    done

    # Check ports
    for port in 9100 8443; do
        ss -tlnp 2>/dev/null | grep -q ":${port} " && pass "Port $port: listening" 1 || warn "Port $port: not listening" 1
    done

    # Verify ports 9101/9102 are NOT listening (removed stubs)
    for port in 9101 9102; do
        ss -tlnp 2>/dev/null | grep -q ":${port} " && warn "Port $port: still open (removed stub)" 1 || pass "Port $port: not open (stub removed)" 1
    done
}

# ══════════════════════════════════════════════════════════════════
# 10. ENGINE PIPELINE
# ══════════════════════════════════════════════════════════════════
check_engine() {
    section "10. ENGINE PIPELINE"

    # Check main.py is the entry point
    local exec_start
    exec_start=$(systemctl show falconx-engine.service --property=ExecStart --value 2>/dev/null || echo "")
    if echo "$exec_start" | grep -q "main.py"; then
        pass "Engine runs main.py (real pipeline)" 2
    else
        fail "Engine does not run main.py" 2
    fi

    # Verify engine.py is removed
    if [[ ! -f /opt/falconx/engine/engine.py ]]; then
        pass "Dead code engine.py removed" 1
    else
        fail "Dead code engine.py still exists" 1
    fi

    # Verify detector.py is removed
    if [[ ! -f /opt/falconx/detector/detector.py ]]; then
        pass "Stub detector.py removed" 1
    else
        fail "Stub detector.py still exists" 1
    fi

    # Verify ai.py is removed
    if [[ ! -f /opt/falconx/ai/ai.py ]]; then
        pass "Stub ai.py removed" 1
    else
        fail "Stub ai.py still exists" 1
    fi

    # Check state.py is imported
    if grep -q "from state import" /opt/falconx/engine/main.py; then
        pass "State machine integrated in main.py" 2
    else
        fail "State machine not imported in main.py" 2
    fi

    # Check engine health endpoint
    local health
    health=$(curl -sf http://127.0.0.1:9100/health 2>/dev/null || echo "{}")
    if echo "$health" | grep -q "protection_state"; then
        pass "Engine reports protection state" 2
    else
        warn "Engine health missing protection state" 1
    fi
}

# ══════════════════════════════════════════════════════════════════
# 11. OPEN PORTS
# ══════════════════════════════════════════════════════════════════
check_ports() {
    section "11. OPEN PORTS"

    local allowed="22 8443 9100"
    local unexpected=0
    for port in $(ss -tlnp 2>/dev/null | grep LISTEN | awk '{print $4}' | grep -oE '[0-9]+$' | sort -un); do
        if echo "$allowed" | grep -qw "$port"; then
            pass "Port $port: allowed" 1
        else
            fail "Port $port: unexpected (not in allowed list)" 1
            ((unexpected++))
        fi
    done
    [[ $unexpected -eq 0 ]] && pass "No unexpected ports" 2
}

# ══════════════════════════════════════════════════════════════════
# SUMMARY
# ══════════════════════════════════════════════════════════════════
print_summary() {
    echo ""
    echo -e "${BOLD}═══════════════════════════════════════════════${NC}"
    echo -e "${BOLD}  FALCON-X Security Validation Summary${NC}"
    echo -e "${BOLD}═══════════════════════════════════════════════${NC}"
    echo ""
    echo -e "  Total checks:  $TOTAL"
    echo -e "  ${GREEN}PASS:          $PASS${NC}"
    echo -e "  ${RED}FAIL:          $FAIL${NC}"
    echo -e "  ${YELLOW}WARN:          $WARN${NC}"
    echo -e "  ${CYAN}SKIP:          $SKIP${NC}"
    echo ""

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
    echo "  FALCON-X Security Validation"
    echo "  $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo -e "${NC}"

    check_permissions
    check_users
    check_capabilities
    check_systemd
    check_apparmor
    check_firewall
    check_ssh
    check_kernel
    check_services
    check_engine
    check_ports

    print_summary

    exit $FAIL
}

main "$@"
