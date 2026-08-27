#!/bin/bash
# FALCON-X Comprehensive Security Audit
# Checks every security control in the repository

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

PASS=0 FAIL=0 WARN=0

pass() { echo -e "  ${GREEN}✓${NC} $*"; ((PASS++)); }
fail() { echo -e "  ${RED}✗${NC} $*"; ((FAIL++)); }
warn() { echo -e "  ${YELLOW}!${NC} $*"; ((WARN++)); }

main() {
    echo "FALCON-X Security Audit"
    echo "======================="
    echo ""

    # ── 1. Service Users ──────────────────────────────────────────
    echo "1. Service Users"
    for user in falconx-engine falconx-web; do
        if id "$user" > /dev/null 2>&1; then
            pass "$user exists"
            local shell
            shell=$(getent passwd "$user" | cut -d: -f7)
            [[ "$shell" == "/usr/sbin/nologin" ]] && pass "$user: nologin" || fail "$user: $shell"
            local groups
            groups=$(id -nG "$user" 2>/dev/null)
            echo "$groups" | grep -q "sudo\|wheel" && fail "$user has sudo" || pass "$user: no sudo"
        else
            fail "$user missing"
        fi
    done

    # ── 2. File Permissions ────────────────────────────────────────
    echo "2. File Permissions"
    for dir in /opt/falconx /etc/falconx /var/lib/falconx /var/log/falconx; do
        [[ -d "$dir" ]] && pass "$dir exists" || fail "$dir missing"
    done

    # ── 3. Secret Permissions ──────────────────────────────────────
    echo "3. Secret Permissions"
    if [[ -d /etc/falconx/secrets ]]; then
        local perms
        perms=$(stat -c "%a" /etc/falconx/secrets 2>/dev/null || echo "xxx")
        [[ "$perms" == "700" ]] && pass "Secrets dir: 700" || fail "Secrets dir: $perms"
    fi
    for f in /etc/falconx/secrets/*; do
        [[ -f "$f" ]] || continue
        local sperms
        sperms=$(stat -c "%a" "$f" 2>/dev/null || echo "xxx")
        [[ "$sperms" == "600" ]] && pass "$(basename "$f"): 600" || fail "$(basename "$f"): $sperms"
    done

    # ── 4. World-Writable Files ────────────────────────────────────
    echo "4. World-Writable Files"
    local ww_count
    ww_count=$(find /opt/falconx /etc/falconx -perm -o+w -type f 2>/dev/null | wc -l)
    [[ $ww_count -eq 0 ]] && pass "No world-writable files" || fail "$ww_count world-writable files"

    # ── 5. Capabilities ────────────────────────────────────────────
    echo "5. Capabilities"
    for svc in falconx-engine falconx-web falconx-health falconx-enforcer; do
        local file="/etc/systemd/system/${svc}.service"
        [[ -f "$file" ]] || { fail "$svc: service file missing"; continue; }
        local caps
        caps=$(grep "CapabilityBoundingSet=" "$file" | sed 's/CapabilityBoundingSet=//')
        pass "$svc: caps=$caps"
    done

    # ── 6. Systemd Sandboxing ──────────────────────────────────────
    echo "6. Systemd Sandboxing"
    for svc in falconx-engine falconx-web falconx-health falconx-enforcer; do
        local file="/etc/systemd/system/${svc}.service"
        [[ -f "$file" ]] || continue
        local score=0
        for d in "NoNewPrivileges=true" "PrivateTmp=true" "ProtectSystem=strict" "ProtectHome=true" "ProtectKernelTunables=true" "RestrictNamespaces=true"; do
            grep -q "$d" "$file" && ((score++))
        done
        [[ $score -ge 5 ]] && pass "$svc: sandboxing ($score/6)" || warn "$svc: sandboxing ($score/6)"
    done

    # ── 7. AppArmor ────────────────────────────────────────────────
    echo "7. AppArmor"
    if command -v apparmor_parser > /dev/null 2>&1; then
        for profile in falconx-engine falconx-web falconx-enforcer; do
            [[ -f "/etc/apparmor.d/$profile" ]] && pass "Profile $profile exists" || warn "Profile $profile missing"
        done
    else
        warn "AppArmor not available"
    fi

    # ── 8. nftables ────────────────────────────────────────────────
    echo "8. nftables"
    if command -v nft > /dev/null 2>&1; then
        nft list ruleset 2>/dev/null | grep -q "falconx_filter" && pass "falconx_filter loaded" || warn "falconx_filter not loaded"
        nft list ruleset 2>/dev/null | grep -q "policy drop" && pass "DROP policy active" || warn "No DROP policy"
    else
        warn "nftables not available"
    fi

    # ── 9. iptables Check ──────────────────────────────────────────
    echo "9. iptables Check"
    local ipt_count
    ipt_count=$(grep -rl "iptables" /opt/falconx/ /etc/falconx/ 2>/dev/null | grep -v "test\|audit\|README\|\.md" | wc -l)
    [[ $ipt_count -eq 0 ]] && pass "No iptables in code" || fail "$ipt_count files reference iptables"

    # ── 10. sysctl ─────────────────────────────────────────────────
    echo "10. sysctl"
    if [[ -f /etc/sysctl.d/99-falconx-hardening.conf ]]; then
        pass "Sysctl config exists"
        sysctl -n kernel.randomize_va_space 2>/dev/null | grep -q "2" && pass "ASLR: full" || warn "ASLR: not set"
        sysctl -n net.ipv4.tcp_syncookies 2>/dev/null | grep -q "1" && pass "SYN cookies: enabled" || warn "SYN cookies: not set"
    else
        warn "Sysctl config missing"
    fi

    # ── 11. SSH ────────────────────────────────────────────────────
    echo "11. SSH"
    if [[ -f /etc/ssh/sshd_config.d/falconx-hardened.conf ]]; then
        grep -q "PermitRootLogin no" /etc/ssh/sshd_config.d/falconx-hardened.conf && pass "Root login disabled" || fail "Root login not disabled"
        grep -q "PasswordAuthentication no" /etc/ssh/sshd_config.d/falconx-hardened.conf && pass "Password auth disabled" || fail "Password auth not disabled"
        grep -q "AllowGroups" /etc/ssh/sshd_config.d/falconx-hardened.conf && pass "SSH group restriction" || fail "No SSH group restriction"
    else
        warn "SSH hardening config missing"
    fi

    # ── 12. Listening Sockets ──────────────────────────────────────
    echo "12. Listening Sockets"
    local allowed="22 8443 9100"
    for port in $(ss -tlnp 2>/dev/null | grep LISTEN | awk '{print $4}' | grep -oE '[0-9]+$' | sort -un); do
        echo "$allowed" | grep -qw "$port" && pass "Port $port: allowed" || fail "Port $port: unexpected"
    done

    # ── 13. TLS ────────────────────────────────────────────────────
    echo "13. TLS"
    if [[ -f /etc/falconx/secrets/server.crt && -f /etc/falconx/secrets/server.key ]]; then
        pass "TLS cert and key exist"
    else
        warn "TLS cert/key not generated"
    fi

    # ── 14. Authentication ────────────────────────────────────────
    echo "14. Authentication"
    if [[ -f /etc/falconx/web-users.json ]]; then
        pass "User file exists"
        local perms
        perms=$(stat -c "%a" /etc/falconx/web-users.json 2>/dev/null || echo "xxx")
        [[ "$perms" == "600" ]] && pass "User file: 600" || fail "User file: $perms"
    else
        warn "User file missing"
    fi

    # ── 15. TODO/FIXME/STUB ────────────────────────────────────────
    echo "15. Code Quality"
    local todo_count
    todo_count=$(grep -rl "TODO\|FIXME\|STUB\|PLACEHOLDER" /opt/falconx/ --include="*.py" 2>/dev/null | wc -l)
    [[ $todo_count -eq 0 ]] && pass "No TODO/FIXME/STUB in Python code" || fail "$todo_count files with TODO/FIXME/STUB"

    # ── 16. Dead Services ──────────────────────────────────────────
    echo "16. Dead Services"
    for stub in falconx-detector.service falconx-ai.service; do
        [[ -f "/etc/systemd/system/$stub" ]] && fail "$stub still exists" || pass "$stub removed"
    done
    for stub in engine.py detector.py ai.py; do
        [[ -f "/opt/falconx/engine/$stub" ]] && fail "$stub still exists" || pass "$stub removed"
    done

    # ── 17. Fake Health Endpoints ──────────────────────────────────
    echo "17. Fake Health Endpoints"
    local fake_count
    fake_count=$(grep -rl "placeholder\|fake\|mock" /opt/falconx/ --include="*.py" 2>/dev/null | grep -v "test\|__pycache__" | wc -l)
    [[ $fake_count -eq 0 ]] && pass "No fake/placeholder code in production" || fail "$fake_count files with fake/placeholder"

    # ── 18. Dangerous Shell Execution ──────────────────────────────
    echo "18. Dangerous Shell Execution"
    local shell_count
    shell_count=$(grep -rn "shell=True\|os.system\|subprocess.call" /opt/falconx/ --include="*.py" 2>/dev/null | grep -v "test" | wc -l)
    [[ $shell_count -eq 0 ]] && pass "No dangerous shell execution" || fail "$shell_count dangerous shell calls"

    # ── 19. Log Permissions ────────────────────────────────────────
    echo "19. Log Permissions"
    if [[ -d /var/log/falconx ]]; then
        pass "Log directory exists"
        local owner
        owner=$(stat -c "%U:%G" /var/log/falconx 2>/dev/null || echo "unknown")
        echo "$owner" | grep -q "falconx-engine\|root" && pass "Log dir owner: $owner" || warn "Log dir owner: $owner"
    fi

    # ── 20. Services ───────────────────────────────────────────────
    echo "20. Services"
    for svc in falconx-engine falconx-web falconx-health falconx-enforcer; do
        if systemctl is-enabled "${svc}.service" > /dev/null 2>&1; then
            pass "$svc enabled"
        else
            warn "$svc not enabled"
        fi
    done

    # ── Summary ────────────────────────────────────────────────────
    echo ""
    echo "=============================="
    echo "Security Audit: $PASS passed, $FAIL failed, $WARN warnings"
    echo ""
    if [[ $FAIL -eq 0 ]]; then
        echo -e "${GREEN}Security audit: PASS${NC}"
    else
        echo -e "${RED}Security audit: FAIL ($FAIL issues)${NC}"
    fi

    exit $FAIL
}

main
