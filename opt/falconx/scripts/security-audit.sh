#!/bin/bash
# FALCON-X Security Audit Script
# Comprehensive security audit of the hardened FALCON-X system

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

pass() {
    echo -e "  ${GREEN}✓ PASS${NC} $*"
    ((PASS++))
}

fail() {
    echo -e "  ${RED}✗ FAIL${NC} $*"
    ((FAIL++))
}

warn() {
    echo -e "  ${YELLOW}! WARN${NC} $*"
    ((WARN++))
}

skip() {
    echo -e "  ${CYAN}- SKIP${NC} $*"
    ((SKIP++))
}

section() {
    echo -e "\n${BOLD}$*${NC}"
    echo "────────────────────────────────────────────"
}

# ══════════════════════════════════════════════════════════════════
# 1. FIREWALL
# ══════════════════════════════════════════════════════════════════
audit_firewall() {
    section "1. FIREWALL"

    # Check nftables is installed
    if command -v nft > /dev/null 2>&1; then
        pass "nftables installed"
    else
        fail "nftables not installed"
        return
    fi

    # Check rules are loaded
    local rule_count
    rule_count=$(nft list ruleset 2>/dev/null | wc -l)
    if [[ $rule_count -gt 10 ]]; then
        pass "Firewall rules loaded ($rule_count lines)"
    else
        fail "No firewall rules loaded"
    fi

    # Check default policies
    local input_policy
    input_policy=$(nft list chain inet falconx_filter input 2>/dev/null | grep "policy" | awk '{print $6}' | tr -d ';')
    if [[ "$input_policy" == "drop" ]]; then
        pass "INPUT policy: DROP"
    else
        fail "INPUT policy: $input_policy (should be DROP)"
    fi

    local forward_policy
    forward_policy=$(nft list chain inet falconx_filter forward 2>/dev/null | grep "policy" | awk '{print $6}' | tr -d ';')
    if [[ "$forward_policy" == "drop" ]]; then
        pass "FORWARD policy: DROP"
    else
        fail "FORWARD policy: $forward_policy (should be DROP)"
    fi

    # Check rate limiting
    if nft list ruleset 2>/dev/null | grep -q "limit rate"; then
        pass "Rate limiting configured"
    else
        warn "No rate limiting found"
    fi

    # Check logging
    if nft list ruleset 2>/dev/null | grep -q "log prefix"; then
        pass "Firewall logging enabled"
    else
        warn "Firewall logging not configured"
    fi
}

# ══════════════════════════════════════════════════════════════════
# 2. SSH
# ══════════════════════════════════════════════════════════════════
audit_ssh() {
    section "2. SSH HARDENING"

    local sshd_config="/etc/ssh/sshd_config.d/falconx-hardened.conf"

    if [[ ! -f "$sshd_config" ]]; then
        warn "SSH hardening config not installed"
        return
    fi

    # Root login
    if grep -q "^PermitRootLogin no" "$sshd_config" 2>/dev/null; then
        pass "Root login disabled"
    else
        fail "Root login not disabled"
    fi

    # Password auth
    if grep -q "^PasswordAuthentication no" "$sshd_config" 2>/dev/null; then
        pass "Password authentication disabled"
    else
        fail "Password authentication not disabled"
    fi

    # Max auth tries
    if grep -q "^MaxAuthTries" "$sshd_config" 2>/dev/null; then
        pass "Max auth tries configured"
    else
        warn "Max auth tries not configured"
    fi

    # Allow groups
    if grep -q "^AllowGroups" "$sshd_config" 2>/dev/null; then
        pass "SSH access restricted to groups"
    else
        fail "SSH access not restricted to groups"
    fi

    # Protocol check
    if grep -q "^LogLevel VERBOSE" "$sshd_config" 2>/dev/null; then
        pass "SSH logging: VERBOSE"
    else
        warn "SSH logging not set to VERBOSE"
    fi
}

# ══════════════════════════════════════════════════════════════════
# 3. SYSTEMD SANDBOXING
# ══════════════════════════════════════════════════════════════════
audit_systemd() {
    section "3. SYSTEMD SANDBOXING"

    local services=("falconx-engine" "falconx-web" "falconx-health")
    local service_dir="/etc/systemd/system"

    for svc in "${services[@]}"; do
        local file="$service_dir/${svc}.service"
        if [[ ! -f "$file" ]]; then
            skip "$svc: service file not found"
            continue
        fi

        echo -e "  ${BOLD}$svc:${NC}"

        # NoNewPrivileges
        if grep -q "NoNewPrivileges=true" "$file" 2>/dev/null; then
            pass "  NoNewPrivileges=true"
        else
            warn "  NoNewPrivileges not set"
        fi

        # PrivateTmp
        if grep -q "PrivateTmp=true" "$file" 2>/dev/null; then
            pass "  PrivateTmp=true"
        else
            warn "  PrivateTmp not set"
        fi

        # ProtectSystem
        if grep -q "ProtectSystem=strict" "$file" 2>/dev/null; then
            pass "  ProtectSystem=strict"
        elif grep -q "ProtectSystem=" "$file" 2>/dev/null; then
            warn "  ProtectSystem set (not strict)"
        else
            fail "  ProtectSystem not set"
        fi

        # ProtectHome
        if grep -q "ProtectHome=true" "$file" 2>/dev/null; then
            pass "  ProtectHome=true"
        else
            warn "  ProtectHome not set"
        fi

        # ProtectKernelTunables
        if grep -q "ProtectKernelTunables=true" "$file" 2>/dev/null; then
            pass "  ProtectKernelTunables=true"
        else
            warn "  ProtectKernelTunables not set"
        fi

        # CapabilityBoundingSet
        if grep -q "CapabilityBoundingSet=" "$file" 2>/dev/null; then
            local caps
            caps=$(grep "CapabilityBoundingSet=" "$file" | sed 's/CapabilityBoundingSet=//')
            if [[ -z "$caps" ]]; then
                pass "  CapabilityBoundingSet= (empty — no capabilities)"
            else
                pass "  CapabilityBoundingSet=$caps"
            fi
        else
            warn "  CapabilityBoundingSet not set"
        fi

        # RestrictNamespaces
        if grep -q "RestrictNamespaces=true" "$file" 2>/dev/null; then
            pass "  RestrictNamespaces=true"
        else
            warn "  RestrictNamespaces not set"
        fi
    done
}

# ══════════════════════════════════════════════════════════════════
# 4. USER PERMISSIONS
# ══════════════════════════════════════════════════════════════════
audit_users() {
    section "4. USERS AND PERMISSIONS"

    local users=("falconx-engine" "falconx-web")

    for user in "${users[@]}"; do
        if id "$user" > /dev/null 2>&1; then
            pass "User $user exists"

            # Check shell
            local shell
            shell=$(getent passwd "$user" | cut -d: -f7)
            if [[ "$shell" == "/usr/sbin/nologin" ]] || [[ "$shell" == "/bin/false" ]]; then
                pass "  Shell: $shell (no login)"
            else
                warn "  Shell: $shell (should be nologin)"
            fi
        else
            fail "User $user does not exist"
        fi
    done

    # Check secrets directory
    if [[ -d /etc/falconx/secrets ]]; then
        local perms
        perms=$(stat -c "%a" /etc/falconx/secrets 2>/dev/null || stat -p "%Lp" /etc/falconx/secrets 2>/dev/null)
        if [[ "$perms" == "700" ]]; then
            pass "Secrets directory: $perms (root only)"
        else
            fail "Secrets directory: $perms (should be 700)"
        fi
    fi

    # Check config files
    for f in /etc/falconx/*.yaml; do
        if [[ -f "$f" ]]; then
            local perms
            perms=$(stat -c "%a" "$f" 2>/dev/null || stat -p "%Lp" "$f" 2>/dev/null)
            if [[ "$perms" == "644" ]]; then
                pass "Config $(basename $f): $perms"
            else
                warn "Config $(basename $f): $perms (expected 644)"
            fi
        fi
    done

    # Check log directory
    if [[ -d /var/log/falconx ]]; then
        local perms
        perms=$(stat -c "%a" /var/log/falconx 2>/dev/null || stat -p "%Lp" /var/log/falconx 2>/dev/null)
        if [[ "$perms" == "755" ]]; then
            pass "Log directory: $perms"
        else
            warn "Log directory: $perms"
        fi
    fi
}

# ══════════════════════════════════════════════════════════════════
# 5. KERNEL HARDENING
# ══════════════════════════════════════════════════════════════════
audit_kernel() {
    section "5. KERNEL HARDENING"

    local sysctl_file="/etc/sysctl.d/99-falconx-hardening.conf"

    if [[ ! -f "$sysctl_file" ]]; then
        warn "Sysctl config not found"
        return
    fi

    # ASLR
    local aslr
    aslr=$(sysctl -n kernel.randomize_va_space 2>/dev/null || echo "unknown")
    if [[ "$aslr" == "2" ]]; then
        pass "ASLR: full ($aslr)"
    else
        fail "ASLR: $aslr (should be 2)"
    fi

    # dmesg restriction
    local dmesg
    dmesg=$(sysctl -n kernel.dmesg_restrict 2>/dev/null || echo "unknown")
    if [[ "$dmesg" == "1" ]]; then
        pass "dmesg restricted to root"
    else
        fail "dmesg not restricted ($dmesg)"
    fi

    # IP forwarding
    local fwd
    fwd=$(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo "unknown")
    if [[ "$fwd" == "0" ]]; then
        pass "IP forwarding disabled (monitor mode)"
    else
        warn "IP forwarding enabled ($fwd)"
    fi

    # SYN cookies
    local syncookies
    syncookies=$(sysctl -n net.ipv4.tcp_syncookies 2>/dev/null || echo "unknown")
    if [[ "$syncookies" == "1" ]]; then
        pass "SYN cookies enabled"
    else
        fail "SYN cookies disabled"
    fi

    # Source routing
    local srcroute
    srcroute=$(sysctl -n net.ipv4.conf.all.accept_source_route 2>/dev/null || echo "unknown")
    if [[ "$srcroute" == "0" ]]; then
        pass "Source routing disabled"
    else
        fail "Source routing enabled ($srcroute)"
    fi

    # ICMP redirects
    local redirects
    redirects=$(sysctl -n net.ipv4.conf.all.accept_redirects 2>/dev/null || echo "unknown")
    if [[ "$redirects" == "0" ]]; then
        pass "ICMP redirects disabled"
    else
        fail "ICMP redirects enabled ($redirects)"
    fi

    # Reverse path filtering
    local rpfilter
    rpfilter=$(sysctl -n net.ipv4.conf.all.rp_filter 2>/dev/null || echo "unknown")
    if [[ "$rpfilter" == "1" ]]; then
        pass "Reverse path filtering enabled"
    else
        warn "Reverse path filtering: $rpfilter"
    fi
}

# ══════════════════════════════════════════════════════════════════
# 6. SECRETS
# ══════════════════════════════════════════════════════════════════
audit_secrets() {
    section "6. SECRETS"

    local secrets_dir="/etc/falconx/secrets"

    if [[ ! -d "$secrets_dir" ]]; then
        fail "Secrets directory missing"
        return
    fi

    # Master key
    if [[ -f "$secrets_dir/master.key" ]]; then
        local perms
        perms=$(stat -c "%a" "$secrets_dir/master.key" 2>/dev/null || stat -p "%Lp" "$secrets_dir/master.key" 2>/dev/null)
        if [[ "$perms" == "600" ]]; then
            pass "Master key: $perms (root only)"
        else
            fail "Master key: $perms (should be 600)"
        fi
    else
        warn "Master key not generated"
    fi

    # TLS cert
    if [[ -f "$secrets_dir/server.crt" ]]; then
        pass "TLS certificate exists"

        # Check expiry
        if openssl x509 -in "$secrets_dir/server.crt" -noout -checkend 2592000 2>/dev/null; then
            pass "TLS certificate expires > 30 days"
        else
            warn "TLS certificate expires within 30 days"
        fi
    else
        warn "TLS certificate not generated"
    fi

    # TLS key
    if [[ -f "$secrets_dir/server.key" ]]; then
        local perms
        perms=$(stat -c "%a" "$secrets_dir/server.key" 2>/dev/null || stat -p "%Lp" "$secrets_dir/server.key" 2>/dev/null)
        if [[ "$perms" == "600" ]]; then
            pass "TLS key: $perms (root only)"
        else
            fail "TLS key: $perms (should be 600)"
        fi
    else
        warn "TLS key not generated"
    fi

    # Signing key
    if [[ -f "$secrets_dir/signing.key" ]] && [[ -f "$secrets_dir/signing.pub" ]]; then
        pass "Signing keypair exists"
    else
        warn "Signing keypair not generated (needed for updates)"
    fi
}

# ══════════════════════════════════════════════════════════════════
# 7. SERVICES
# ══════════════════════════════════════════════════════════════════
audit_services() {
    section "7. SERVICE STATUS"

    local services=("falconx-engine" "falconx-web" "falconx-health")

    for svc in "${services[@]}"; do
        if systemctl is-active "$svc.service" > /dev/null 2>&1; then
            pass "$svc: running"
        else
            fail "$svc: not running"
        fi

        if systemctl is-enabled "$svc.service" > /dev/null 2>&1; then
            pass "$svc: enabled at boot"
        else
            warn "$svc: not enabled at boot"
        fi
    done

    # Check ports
    echo ""
    echo -e "  ${BOLD}Listening ports:${NC}"
    for port in 9100 8443; do
        if ss -tlnp | grep -q ":${port} "; then
            pass "  Port $port: listening"
        else
            warn "  Port $port: not listening"
        fi
    done
}

# ══════════════════════════════════════════════════════════════════
# 8. LOGGING
# ══════════════════════════════════════════════════════════════════
audit_logging() {
    section "8. LOGGING"

    # Security log directory
    if [[ -d /var/log/falconx/security ]]; then
        pass "Security log directory exists"
    else
        warn "Security log directory not found"
    fi

    # rsyslog config
    if [[ -f /etc/rsyslog.d/50-falconx-security.conf ]]; then
        pass "Security rsyslog config installed"
    else
        warn "Security rsyslog config not found"
    fi

    # Logrotate
    if [[ -f /etc/logrotate.d/falconx ]]; then
        pass "Logrotate config installed"
    else
        warn "Logrotate config not found"
    fi

    # Check app logs exist
    for log in /var/log/falconx/*.log; do
        if [[ -f "$log" ]]; then
            pass "Log file: $(basename $log)"
        fi
    done
}

# ══════════════════════════════════════════════════════════════════
# 9. APPARMOR
# ══════════════════════════════════════════════════════════════════
audit_apparmor() {
    section "9. APPARMOR PROFILES"

    local profiles=("falconx-engine" "falconx-web")
    local profile_dir="/etc/apparmor.d"

    for profile in "${profiles[@]}"; do
        if [[ -f "$profile_dir/$profile" ]]; then
            pass "$profile: profile exists"

            # Check if enforced
            if command -v aa-status > /dev/null 2>&1; then
                if aa-status 2>/dev/null | grep -q "$profile"; then
                    pass "$profile: enforced"
                else
                    warn "$profile: not enforced (install with: apparmor_parser -r $profile_dir/$profile)"
                fi
            fi
        else
            warn "$profile: profile not found"
        fi
    done
}

# ══════════════════════════════════════════════════════════════════
# 10. NETWORK
# ══════════════════════════════════════════════════════════════════
audit_network() {
    section "10. NETWORK SECURITY"

    # Check interfaces
    local interfaces
    interfaces=$(ip -brief addr show 2>/dev/null | grep -v "lo" | awk '{print $1}' | head -5)
    for iface in $interfaces; do
        local state
        state=$(ip -brief link show "$iface" 2>/dev/null | awk '{print $2}')
        if [[ "$state" == "UP" ]]; then
            pass "Interface $iface: UP"
        else
            warn "Interface $iface: $state"
        fi
    done

    # DNS
    if [[ -f /etc/resolv.conf ]]; then
        local ns_count
        ns_count=$(grep -c "nameserver" /etc/resolv.conf 2>/dev/null || echo 0)
        if [[ $ns_count -gt 0 ]]; then
            pass "DNS servers configured ($ns_count)"
        else
            warn "No DNS servers configured"
        fi
    fi

    # NTP
    if systemctl is-active systemd-timesyncd > /dev/null 2>&1; then
        pass "NTP (systemd-timesyncd) running"
    else
        warn "NTP not running"
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
    echo -e "  ${GREEN}PASS: $PASS${NC}"
    echo -e "  ${RED}FAIL: $FAIL${NC}"
    echo -e "  ${YELLOW}WARN: $WARN${NC}"
    echo -e "  ${CYAN}SKIP: $SKIP${NC}"
    echo ""

    local total=$((PASS + FAIL + WARN + SKIP))
    echo -e "  Total checks: $total"
    echo ""

    if [[ $FAIL -eq 0 ]]; then
        echo -e "  ${GREEN}Overall: PASS${NC}"
    else
        echo -e "  ${RED}Overall: FAIL ($FAIL critical issue(s))${NC}"
    fi
    echo ""
}

main() {
    echo -e "${CYAN}"
    echo "  FALCON-X Security Audit"
    echo "  $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo -e "${NC}"

    audit_firewall
    audit_ssh
    audit_systemd
    audit_users
    audit_kernel
    audit_secrets
    audit_services
    audit_logging
    audit_apparmor
    audit_network

    print_summary

    exit $FAIL
}

main "$@"
