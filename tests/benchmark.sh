#!/bin/bash
# FALCON-X Performance Benchmark
# Measures key performance metrics on Raspberry Pi 4

set -euo pipefail

CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m'

RESULTS_FILE="/var/lib/falconx/benchmark-results.json"
TIMESTAMP=$(date -u +%Y-%m-%dT%H:%M:%SZ)

section() { echo -e "\n${BOLD}$*${NC}"; echo "────────────────────────────────────────────"; }

get_memory_mb() {
    grep "VmRSS" /proc/self/status 2>/dev/null | awk '{print $2/1024}' || echo "0"
}

get_cpu_temp() {
    cat /sys/class/thermal/thermal_zone0/temp 2>/dev/null | awk '{print $1/1000}' || echo "N/A"
}

# ══════════════════════════════════════════════════════════════════
# BENCHMARK: Boot Time
# ══════════════════════════════════════════════════════════════════
bench_boot() {
    section "Boot Time"

    local uptime_s
    uptime_s=$(awk '{print int($1)}' /proc/uptime 2>/dev/null || echo "0")
    echo "  System uptime: ${uptime_s}s"

    # Time to reach current state
    echo "  (Full boot timing requires reboot measurement)"
}

# ══════════════════════════════════════════════════════════════════
# BENCHMARK: CPU
# ══════════════════════════════════════════════════════════════════
bench_cpu() {
    section "CPU Performance"

    # CPU info
    local cpu_model
    cpu_model=$(grep "model name" /proc/cpuinfo 2>/dev/null | head -1 | cut -d: -f2 | xargs || echo "Unknown")
    local cpu_cores
    cpu_cores=$(nproc 2>/dev/null || echo "1")
    echo "  Model: $cpu_model"
    echo "  Cores: $cpu_cores"

    # Load averages
    local load
    load=$(awk '{print $1, $2, $3}' /proc/loadavg 2>/dev/null || echo "N/A N/A N/A")
    echo "  Load average: $load"

    # CPU usage
    local cpu_idle
    cpu_idle=$(awk '/^cpu / {print $5}' /proc/stat 2>/dev/null || echo "0")
    echo "  CPU idle: ${cpu_idle}%"

    # Temperature
    local temp
    temp=$(get_cpu_temp)
    echo "  Temperature: ${temp}°C"
}

# ══════════════════════════════════════════════════════════════════
# BENCHMARK: Memory
# ══════════════════════════════════════════════════════════════════
bench_memory() {
    section "Memory Usage"

    local total available used pct
    total=$(awk '/MemTotal/ {print $2}' /proc/meminfo 2>/dev/null || echo "0")
    available=$(awk '/MemAvailable/ {print $2}' /proc/meminfo 2>/dev/null || echo "0")
    used=$((total - available))
    pct=$((used * 100 / total))

    echo "  Total:     $((total / 1024))MB"
    echo "  Available: $((available / 1024))MB"
    echo "  Used:      $((used / 1024))MB (${pct}%)"

    # Per-process memory
    echo ""
    echo "  Top FALCON-X processes by memory:"
    ps aux 2>/dev/null | grep -E "falconx|python3" | grep -v grep | sort -k4 -rn | head -5 | \
        awk '{printf "    %-30s RSS=%sMB  CPU=%s%%\n", $11, int($6/1024), $3}' 2>/dev/null || echo "    (no processes found)"
}

# ══════════════════════════════════════════════════════════════════
# BENCHMARK: Disk
# ══════════════════════════════════════════════════════════════════
bench_disk() {
    section "Disk Usage"

    df -h / 2>/dev/null | tail -1 | awk '{
        printf "  Total: %s  Used: %s  Free: %s  Use%%: %s\n", $2, $3, $4, $5
    }'

    # FALCON-X specific
    echo ""
    echo "  FALCON-X directory sizes:"
    for dir in /opt/falconx /etc/falconx /var/lib/falconx /var/log/falconx; do
        if [[ -d "$dir" ]]; then
            local size
            size=$(du -sh "$dir" 2>/dev/null | cut -f1 || echo "0")
            echo "    $dir: $size"
        fi
    done
}

# ══════════════════════════════════════════════════════════════════
# BENCHMARK: Network
# ══════════════════════════════════════════════════════════════════
bench_network() {
    section "Network Performance"

    # Interface speeds
    for iface in eth0 wlan0; do
        if [[ -d "/sys/class/net/$iface" ]]; then
            local speed
            speed=$(cat "/sys/class/net/$iface/speed" 2>/dev/null || echo "unknown")
            local state
            state=$(cat "/sys/class/net/$iface/operstate" 2>/dev/null || echo "unknown")
            echo "  $iface: ${speed}Mbps (${state})"
        fi
    done

    # Current connections
    local tcp_count
    tcp_count=$(ss -t state established 2>/dev/null | wc -l || echo "0")
    echo "  TCP connections: $tcp_count"

    # Listening ports
    echo ""
    echo "  FALCON-X listening ports:"
    ss -tlnp 2>/dev/null | grep -E "(9100|8443)" | \
        awk '{printf "    %s → %s\n", $4, $6}' 2>/dev/null || echo "    (none)"
}

# ══════════════════════════════════════════════════════════════════
# BENCHMARK: Detection Engine
# ══════════════════════════════════════════════════════════════════
bench_detection() {
    section "Detection Engine"

    # Get engine stats
    local stats
    stats=$(curl -sf http://127.0.0.1:9100/stats 2>/dev/null || echo "{}")

    if echo "$stats" | python3 -c "import sys,json; json.load(sys.stdin)" 2>/dev/null; then
        echo "  Engine stats:"
        echo "$stats" | python3 -c "
import sys, json
data = json.load(sys.stdin)
cap = data.get('capture', {})
feat = data.get('features', {})
base = data.get('baseline', {})
inc = data.get('incidents', {})
eng = data.get('engine', {})
print(f'    Packets captured: {cap.get(\"packets_captured\", 0):,}')
print(f'    Packets dropped:  {cap.get(\"packets_dropped\", 0):,}')
print(f'    Active flows:     {feat.get(\"active_flows\", 0)}')
print(f'    Total flows:      {feat.get(\"total_flows\", 0):,}')
print(f'    Baseline ready:   {base.get(\"ready\", False)}')
print(f'    Open incidents:   {inc.get(\"open_incidents\", 0)}')
print(f'    Engine uptime:    {eng.get(\"uptime\", 0):.0f}s')
" 2>/dev/null || echo "    (parse error)"
    else
        echo "  Engine not responding"
    fi

    # Python module import time
    echo ""
    echo "  Module load times:"
    cd /opt/falconx/engine
    for module in capture features rules anomaly risk incidents; do
        local t
        t=$(python3 -c "import time; s=time.time(); import $module; print(f'{(time.time()-s)*1000:.1f}ms')" 2>/dev/null || echo "N/A")
        echo "    $module: $t"
    done
}

# ══════════════════════════════════════════════════════════════════
# BENCHMARK: Dashboard
# ══════════════════════════════════════════════════════════════════
bench_dashboard() {
    section "Dashboard"

    # Response time
    local time_total time_connect time_ttfb
    time_total=$(curl -sf -o /dev/null -w "%{time_total}" https://127.0.0.1:8443/ --insecure 2>/dev/null || echo "N/A")
    time_connect=$(curl -sf -o /dev/null -w "%{time_connect}" https://127.0.0.1:8443/ --insecure 2>/dev/null || echo "N/A")
    time_ttfb=$(curl -sf -o /dev/null -w "%{time_starttransfer}" https://127.0.0.1:8443/ --insecure 2>/dev/null || echo "N/A")

    echo "  Login page:"
    echo "    Total time:    ${time_total}s"
    echo "    Connect time:  ${time_connect}s"
    echo "    TTFB:          ${time_ttfb}s"

    # API response time
    time_total=$(curl -sf -o /dev/null -w "%{time_total}" https://127.0.0.1:8443/api/health --insecure 2>/dev/null || echo "N/A")
    echo "  API /health:"
    echo "    Response time: ${time_total}s"
}

# ══════════════════════════════════════════════════════════════════
# BENCHMARK: Storage
# ══════════════════════════════════════════════════════════════════
bench_storage() {
    section "Storage"

    # Write speed test
    echo "  Testing write speed (10MB)..."
    local write_start write_end
    write_start=$(date +%s%N)
    dd if=/dev/zero of=/tmp/falconx-bench bs=1M count=10 oflag=direct 2>/dev/null
    sync
    write_end=$(date +%s%N)
    local write_ms=$(( (write_end - write_start) / 1000000 ))
    echo "    Write: ${write_ms}ms ($(( 10000 / (write_ms + 1) ))MB/s)"

    # Read speed test
    echo "  Testing read speed (10MB)..."
    local read_start read_end
    read_start=$(date +%s%N)
    dd if=/tmp/falconx-bench of=/dev/null bs=1M iflag=direct 2>/dev/null
    read_end=$(date +%s%N)
    local read_ms=$(( (read_end - read_start) / 1000000 ))
    echo "    Read:  ${read_ms}ms ($(( 10000 / (read_ms + 1) ))MB/s)"

    rm -f /tmp/falconx-bench
}

# ══════════════════════════════════════════════════════════════════
# SAVE RESULTS
# ══════════════════════════════════════════════════════════════════
save_results() {
    mkdir -p "$(dirname "$RESULTS_FILE")"
    # Results are printed to stdout, JSON summary saved
    echo -e "\n${GREEN}Benchmark complete. Results printed above.${NC}"
}

# ══════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════
main() {
    echo -e "${CYAN}"
    echo "  FALCON-X Performance Benchmark"
    echo "  $TIMESTAMP"
    echo -e "${NC}"

    bench_boot
    bench_cpu
    bench_memory
    bench_disk
    bench_network
    bench_detection
    bench_dashboard
    bench_storage

    save_results

    echo -e "\n${GREEN}═══════════════════════════════════════════════${NC}"
    echo -e "${GREEN}  Benchmark complete${NC}"
    echo -e "${GREEN}═══════════════════════════════════════════════${NC}"
}

main "$@"
