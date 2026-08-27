#!/bin/bash
# FALCON-X Pipeline Integration Test
# Verifies the complete packet → incident logical path

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

echo -e "\n${CYAN}FALCON-X Pipeline Integration Test${NC}"
echo -e "${CYAN}$(date -u +%Y-%m-%dT%H:%M:%SZ)${NC}\n"

# ── 1. File Existence ────────────────────────────────────────────
echo -e "${BOLD}1. Pipeline File Verification${NC}"

for f in \
    opt/falconx/engine/main.py \
    opt/falconx/engine/capture.py \
    opt/falconx/engine/features.py \
    opt/falconx/engine/baseline.py \
    opt/falconx/engine/rules.py \
    opt/falconx/engine/anomaly.py \
    opt/falconx/engine/ml_interface.py \
    opt/falconx/engine/risk.py \
    opt/falconx/engine/incidents.py \
    opt/falconx/engine/enforcement.py \
    opt/falconx/engine/enforcer.py \
    opt/falconx/engine/state.py; do
    if [[ -f "$f" ]]; then
        pass "$f exists"
    else
        fail "$f MISSING"
    fi
done

# Verify dead code removed
for f in \
    opt/falconx/engine/engine.py \
    opt/falconx/detector/detector.py \
    opt/falconx/ai/ai.py; do
    if [[ ! -f "$f" ]]; then
        pass "$f correctly removed"
    else
        fail "$f still exists (should be removed)"
    fi
done

# ── 2. Import Chain Verification ──────────────────────────────────
echo -e "\n${BOLD}2. Import Chain Verification${NC}"

if command -v python3 > /dev/null 2>&1; then
    # Test that main.py imports all pipeline components
    cd opt/falconx/engine
    for mod in capture features baseline rules anomaly ml_interface risk incidents enforcement state; do
        if python3 -c "import $mod" 2>/dev/null; then
            pass "import $mod"
        else
            fail "import $mod FAILED"
        fi
    done
    cd - > /dev/null
else
    skip "python3 not available — import tests skipped"
fi

# ── 3. main.py Interface Verification ─────────────────────────────
echo -e "\n${BOLD}3. main.py Interface Verification${NC}"

# Verify main.py imports state.py
if grep -q "from state import" opt/falconx/engine/main.py; then
    pass "main.py imports state.py"
else
    fail "main.py does NOT import state.py"
fi

# Verify main.py calls all pipeline stages
for stage in "features.process_batch" "baseline.process_features" "rules.evaluate" "anomaly.analyze" "ml.predict" "risk.assess" "incidents.process_detection" "enforcement.evaluate"; do
    if grep -q "$stage" opt/falconx/engine/main.py; then
        pass "main.py calls $stage"
    else
        fail "main.py does NOT call $stage"
    fi
done

# Verify exception handling
if grep -q "except Exception" opt/falconx/engine/main.py; then
    pass "main.py has exception handling"
else
    fail "main.py missing exception handling"
fi

# ── 4. Capture → Features Interface ───────────────────────────────
echo -e "\n${BOLD}4. Capture → Features Interface${NC}"

# Verify PacketMetadata is defined
if grep -q "class PacketMetadata" opt/falconx/engine/capture.py; then
    pass "PacketMetadata class defined"
else
    fail "PacketMetadata class missing"
fi

# Verify features.py accepts list of metadata
if grep -q "def process_batch(self, packets: List)" opt/falconx/engine/features.py; then
    pass "features.process_batch accepts List"
else
    fail "features.process_batch signature mismatch"
fi

# ── 5. Features → Baseline Interface ──────────────────────────────
echo -e "\n${BOLD}5. Features → Baseline Interface${NC}"

# Verify baseline enriches features
if grep -q "features\[.anomaly_score.\]" opt/falconx/engine/baseline.py; then
    pass "baseline adds anomaly_score to features"
else
    fail "baseline does NOT add anomaly_score"
fi

if grep -q "features\[.device_status.\]" opt/falconx/engine/baseline.py; then
    pass "baseline adds device_status to features"
else
    fail "baseline does NOT add device_status"
fi

if grep -q "features\[.device_reputation.\]" opt/falconx/engine/baseline.py; then
    pass "baseline adds device_reputation to features"
else
    fail "baseline does NOT add device_reputation"
fi

# ── 6. Detection → Risk Interface ─────────────────────────────────
echo -e "\n${BOLD}6. Detection → Risk Interface${NC}"

# Verify risk.assess signature
if grep -q "def assess(self, features: dict, detection_events: list" opt/falconx/engine/risk.py; then
    pass "risk.assess accepts features + detection_events"
else
    fail "risk.assess signature mismatch"
fi

# Verify risk uses anomaly_score from features
if grep -q "anomaly_score" opt/falconx/engine/risk.py; then
    pass "risk reads anomaly_score from features"
else
    fail "risk does NOT read anomaly_score"
fi

# ── 7. Risk → Incidents Interface ─────────────────────────────────
echo -e "\n${BOLD}7. Risk → Incidents Interface${NC}"

# Verify incidents.process_detection signature
if grep -q "def process_detection(self, device_ip: str, event_type: str" opt/falconx/engine/incidents.py; then
    pass "incidents.process_detection has correct signature"
else
    fail "incidents.process_detection signature mismatch"
fi

# Verify incidents persist
if grep -q "def _save(self)" opt/falconx/engine/incidents.py; then
    pass "incidents has persistence (_save)"
else
    fail "incidents missing persistence"
fi

# ── 8. State Machine Integration ──────────────────────────────────
echo -e "\n${BOLD}8. State Machine Integration${NC}"

if grep -q "from state import" opt/falconx/engine/main.py; then
    pass "main.py imports state machine"
else
    fail "main.py does NOT import state machine"
fi

if grep -q "ProtectionState" opt/falconx/engine/main.py; then
    pass "main.py uses ProtectionState"
else
    fail "main.py does NOT use ProtectionState"
fi

# ── 9. Exception Handling ─────────────────────────────────────────
echo -e "\n${BOLD}9. Exception Handling${NC}"

for mod in capture features baseline rules anomaly; do
    if grep -q "except Exception" "opt/falconx/engine/${mod}.py"; then
        pass "${mod}.py has exception handling"
    else
        fail "${mod}.py missing exception handling"
    fi
done

# ── 10. Bounded Resources ─────────────────────────────────────────
echo -e "\n${BOLD}10. Bounded Resources${NC}"

if grep -q "maxsize=buffer_size" opt/falconx/engine/capture.py; then
    pass "capture.py has bounded queue"
else
    fail "capture.py missing bounded queue"
fi

if grep -q "max_flows" opt/falconx/engine/features.py; then
    pass "features.py has bounded flow table"
else
    fail "features.py missing bounded flow table"
fi

# ── 11. Systemd Services ──────────────────────────────────────────
echo -e "\n${BOLD}11. Systemd Services${NC}"

for svc in falconx-engine falconx-web falconx-health falconx-enforcer; do
    if [[ -f "etc/systemd/system/${svc}.service" ]]; then
        pass "${svc}.service exists"
    else
        fail "${svc}.service MISSING"
    fi
done

# Verify no removed services
for svc in falconx-detector falconx-ai; do
    if [[ ! -f "etc/systemd/system/${svc}.service" ]]; then
        pass "${svc}.service correctly removed"
    else
        fail "${svc}.service still exists"
    fi
done

# ── 12. Firewall ──────────────────────────────────────────────────
echo -e "\n${BOLD}12. Firewall${NC}"

if grep -q "policy drop" etc/nftables/falconx-monitor.nft; then
    pass "Monitor firewall: INPUT DROP policy"
else
    fail "Monitor firewall: missing INPUT DROP"
fi

if grep -q "9100" etc/nftables/falconx-monitor.nft; then
    pass "Firewall allows engine port 9100"
else
    fail "Firewall missing engine port 9100"
fi

# Verify no iptables references in nft files
if ! grep -q "iptables" etc/nftables/falconx-monitor.nft; then
    pass "No iptables in nftables rules"
else
    fail "iptables found in nftables rules"
fi

# ── 13. AppArmor ──────────────────────────────────────────────────
echo -e "\n${BOLD}13. AppArmor${NC}"

if grep -q "main.py" etc/apparmor.d/falconx-engine; then
    pass "Engine AppArmor targets main.py"
else
    fail "Engine AppArmor does NOT target main.py"
fi

# ── 14. Python Pipeline Test ──────────────────────────────────────
echo -e "\n${BOLD}14. Python Pipeline Test${NC}"

if command -v python3 > /dev/null 2>&1; then
    cd opt/falconx/engine
    if python3 test_pipeline.py 2>&1; then
        pass "Pipeline integration tests passed"
    else
        fail "Pipeline integration tests failed"
    fi
    cd - > /dev/null
else
    skip "python3 not available — pipeline test skipped"
fi

# ── Summary ────────────────────────────────────────────────────────
echo -e "\n${BOLD}═══════════════════════════════════════════════${NC}"
echo -e "${BOLD}  Pipeline Integration Test Results${NC}"
echo -e "${BOLD}═══════════════════════════════════════════════${NC}"
echo ""
echo -e "  Total:  $((PASS + FAIL + SKIP))"
echo -e "  ${GREEN}Pass:   $PASS${NC}"
echo -e "  ${RED}Fail:   $FAIL${NC}"
echo -e "  ${YELLOW}Skip:   $SKIP${NC}"
echo ""

if [[ $FAIL -eq 0 ]]; then
    echo -e "  ${GREEN}All pipeline integration tests passed!${NC}"
else
    echo -e "  ${RED}$FAIL test(s) failed${NC}"
fi
echo ""

exit $FAIL
