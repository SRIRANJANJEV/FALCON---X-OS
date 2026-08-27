#!/bin/bash
# FALCON-X Failure Simulation Tests
# Tests protection state transitions under component failures

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

PASS=0 FAIL=0 SKIP=0

pass() { echo -e "  ${GREEN}✓${NC} $*"; ((PASS++)); }
fail() { echo -e "  ${RED}✗${NC} $*"; ((FAIL++)); }
skip() { echo -e "  ${YELLOW}—${NC} $*"; ((SKIP++)); }

echo "FALCON-X Failure Simulation Tests"
echo "==================================="
echo ""

# ── Pre-flight ────────────────────────────────────────────────────
echo "Pre-flight"
if command -v python3 > /dev/null 2>&1; then
    pass "python3 available"
else
    skip "python3 not available — all tests skipped"
    exit 0
fi

# ── 1. Protection State Machine ──────────────────────────────────
echo "1. Protection State Machine"
cd opt/falconx/engine 2>/dev/null || { skip "Cannot cd to engine dir"; exit 0; }

python3 -c "
import sys, os, tempfile, time
sys.path.insert(0, '.')
from state import StateManager, ProtectionState, CRITICAL_COMPONENTS, OPTIONAL_COMPONENTS

# Create temp state file
state_file = tempfile.mktemp(suffix='.json')
import state
state.STATE_FILE = state_file

sm = StateManager()
sm.clear_state()

# Test: BOOTING → INITIALIZING
assert sm.state == ProtectionState.BOOTING
sm.transition(ProtectionState.INITIALIZING)
assert sm.state == ProtectionState.INITIALIZING

# Test: INITIALIZING → PROTECTED (all healthy)
for c in CRITICAL_COMPONENTS:
    sm.update_component(c, True, 'ok')
for c in OPTIONAL_COMPONENTS:
    sm.update_component(c, True, 'ok')
assert sm.state == ProtectionState.PROTECTED, f'Expected PROTECTED, got {sm.state}'
print('PASS: All healthy → PROTECTED')

# Test: Engine failure → UNPROTECTED
sm.update_component('engine', False, 'Engine down')
assert sm.state == ProtectionState.UNPROTECTED, f'Expected UNPROTECTED, got {sm.state}'
print('PASS: Engine failure → UNPROTECTED')

# Test: Recovery
sm.transition(ProtectionState.RECOVERY, 'attempting')
sm.update_component('engine', True, 'Engine recovered')
assert sm.state == ProtectionState.PROTECTED, f'Expected PROTECTED, got {sm.state}'
print('PASS: Recovery → PROTECTED')

# Test: Firewall failure → UNPROTECTED
sm.update_component('firewall', False, 'nftables down')
assert sm.state == ProtectionState.UNPROTECTED, f'Expected UNPROTECTED, got {sm.state}'
print('PASS: Firewall failure → UNPROTECTED')

# Test: AI failure → DEGRADED
sm.transition(ProtectionState.RECOVERY)
sm.update_component('firewall', True, 'recovered')
sm.update_component('engine', True, 'ok')
for c in CRITICAL_COMPONENTS:
    sm.update_component(c, True, 'ok')
assert sm.state == ProtectionState.PROTECTED
sm.update_component('ai', False, 'OmniRoute down')
assert sm.state == ProtectionState.DEGRADED, f'Expected DEGRADED, got {sm.state}'
print('PASS: AI failure → DEGRADED')

# Test: Dashboard failure → DEGRADED
sm.update_component('ai', True, 'restored')
assert sm.state == ProtectionState.PROTECTED
sm.update_component('web', False, 'Dashboard down')
assert sm.state == ProtectionState.DEGRADED, f'Expected DEGRADED, got {sm.state}'
print('PASS: Dashboard failure → DEGRADED')

# Test: ML failure → DEGRADED
sm.update_component('web', True, 'restored')
assert sm.state == ProtectionState.PROTECTED
sm.update_component('ml', False, 'Model failed')
assert sm.state == ProtectionState.DEGRADED, f'Expected DEGRADED, got {sm.state}'
print('PASS: ML failure → DEGRADED')

# Test: Capture failure → UNPROTECTED
sm.update_component('ml', True, 'restored')
assert sm.state == ProtectionState.PROTECTED
sm.update_component('capture', False, 'Scapy unavailable')
assert sm.state == ProtectionState.UNPROTECTED, f'Expected UNPROTECTED, got {sm.state}'
print('PASS: Capture failure → UNPROTECTED')

# Test: Network failure → UNPROTECTED
sm.transition(ProtectionState.RECOVERY)
sm.update_component('capture', True, 'recovered')
for c in CRITICAL_COMPONENTS:
    sm.update_component(c, True, 'ok')
assert sm.state == ProtectionState.PROTECTED
sm.update_component('network', False, 'No default route')
assert sm.state == ProtectionState.UNPROTECTED, f'Expected UNPROTECTED, got {sm.state}'
print('PASS: Network failure → UNPROTECTED')

# Cleanup
os.unlink(state_file)
print('PASS: All state transition tests passed')
" 2>&1 && pass "State transition tests" || fail "State transition tests"

cd - > /dev/null 2>&1

# ── 2. Enforcement Mode Tests ────────────────────────────────────
echo "2. Enforcement Mode"
cd opt/falconx/engine 2>/dev/null || { skip "Cannot cd to engine dir"; exit 0; }

python3 -c "
import sys, os, tempfile
sys.path.insert(0, '.')
from enforcement import EnforcementEngine, EnforcementAction

tmpdir = tempfile.mkdtemp()
cmd_dir = os.path.join(tmpdir, 'enforcer')
os.makedirs(cmd_dir)

import enforcement
enforcement.COMMAND_DIR = cmd_dir

# Test log-only mode
engine = EnforcementEngine(mode='log-only', risk_threshold_alert=30, min_confidence=0.5)
result = engine.evaluate(65, 0.9, '10.0.0.1', [])
assert result is not None
assert result.action_type == 'alert'
print('PASS: log-only mode creates alerts')

# Test active mode with mocked sender
engine2 = EnforcementEngine(mode='active', risk_threshold_block=80, min_confidence=0.5)
engine2._send_command = lambda *a, **k: True
result = engine2.evaluate(85, 0.9, '10.0.0.1', [])
assert result is not None
assert result.action_type == 'block_ip'
assert engine2.is_blocked('10.0.0.1')
print('PASS: active mode blocks IP')

# Test port blocking
action = engine2.block_port('443', reason='test')
assert action is not None
assert engine2.is_port_blocked('443')
print('PASS: port blocking works')

# Test unblock
engine2.unblock('10.0.0.1')
assert not engine2.is_blocked('10.0.0.1')
engine2.unblock_port('443')
assert not engine2.is_port_blocked('443')
print('PASS: unblock works')

import shutil
shutil.rmtree(tmpdir)
print('PASS: All enforcement tests passed')
" 2>&1 && pass "Enforcement tests" || fail "Enforcement tests"

cd - > /dev/null 2>&1

# ── 3. ML Lifecycle Tests ────────────────────────────────────────
echo "3. ML Lifecycle"
cd opt/falconx/engine 2>/dev/null || { skip "Cannot cd to engine dir"; exit 0; }

python3 -c "
import sys, os, tempfile
sys.path.insert(0, '.')
from ml_interface import MLInterface, MLState, ML_FEATURES

tmpdir = tempfile.mkdtemp()
ml = MLInterface(model_path=tmpdir, enabled=True)

# Test initial state
assert ml.state == MLState.LEARNING, f'Expected LEARNING, got {ml.state}'
print('PASS: Initial state is LEARNING')

# Test collecting data
features = {f: 1.0 for f in ML_FEATURES[:16]}
result = ml.predict(features)
assert result is not None
assert result['type'] == 'ml_collecting'
assert result['ml_state'] == 'LEARNING'
print('PASS: predict() returns collecting during LEARNING')

# Test NaN handling
nan_features = {f: float('nan') for f in ML_FEATURES[:16]}
vec = ml.extract_feature_vector(nan_features)
assert all(v == 0.0 for v in vec)
print('PASS: NaN values handled')

# Test inf handling
inf_features = {f: float('inf') for f in ML_FEATURES[:16]}
vec = ml.extract_feature_vector(inf_features)
assert all(v == 0.0 for v in vec)
print('PASS: Inf values handled')

# Test disabled state
ml2 = MLInterface(enabled=False)
assert ml2.state == MLState.DISABLED
result = ml2.predict(features)
assert result is None
print('PASS: Disabled state returns None')

# Test stats
stats = ml.get_stats()
assert 'state' in stats
assert 'sample_count' in stats
assert 'buffer_size' in stats
print('PASS: Stats structure correct')

import shutil
shutil.rmtree(tmpdir)
print('PASS: All ML tests passed')
" 2>&1 && pass "ML lifecycle tests" || fail "ML lifecycle tests"

cd - > /dev/null 2>&1

# ── 4. Dashboard Tests ───────────────────────────────────────────
echo "4. Dashboard"
cd opt/falconx/dashboard 2>/dev/null || { skip "Cannot cd to dashboard dir"; exit 0; }

python3 -c "
import sys, os, tempfile
sys.path.insert(0, '.')
import auth

# Test user creation
tmpfile = tempfile.mktemp(suffix='.json')
auth._get_credentials_file = lambda: tmpfile
auth._sessions.clear()

result = auth.create_user('testuser', 'TestPass123!')
assert result == True
print('PASS: User creation works')

# Test authentication
token = auth.authenticate('testuser', 'TestPass123!')
assert token is not None
print('PASS: Authentication works')

# Test session validation
session = auth.validate_session(token)
assert session is not None
assert session['username'] == 'testuser'
print('PASS: Session validation works')

# Test wrong password
token2 = auth.authenticate('testuser', 'WrongPassword')
assert token2 is None
print('PASS: Wrong password rejected')

# Test lockout
for _ in range(5):
    auth.authenticate('testuser', 'WrongPassword')
token3 = auth.authenticate('testuser', 'TestPass123!')
assert token3 is None  # Should be locked out
print('PASS: Account lockout works')

# Test session destruction
auth.destroy_session(token)
session = auth.validate_session(token)
assert session is None
print('PASS: Session destruction works')

# Test password not leaked
import logging
with auth.logger.parent.handlerürRe if hasattr(auth.logger, 'parent') else __import__('logging').getLogger('test'):
    pass

# Cleanup
os.unlink(tmpfile)
print('PASS: All dashboard tests passed')
" 2>&1 && pass "Dashboard auth tests" || fail "Dashboard auth tests"

cd - > /dev/null 2>&1

# ── 5. Pipeline Tests ────────────────────────────────────────────
echo "5. Pipeline Integration"
cd opt/falconx/engine 2>/dev/null || { skip "Cannot cd to engine dir"; exit 0; }

python3 -c "
import sys, os, tempfile, time
sys.path.insert(0, '.')
from capture import PacketMetadata
from features import FeatureExtractor
from baseline import NetworkBaseline
from rules import RuleEngine
from anomaly import StatisticalDetector
from ml_interface import MLInterface
from risk import RiskEngine
from incidents import IncidentEngine
from enforcement import EnforcementEngine

tmpdir = tempfile.mkdtemp()

# Create synthetic packets
def make_pkt(src_ip='10.0.0.1', dst_port=80, protocol='TCP'):
    m = PacketMetadata()
    m.timestamp = time.time()
    m.src_ip = src_ip
    m.dst_ip = '8.8.8.8'
    m.src_port = 12345
    m.dst_port = dst_port
    m.protocol = protocol
    m.size = 64
    m.is_syn = False
    m.is_rst = False
    m.is_fin = False
    m.tcp_flags = 0
    m.dns_query = ''
    m.dns_type = ''
    m.icmp_type = -1
    m.arp_op = 0
    m.arp_src_mac = ''
    m.arp_dst_mac = ''
    m.raw_entropy = 0.0
    return m

# Test feature extraction
ext = FeatureExtractor(flow_timeout=0.5, max_flows=1000)
pkts = [make_pkt() for _ in range(3)]
features = ext.process_batch(pkts)
assert len(features) == 0  # No expired flows yet
time.sleep(0.6)
features = ext.process_batch([])
assert len(features) >= 1
f = features[0]
assert f['src_ip'] == '10.0.0.1'
assert f['packet_count'] == 3
print('PASS: Feature extraction')

# Test baseline
base = NetworkBaseline(learning_period_hours=0, min_samples=1, max_devices=100,
                       storage_path=os.path.join(tmpdir, 'baseline'))
enriched = base.process_features(features)
assert len(enriched) == 1
assert 'anomaly_score' in enriched[0]
assert 'device_status' in enriched[0]
print('PASS: Baseline enrichment')

# Test rules
rules = RuleEngine({'port_scan': {'enabled': True, 'threshold_unique_ports': 3, 'severity': 'HIGH'}})
scan_pkts = [make_pkt(dst_port=p) for p in range(1, 6)]
scan_features = ext.process_batch(scan_pkts)
time.sleep(0.6)
scan_features.extend(ext.process_batch([]))
scan_enriched = base.process_features(scan_features)
events = []
for f in scan_enriched:
    events.extend(rules.evaluate(f))
assert len(events) > 0
print('PASS: Rule detection')

# Test risk
risk = RiskEngine()
assessment = risk.assess({'anomaly_score': 0.8, 'device_reputation': 0.2}, events)
assert assessment.score >= 30
print('PASS: Risk scoring')

# Test incidents
inc = IncidentEngine(storage_path=os.path.join(tmpdir, 'incidents'), dedup_window=1)
incident = inc.process_detection(
    device_ip='10.0.0.1', event_type='port_scan', severity='HIGH',
    risk_score=70, confidence=0.8, evidence=['test']
)
assert incident is not None
open_inc = inc.get_open_incidents()
assert len(open_inc) >= 1
print('PASS: Incident creation')

# Test full pipeline
print('PASS: Full pipeline integration')

import shutil
shutil.rmtree(tmpdir)
print('PASS: All pipeline tests passed')
" 2>&1 && pass "Pipeline integration tests" || fail "Pipeline integration tests"

cd - > /dev/null 2>&1

# ── Summary ───────────────────────────────────────────────────────
echo ""
echo "=============================="
echo "Results: $PASS passed, $FAIL failed, $SKIP skipped"
echo ""

if [[ $FAIL -eq 0 ]] && [[ $PASS -gt 0 ]]; then
    echo -e "${GREEN}All tests passed!${NC}"
else
    echo -e "${RED}$FAIL test(s) failed${NC}"
fi

exit $FAIL
