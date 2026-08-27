# FALCON-X Detection Engine Documentation

## Architecture

```
Network Traffic → Packet Capture → Feature Extraction → Baseline → Detection → Risk → Incident → Dashboard
                    (Scapy)         (Flow Aggregation)    (Learn)    (Rules+Stats)  (Score)   (Track)
```

## Components

### Packet Capture (`capture.py`)
- Scapy-based async capture with bounded queue (10K packets)
- Graceful overload: drops packets when queue full
- Stores only metadata (not full packets)
- Snap length: 96 bytes (headers only)
- Auto-selects best interface

### Feature Extraction (`features.py`)
- Flow aggregation with configurable timeout (120s)
- 21 features per flow:
  - Flow duration, packet count, byte count
  - PPS, BPS, packet size stats
  - TCP flag rates (SYN/RST/FIN)
  - DNS/ICMP/ARP activity
  - Unique destinations/ports
  - Inter-arrival time statistics
- Bounded flow table (50K max, LRU eviction)

### Baseline Engine (`baseline.py`)
- Per-device behavioral profiles
- 24-hour learning period
- Tracks: destinations, ports, protocols, traffic patterns
- Device states: UNKNOWN → LEARNING → KNOWN
- Anomaly scoring via z-score comparison

### Rule Engine (`rules.py`)
- 10 detection rules:
  - Port scan (15+ unique ports)
  - SYN flood (high SYN ratio)
  - Abnormal connection rate
  - DNS anomaly (query flood)
  - ARP anomaly (ARP flood)
  - Unknown device
  - Brute force (repeated RST)
  - Data exfiltration (high volume)
  - ICMP flood
  - Unusual protocol
- Sliding window counters
- Deterministic, explainable

### Statistical Detector (`anomaly.py`)
- Welford's online algorithm
- Per-IP and global statistics
- Z-score threshold: 3.0
- 13 numeric features monitored
- Streaming (no batch recomputation)

### ML Interface (`ml_interface.py`)
- Isolation Forest when scikit-learn available
- Fallback: distance-based scoring (no dependencies)
- Auto-retrains every 10K samples
- Saves model to `/opt/falconx/models/`
- 16-feature vector

### Risk Engine (`risk.py`)
- Weighted scoring (0-100):
  - Anomaly score (30%)
  - Event severity (25%)
  - Device reputation (20%)
  - Frequency (15%)
  - Confidence (10%)
- Levels: LOW(0-29), MEDIUM(30-59), HIGH(60-79), CRITICAL(80-100)
- Full reasoning chain

### Incident Engine (`incidents.py`)
- Structured incidents with full lifecycle
- States: OPEN → INVESTIGATING → RESOLVED / FALSE_POSITIVE
- Deduplication (5-minute window)
- Auto-close after 72 hours
- Persistent storage

### Enforcement Abstraction (`enforcement.py`)
- **NEVER auto-blocks based on ML alone**
- Modes: log-only, alert, block
- Policy gates: risk threshold + confidence threshold
- Auto-unblock after 30 minutes
- Safe by default

## Configuration

Main config: `/etc/falconx/engine.yaml`

Key settings:
```yaml
capture:
  interface: "auto"        # or "eth0"
  snap_length: 96          # bytes (headers only)
  buffer_size: 10000       # max queued packets
  batch_size: 100          # packets per processing batch

features:
  flow_timeout_seconds: 120
  max_flows: 50000

baseline:
  learning_period_hours: 24
  min_samples: 100

detection:
  sensitivity: "medium"
  rules:
    port_scan:
      enabled: true
      threshold_unique_ports: 15

enforcement:
  mode: "log-only"         # safe default
```

## Running

```bash
# Start engine
sudo systemctl start falconx-engine

# Check status
curl http://127.0.0.1:9100/health

# View stats
curl http://127.0.0.1:9100/stats

# View incidents
curl http://127.0.0.1:9100/incidents

# View logs
falconx logs falconx-engine
```

## Testing

```bash
# Unit tests
cd /opt/falconx/engine
python3 -m pytest test_engine.py -v

# Performance tests
python3 test_performance.py
```

## Dependencies

### Required
- Python 3.9+
- pyyaml

### Optional (for packet capture)
- scapy
- libpcap-dev

### Optional (for ML)
- scikit-learn
- numpy

## Raspberry Pi 4 Performance

Expected performance:
- Throughput: ~500-1000 packets/second
- Memory: ~50-100MB steady state
- CPU: ~20-40% during normal traffic
- Latency: <10ms per batch

## File Structure

```
/opt/falconx/engine/
├── main.py              # Main orchestrator
├── capture.py           # Packet capture (Scapy)
├── features.py          # Feature extraction
├── baseline.py          # Behavioral baseline
├── rules.py             # Rule-based detection
├── anomaly.py           # Statistical anomaly detection
├── ml_interface.py      # ML interface
├── risk.py              # Risk scoring
├── incidents.py         # Incident management
├── enforcement.py       # Enforcement abstraction
├── test_engine.py       # Unit tests
└── test_performance.py  # Performance tests
```
