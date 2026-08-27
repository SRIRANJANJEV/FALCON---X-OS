"""FALCON-X Engine — packet capture module.

Uses Scapy for packet capture with bounded queues, async processing,
and graceful overload behavior.
"""

import logging
import queue
import threading
import time
from typing import Callable, Optional

logger = logging.getLogger("falconx-engine.capture")

# Optional Scapy import — degrade gracefully if unavailable
try:
    from scapy.all import (
        AsyncSniffer,
        IP,
        TCP,
        UDP,
        ICMP,
        ARP,
        DNS,
        DNSQR,
        conf,
        get_if_list,
    )
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    logger.warning("Scapy not available — packet capture disabled")


class PacketMetadata:
    """Lightweight packet representation — stores metadata only, not full packet."""

    __slots__ = (
        "timestamp", "src_ip", "dst_ip", "src_port", "dst_port",
        "protocol", "size", "tcp_flags", "is_syn", "is_rst", "is_fin",
        "dns_query", "dns_type", "icmp_type", "arp_op", "arp_src_mac",
        "arp_dst_mac", "raw_entropy",
    )

    def __init__(self):
        self.timestamp: float = 0.0
        self.src_ip: str = ""
        self.dst_ip: str = ""
        self.src_port: int = 0
        self.dst_port: int = 0
        self.protocol: str = ""
        self.size: int = 0
        self.tcp_flags: int = 0
        self.is_syn: bool = False
        self.is_rst: bool = False
        self.is_fin: bool = False
        self.dns_query: str = ""
        self.dns_type: str = ""
        self.icmp_type: int = -1
        self.arp_op: int = 0
        self.arp_src_mac: str = ""
        self.arp_dst_mac: str = ""
        self.raw_entropy: float = 0.0

    def to_dict(self) -> dict:
        return {k: getattr(self, k) for k in self.__slots__}


def _estimate_entropy(data: bytes) -> float:
    """Estimate Shannon entropy of raw payload (0.0–8.0)."""
    if not data:
        return 0.0
    import math
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    length = len(data)
    entropy = 0.0
    for count in freq:
        if count:
            p = count / length
            entropy -= p * math.log2(p)
    return entropy


def _parse_packet(raw_pkt) -> Optional[PacketMetadata]:
    """Extract metadata from a raw Scapy packet. Never raises."""
    if not SCAPY_AVAILABLE:
        return None

    try:
        meta = PacketMetadata()
        meta.timestamp = time.time()

        if not raw_pkt.haslayer(IP):
            return None

        ip = raw_pkt[IP]
        meta.src_ip = ip.src
        meta.dst_ip = ip.dst
        meta.size = len(raw_pkt)

        # TCP
        if raw_pkt.haslayer(TCP):
            tcp = raw_pkt[TCP]
            meta.protocol = "TCP"
            meta.src_port = tcp.sport
            meta.dst_port = tcp.dport
            meta.tcp_flags = int(tcp.flags)
            meta.is_syn = bool(tcp.flags & 0x02)
            meta.is_rst = bool(tcp.flags & 0x04)
            meta.is_fin = bool(tcp.flags & 0x01)
            if tcp.payload:
                meta.raw_entropy = _estimate_entropy(bytes(tcp.payload)[:256])

        # UDP
        elif raw_pkt.haslayer(UDP):
            udp = raw_pkt[UDP]
            meta.protocol = "UDP"
            meta.src_port = udp.sport
            meta.dst_port = udp.dport

            # DNS
            if raw_pkt.haslayer(DNS) and raw_pkt.haslayer(DNSQR):
                dns = raw_pkt[DNS]
                qr = raw_pkt[DNSQR]
                meta.dns_query = qr.qname.decode("utf-8", errors="replace").rstrip(".")
                meta.dns_type = str(qr.qtype)
                if dns.qr == 1:
                    meta.protocol = "DNS_RESPONSE"
                else:
                    meta.protocol = "DNS_REQUEST"

        # ICMP
        elif raw_pkt.haslayer(ICMP):
            icmp = raw_pkt[ICMP]
            meta.protocol = "ICMP"
            meta.icmp_type = icmp.type

        # ARP
        elif raw_pkt.haslayer(ARP):
            arp = raw_pkt[ARP]
            meta.protocol = "ARP"
            meta.arp_op = arp.op
            meta.arp_src_mac = arp.hwsrc
            meta.arp_dst_mac = arp.hwdst
            meta.src_ip = arp.psrc
            meta.dst_ip = arp.pdst

        else:
            meta.protocol = f"OTHER({ip.proto})"

        return meta
    except Exception:
        # Malformed packet — skip silently
        return None


class PacketCapture:
    """Bounded, async packet capture with graceful overload.

    Packets are placed into a bounded queue. If the queue is full,
    packets are dropped (graceful overload). The consumer processes
    packets in batches.
    """

    def __init__(
        self,
        interface: str = "auto",
        bpf_filter: str = "",
        snap_length: int = 96,
        buffer_size: int = 10000,
        batch_size: int = 100,
        flush_interval_ms: int = 100,
        on_batch: Optional[Callable] = None,
    ):
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.snap_length = snap_length
        self.buffer_size = buffer_size
        self.batch_size = batch_size
        self.flush_interval = flush_interval_ms / 1000.0
        self.on_batch = on_batch

        self._packet_queue: queue.Queue = queue.Queue(maxsize=buffer_size)
        self._sniffer: Optional[AsyncSniffer] = None
        self._running = False
        self._worker_thread: Optional[threading.Thread] = None

        # Stats
        self._packets_captured = 0
        self._packets_dropped = 0
        self._batches_processed = 0
        self._last_stats_time = time.time()

    def discover_interfaces(self) -> list:
        """List available network interfaces."""
        if not SCAPY_AVAILABLE:
            logger.error("Scapy not available")
            return []
        try:
            ifaces = get_if_list()
            logger.info("Discovered interfaces: %s", ifaces)
            return ifaces
        except Exception as e:
            logger.error("Interface discovery failed: %s", e)
            return []

    def select_interface(self) -> str:
        """Auto-select the best capture interface."""
        if self.interface != "auto":
            return self.interface

        ifaces = self.discover_interfaces()
        if not ifaces:
            logger.error("No interfaces found")
            return ""

        # Prefer eth0, then first non-loopback
        for iface in ifaces:
            if "eth" in iface.lower():
                logger.info("Selected interface: %s", iface)
                return iface

        for iface in ifaces:
            if "lo" not in iface.lower():
                logger.info("Selected interface: %s", iface)
                return iface

        return ifaces[0] if ifaces else ""

    def _on_packet(self, pkt):
        """Callback for each captured packet — puts metadata into queue."""
        meta = _parse_packet(pkt)
        if meta is None:
            return

        self._packets_captured += 1

        try:
            self._packet_queue.put_nowait(meta)
        except queue.Full:
            self._packets_dropped += 1

    def _batch_worker(self):
        """Worker thread that drains queue into batches and calls on_batch."""
        while self._running:
            batch = []
            deadline = time.time() + self.flush_interval

            while len(batch) < self.batch_size and time.time() < deadline:
                try:
                    remaining = deadline - time.time()
                    if remaining <= 0:
                        break
                    meta = self._packet_queue.get(timeout=min(remaining, 0.01))
                    batch.append(meta)
                except queue.Empty:
                    continue

            if batch and self.on_batch:
                try:
                    self.on_batch(batch)
                    self._batches_processed += 1
                except Exception as e:
                    logger.error("Batch callback error: %s", e)

    def start(self) -> bool:
        """Start packet capture."""
        if not SCAPY_AVAILABLE:
            logger.error("Cannot start capture: Scapy not available")
            return False

        if self._running:
            logger.warning("Capture already running")
            return True

        iface = self.select_interface()
        if not iface:
            logger.error("No interface available for capture")
            return False

        self._running = True

        # Start batch processing worker
        self._worker_thread = threading.Thread(
            target=self._batch_worker, daemon=True, name="falconx-batch-worker"
        )
        self._worker_thread.start()

        # Start Scapy sniffer
        try:
            kwargs = {
                "iface": iface,
                "prn": self._on_packet,
                "store": False,
                "count": 0,
            }
            if self.bpf_filter:
                kwargs["filter"] = self.bpf_filter
            if self.snap_length:
                kwargs["snaplen"] = self.snap_length

            self._sniffer = AsyncSniffer(**kwargs)
            self._sniffer.start()
            logger.info("Packet capture started on %s (snap=%d)", iface, self.snap_length)
            return True
        except Exception as e:
            logger.error("Failed to start capture: %s", e)
            self._running = False
            return False

    def stop(self):
        """Stop packet capture gracefully."""
        self._running = False

        if self._sniffer:
            try:
                self._sniffer.stop()
            except Exception:
                pass
            self._sniffer = None

        if self._worker_thread:
            self._worker_thread.join(timeout=5)
            self._worker_thread = None

        logger.info(
            "Capture stopped. captured=%d dropped=%d batches=%d",
            self._packets_captured,
            self._packets_dropped,
            self._batches_processed,
        )

    def get_stats(self) -> dict:
        return {
            "running": self._running,
            "packets_captured": self._packets_captured,
            "packets_dropped": self._packets_dropped,
            "queue_size": self._packet_queue.qsize(),
            "batches_processed": self._batches_processed,
            "drop_rate": (
                self._packets_dropped / max(self._packets_captured, 1)
            ),
        }
