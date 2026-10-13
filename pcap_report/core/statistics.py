"""Aggregate statistics computed from a list of packet records."""

from collections import Counter
from dataclasses import dataclass, field
from typing import List, Tuple

from pcap_report.config import TIMELINE_MAX_BUCKETS
from pcap_report.core.models import (
    Conversation, Endpoint, PortUsage, ProtocolUsage,
)
from pcap_report.core.protocols import service_name

# Candidate timeline bucket widths, in seconds.
_BUCKET_SIZES = (0.001, 0.01, 0.1, 0.5, 1, 5, 10, 30, 60, 300, 600, 1800, 3600, 86400)


@dataclass
class CaptureStatistics:
    total_packets: int = 0
    total_bytes: int = 0
    first_timestamp: float = 0.0
    last_timestamp: float = 0.0
    protocol_counts: Counter = field(default_factory=Counter)
    protocol_bytes: Counter = field(default_factory=Counter)
    app_protocol_counts: Counter = field(default_factory=Counter)
    app_protocol_bytes: Counter = field(default_factory=Counter)
    src_ip_counts: Counter = field(default_factory=Counter)
    dst_ip_counts: Counter = field(default_factory=Counter)
    src_port_counts: Counter = field(default_factory=Counter)
    dst_port_counts: Counter = field(default_factory=Counter)
    conversations: List[Conversation] = field(default_factory=list)
    endpoints: List[Endpoint] = field(default_factory=list)
    ports: List[PortUsage] = field(default_factory=list)
    timeline_bucket: float = 1.0
    timeline: List[Tuple[float, int, int]] = field(default_factory=list)

    # -- derived values ----------------------------------------------------- #

    @property
    def duration(self):
        return max(0.0, self.last_timestamp - self.first_timestamp)

    @property
    def average_packet_size(self):
        return self.total_bytes / self.total_packets if self.total_packets else 0.0

    @property
    def packets_per_second(self):
        return self.total_packets / self.duration if self.duration else 0.0

    @property
    def bits_per_second(self):
        return self.total_bytes * 8 / self.duration if self.duration else 0.0

    @property
    def unique_src_ips(self):
        return len(self.src_ip_counts)

    @property
    def unique_dst_ips(self):
        return len(self.dst_ip_counts)

    def top_sources(self, n=10):
        return self.src_ip_counts.most_common(n)

    def top_destinations(self, n=10):
        return self.dst_ip_counts.most_common(n)

    def top_source_ports(self, n=10):
        return self.src_port_counts.most_common(n)

    def top_destination_ports(self, n=10):
        return self.dst_port_counts.most_common(n)

    def top_conversations(self, n=10):
        return self.conversations[:n]

    def protocol_usage(self):
        return _usage(self.protocol_counts, self.protocol_bytes, self.total_packets)

    def app_protocol_usage(self):
        return _usage(self.app_protocol_counts, self.app_protocol_bytes, self.total_packets)


def _usage(counts, byte_counts, total):
    return [
        ProtocolUsage(name, packets, byte_counts[name],
                      packets * 100.0 / total if total else 0.0)
        for name, packets in counts.most_common()
    ]


def compute_statistics(records):
    """Aggregate *records* into a :class:`CaptureStatistics`."""
    stats = CaptureStatistics()
    if not records:
        return stats

    conversations = {}
    endpoints = {}
    ports = {}

    stats.first_timestamp = min(r.timestamp for r in records)
    stats.last_timestamp = max(r.timestamp for r in records)

    for rec in records:
        size = rec.length
        stats.total_packets += 1
        stats.total_bytes += size
        stats.protocol_counts[rec.protocol] += 1
        stats.protocol_bytes[rec.protocol] += size
        if rec.app_protocol:
            stats.app_protocol_counts[rec.app_protocol] += 1
            stats.app_protocol_bytes[rec.app_protocol] += size

        if not (rec.src and rec.dst):
            continue
        stats.src_ip_counts[rec.src] += 1
        stats.dst_ip_counts[rec.dst] += 1

        if rec.sport is not None:
            stats.src_port_counts[rec.sport] += 1
            _port(ports, rec.sport).as_source += 1
        if rec.dport is not None:
            stats.dst_port_counts[rec.dport] += 1
            _port(ports, rec.dport).as_destination += 1

        _endpoint(endpoints, rec.src).packets_sent += 1
        _endpoint(endpoints, rec.src).bytes_sent += size
        _endpoint(endpoints, rec.dst).packets_received += 1
        _endpoint(endpoints, rec.dst).bytes_received += size

        _add_to_conversation(conversations, rec)

    stats.conversations = sorted(conversations.values(), key=lambda c: c.packets, reverse=True)
    stats.endpoints = sorted(endpoints.values(), key=lambda e: e.packets, reverse=True)
    stats.ports = sorted(ports.values(), key=lambda p: p.packets, reverse=True)
    stats.timeline_bucket, stats.timeline = _timeline(records, stats)
    return stats


def _port(ports, number):
    if number not in ports:
        ports[number] = PortUsage(number, service_name(number))
    return ports[number]


def _endpoint(endpoints, address):
    if address not in endpoints:
        endpoints[address] = Endpoint(address)
    return endpoints[address]


def _add_to_conversation(conversations, rec):
    side_src = (rec.src, rec.sport)
    side_dst = (rec.dst, rec.dport)
    a, b = sorted((side_src, side_dst), key=lambda s: (s[0], -1 if s[1] is None else s[1]))
    key = (rec.protocol, a, b)
    conv = conversations.get(key)
    if conv is None:
        conv = Conversation(rec.protocol, a[0], a[1], b[0], b[1],
                            first_seen=rec.timestamp, last_seen=rec.timestamp)
        conversations[key] = conv
    if side_src == a:
        conv.packets_a_to_b += 1
        conv.bytes_a_to_b += rec.length
    else:
        conv.packets_b_to_a += 1
        conv.bytes_b_to_a += rec.length
    conv.first_seen = min(conv.first_seen, rec.timestamp)
    conv.last_seen = max(conv.last_seen, rec.timestamp)


def choose_bucket_size(duration, max_buckets=TIMELINE_MAX_BUCKETS):
    for size in _BUCKET_SIZES:
        if duration / size <= max_buckets:
            return size
    return _BUCKET_SIZES[-1]


def _timeline(records, stats):
    """Packets and bytes per time bucket, relative to the first packet."""
    bucket = choose_bucket_size(stats.duration)
    count = int(stats.duration // bucket) + 1
    packets = [0] * count
    volume = [0] * count
    for rec in records:
        idx = min(count - 1, int((rec.timestamp - stats.first_timestamp) // bucket))
        packets[idx] += 1
        volume[idx] += rec.length
    return bucket, [(i * bucket, packets[i], volume[i]) for i in range(count)]
