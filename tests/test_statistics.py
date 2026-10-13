"""Tests for statistics aggregation."""

import pytest

from pcap_report.core.statistics import choose_bucket_size, compute_statistics


def test_totals(stats, records):
    assert stats.total_packets == 12
    assert stats.total_bytes == sum(r.length for r in records)
    assert stats.duration == pytest.approx(4.21, abs=1e-3)
    assert stats.average_packet_size == pytest.approx(stats.total_bytes / 12)


def test_protocol_counts(stats):
    assert stats.protocol_counts["TCP"] == 5
    assert stats.app_protocol_counts == {"HTTP": 4, "DNS": 2, "TLS": 1}
    usage = stats.protocol_usage()
    assert usage[0].name == "TCP"
    assert sum(u.percent for u in usage) == pytest.approx(100)


def test_unique_counts_are_not_truncated_to_top_n(stats):
    assert stats.unique_src_ips == 5
    assert stats.unique_dst_ips == 7


def test_conversations_are_bidirectional(stats):
    http = stats.conversations[0]
    assert http.protocol == "TCP"
    assert {http.addr_a, http.addr_b} == {"192.168.1.10", "93.184.216.34"}
    assert http.packets == 4
    assert http.packets_a_to_b == 2 and http.packets_b_to_a == 2
    assert http.duration == pytest.approx(0.07, abs=1e-3)
    assert len(stats.conversations) == 7


def test_endpoints_and_ports(stats):
    client = stats.endpoints[0]
    assert client.address == "192.168.1.10"
    assert client.packets_sent == 7
    port80 = next(p for p in stats.ports if p.port == 80)
    assert (port80.service, port80.as_source, port80.as_destination) == ("HTTP", 2, 2)


def test_timeline(stats):
    assert stats.timeline_bucket == 0.1
    assert sum(p for _, p, _ in stats.timeline) == 12


def test_empty_statistics():
    empty = compute_statistics([])
    assert empty.total_packets == 0
    assert empty.duration == 0
    assert empty.packets_per_second == 0
    assert empty.conversations == [] and empty.timeline == []


@pytest.mark.parametrize("duration, expected", [(0, 0.001), (1, 0.01), (60, 0.5), (3600, 30)])
def test_choose_bucket_size(duration, expected):
    assert choose_bucket_size(duration) == expected
