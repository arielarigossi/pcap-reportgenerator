"""Tests for the display filter language."""

import pytest

from pcap_report.core.filters import FilterSyntaxError, apply_filter, compile_filter


def numbers(records, text):
    return [r.number for r in apply_filter(records, text)]


@pytest.mark.parametrize("text, expected", [
    ("tcp", [1, 2, 3, 4, 11]),
    ("TCP", [1, 2, 3, 4, 11]),
    ("udp", [5, 6]),
    ("dns", [5, 6]),
    ("http", [1, 2, 3, 4]),
    ("https", [11]),
    ("http or tls", [1, 2, 3, 4, 11]),
    ("http || tls", [1, 2, 3, 4, 11]),
    ("icmp", [7, 8]),
    ("arp", [9]),
    ("ipv6", [10]),
    ("gre", [12]),
    ("not (tcp or udp)", [7, 8, 9, 10, 12]),
    ("!tcp && !udp", [7, 8, 9, 10, 12]),
    ("ip.src == 192.168.1.10 and tcp", [1, 3, 11]),
    ("ip.dst eq 8.8.8.8", [5]),
    ("ip.addr == 8.8.8.8", [5, 6]),
    ("host 1.1.1.1", [7, 8]),
    ("ip.addr == 10.0.0.0/8", [11, 12]),
    ("ip.src != 192.168.1.10", [2, 4, 6, 8, 10]),
    ("port 53", [5, 6]),
    ("tcp.port == 443", [11]),
    ("udp.port == 80", []),
    ("srcport == 80", [2, 4]),
    ("dport >= 51000", [2, 4, 6]),
    ("len > 1000", [4]),
    ("frame.len <= 42 and icmp", [7, 8]),
    ("frame.number < 3", [1, 2]),
    ("time > 4", [11, 12]),
    ("tcp.flags contains S", [1, 2, 11]),
    ("tcp.flags == SA", [2]),
    ('info contains "example.com"', [5, 6]),
    ("info contains GET", [3]),
    ('proto matches "^(HTTP|TLS)$"', [1, 2, 3, 4, 11]),
    ("eth.dst == ff:ff:ff:ff:ff:ff", [9]),
    ("ip.version == 6", [10]),
    ("(tcp and port 80) or (udp and port 53)", [1, 2, 3, 4, 5, 6]),
    ("tcp.flags", [1, 2, 3, 4, 11]),
])
def test_filter_matches(records, text, expected):
    assert numbers(records, text) == expected


@pytest.mark.parametrize("text", ["", "   ", None])
def test_empty_filter_matches_everything(records, text):
    assert compile_filter(text) is None
    assert len(apply_filter(records, text or "")) == len(records)


@pytest.mark.parametrize("text", [
    "ip.addr ==",
    "(tcp",
    "tcp)",
    "tcp and",
    "len > abc",
    "ip.src > 10.0.0.1",
    "ip.addr == 10.0.0.0/99",
    'info matches "("',
    "proto < tcp",
    "a = b",
    "tcp &&& udp",
])
def test_invalid_filters_raise(text):
    with pytest.raises(FilterSyntaxError):
        compile_filter(text)


def test_conversation_display_filter_selects_conversation(records, stats):
    for conv in stats.conversations:
        selected = apply_filter(records, conv.display_filter())
        assert len(selected) == conv.packets, conv.display_filter()
