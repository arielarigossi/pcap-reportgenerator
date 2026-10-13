"""Tests for capture parsing."""

import pytest

from pcap_report.core.control import TaskCancelled, TaskControl
from pcap_report.core.parser import decode_record, read_packets, write_records


def test_reads_all_packets(records):
    assert [r.number for r in records] == list(range(1, 13))
    assert records[0].relative_time == 0
    assert records[-1].relative_time == pytest.approx(4.21, abs=1e-3)


def test_tcp_and_http_dissection(records):
    syn, _, get, response = records[:4]
    assert (syn.protocol, syn.app_protocol, syn.sport, syn.dport) == ("TCP", "HTTP", 51000, 80)
    assert syn.tcp_flags == "S"
    assert get.info == "GET /index.html HTTP/1.1"
    assert response.info == "HTTP/1.1 200 OK"
    assert response.length > 1200


def test_dns_icmp_arp_ipv6(records):
    assert records[4].app_protocol == "DNS"
    assert "example.com" in records[4].info
    assert "response" in records[5].info
    assert records[6].protocol == "ICMP" and "echo-request" in records[6].info
    arp = records[8]
    assert (arp.protocol, arp.src, arp.dst) == ("ARP", "192.168.1.10", "192.168.1.1")
    assert arp.info == "Who has 192.168.1.1? Tell 192.168.1.10"
    assert (records[9].protocol, records[9].ip_version) == ("ICMPv6", 6)
    assert records[11].protocol == "GRE"


def test_progress_reaches_100(sample_pcap):
    seen = []
    read_packets(sample_pcap, progress=seen.append, progress_interval=5)
    assert seen[-1] == 100
    assert all(0 <= p <= 100 for p in seen)


def test_cancel_stops_reading(sample_pcap):
    control = TaskControl()
    control.cancel()
    with pytest.raises(TaskCancelled):
        read_packets(sample_pcap, control=control)


def test_missing_file_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        read_packets(str(tmp_path / "missing.pcap"))


def test_decode_and_write_roundtrip(records, tmp_path):
    assert decode_record(records[2]).haslayer("TCP")
    out = tmp_path / "subset.pcap"
    write_records(records[4:6], str(out))
    again = read_packets(str(out))
    assert [r.info for r in again] == [r.info for r in records[4:6]]
    assert again[0].timestamp == pytest.approx(records[4].timestamp)
