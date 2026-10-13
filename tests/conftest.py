"""Shared fixtures: a small synthetic capture covering common protocols."""

import os

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
os.environ.setdefault("MPLBACKEND", "Agg")

BASE_TIME = 1700000000.0


def _build_packets():
    from scapy.all import (
        ARP, DNS, DNSQR, DNSRR, GRE, ICMP, IP, TCP, UDP, Ether, ICMPv6ND_RS, IPv6, Raw,
    )

    eth = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb")
    client, server, dns = "192.168.1.10", "93.184.216.34", "8.8.8.8"
    spec = [
        (0.00, eth / IP(src=client, dst=server) / TCP(sport=51000, dport=80, flags="S")),
        (0.01, eth / IP(src=server, dst=client) / TCP(sport=80, dport=51000, flags="SA")),
        (0.02, eth / IP(src=client, dst=server) / TCP(sport=51000, dport=80, flags="PA")
         / Raw(b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n")),
        (0.07, eth / IP(src=server, dst=client) / TCP(sport=80, dport=51000, flags="PA")
         / Raw(b"HTTP/1.1 200 OK\r\n\r\n" + b"x" * 1200)),
        (0.57, eth / IP(src=client, dst=dns) / UDP(sport=53000, dport=53)
         / DNS(id=0x1234, rd=1, qd=DNSQR(qname="example.com"))),
        (0.59, eth / IP(src=dns, dst=client) / UDP(sport=53, dport=53000)
         / DNS(id=0x1234, qr=1, qd=DNSQR(qname="example.com"),
               an=DNSRR(rrname="example.com", rdata=server))),
        (1.59, eth / IP(src=client, dst="1.1.1.1") / ICMP()),
        (1.61, eth / IP(src="1.1.1.1", dst=client) / ICMP(type=0)),
        (1.91, Ether(src="00:11:22:33:44:55", dst="ff:ff:ff:ff:ff:ff")
         / ARP(psrc=client, pdst="192.168.1.1")),
        (2.11, eth / IPv6(src="fe80::1", dst="ff02::1") / ICMPv6ND_RS()),
        (4.11, eth / IP(src=client, dst="10.0.0.5") / TCP(sport=40000, dport=443, flags="S")),
        (4.21, eth / IP(src=client, dst="10.0.0.5") / GRE() / Raw(b"x")),
    ]
    packets = []
    for offset, pkt in spec:
        pkt.time = BASE_TIME + offset
        packets.append(pkt)
    return packets


@pytest.fixture(scope="session")
def sample_pcap(tmp_path_factory):
    from scapy.all import wrpcap

    path = tmp_path_factory.mktemp("captures") / "sample.pcap"
    wrpcap(str(path), _build_packets())
    return str(path)


@pytest.fixture(scope="session")
def records(sample_pcap):
    from pcap_report.core.parser import read_packets

    return read_packets(sample_pcap)


@pytest.fixture(scope="session")
def stats(records):
    from pcap_report.core.statistics import compute_statistics

    return compute_statistics(records)
