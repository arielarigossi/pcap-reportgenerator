"""Read capture files into :class:`PacketRecord` objects.

Packets are streamed with scapy's :class:`PcapReader` (which handles both
pcap and pcapng), so only the compact records are kept in memory rather
than a full list of scapy packet objects.
"""

import os

from scapy.all import ARP, DNS, ICMP, IP, TCP, UDP, Ether, IPv6, PcapReader, wrpcap

from pcap_report.core.models import PacketRecord
from pcap_report.core.protocols import (
    HTTP_REQUEST_PREFIXES, HTTP_RESPONSE_PREFIX, guess_app_protocol,
    ip_protocol_name,
)

DNS_QUERY_TYPES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX",
                   16: "TXT", 28: "AAAA", 33: "SRV", 65: "HTTPS", 255: "ANY"}


def read_packets(path, progress=None, control=None, progress_interval=500):
    """Read every packet in *path* and return a list of records.

    Parameters
    ----------
    path : str
        pcap / pcapng file.
    progress : callable, optional
        Called with an integer percentage (0-100) as reading advances.
    control : TaskControl, optional
        Polled between packets to support pause / cancel.
    progress_interval : int
        Number of packets between progress callbacks.
    """
    if not os.path.isfile(path):
        raise FileNotFoundError(path)

    file_size = os.path.getsize(path) or 1
    records = []
    first_ts = None

    with PcapReader(path) as reader:
        for number, pkt in enumerate(reader, start=1):
            if control is not None:
                control.checkpoint()
            ts = float(pkt.time)
            if first_ts is None:
                first_ts = ts
            records.append(packet_to_record(pkt, number, ts - first_ts))

            if progress is not None and number % progress_interval == 0:
                progress(_reader_percent(reader, file_size))

    if progress is not None:
        progress(100)
    return records


def _reader_percent(reader, file_size):
    try:
        return min(99, int(reader.f.tell() * 100 / file_size))
    except (AttributeError, OSError, ValueError):
        return 0


def packet_to_record(pkt, number, relative_time=0.0):
    """Dissect one scapy packet into a :class:`PacketRecord`."""
    raw = bytes(pkt)
    wirelen = getattr(pkt, "wirelen", None)
    rec = PacketRecord(
        number=number,
        timestamp=float(pkt.time),
        relative_time=relative_time,
        length=wirelen or len(raw),
        src="",
        dst="",
        protocol=pkt.lastlayer().name,
        raw=raw,
        layer_cls=type(pkt),
    )

    if Ether in pkt:
        rec.src_mac = pkt[Ether].src
        rec.dst_mac = pkt[Ether].dst
        rec.src, rec.dst = rec.src_mac, rec.dst_mac

    if IP in pkt:
        ip = pkt[IP]
        rec.src, rec.dst = ip.src, ip.dst
        rec.ip_version, rec.ttl = 4, ip.ttl
        rec.protocol = ip_protocol_name(ip.proto)
    elif IPv6 in pkt:
        ip6 = pkt[IPv6]
        rec.src, rec.dst = ip6.src, ip6.dst
        rec.ip_version, rec.ttl = 6, ip6.hlim
        rec.protocol = ip_protocol_name(ip6.nh)
    elif ARP in pkt:
        _fill_arp(rec, pkt[ARP])
        return rec

    if TCP in pkt:
        _fill_tcp(rec, pkt[TCP])
    elif UDP in pkt:
        _fill_udp(rec, pkt[UDP])
    elif ICMP in pkt:
        icmp = pkt[ICMP]
        rec.protocol = "ICMP"
        rec.info = f"{icmp.sprintf('%ICMP.type%')} (type={icmp.type}, code={icmp.code})"
    elif rec.protocol == "ICMPv6":
        rec.info = pkt[IPv6].payload.name

    if DNS in pkt:
        rec.app_protocol = "DNS"
        rec.info = _dns_info(pkt[DNS]) or rec.info
    if not rec.info:
        rec.info = pkt.summary()
    return rec


def _fill_arp(rec, arp):
    rec.protocol = "ARP"
    rec.src, rec.dst = arp.psrc, arp.pdst
    if arp.op == 1:
        rec.info = f"Who has {arp.pdst}? Tell {arp.psrc}"
    elif arp.op == 2:
        rec.info = f"{arp.psrc} is at {arp.hwsrc}"
    else:
        rec.info = f"ARP op={arp.op}"


def _fill_tcp(rec, tcp):
    rec.protocol = "TCP"
    rec.sport, rec.dport = int(tcp.sport), int(tcp.dport)
    rec.tcp_flags = str(tcp.flags)
    payload = bytes(tcp.payload)
    rec.app_protocol = guess_app_protocol(rec.sport, rec.dport)
    http_line = _http_first_line(payload)
    if http_line:
        rec.app_protocol = "HTTP"
        rec.info = http_line
        return
    rec.info = (
        f"{rec.sport} → {rec.dport} [{rec.tcp_flags}] "
        f"Seq={tcp.seq} Ack={tcp.ack} Win={tcp.window} Len={len(payload)}"
    )


def _fill_udp(rec, udp):
    rec.protocol = "UDP"
    rec.sport, rec.dport = int(udp.sport), int(udp.dport)
    rec.app_protocol = guess_app_protocol(rec.sport, rec.dport)
    rec.info = f"{rec.sport} → {rec.dport} Len={len(bytes(udp.payload))}"


def _http_first_line(payload):
    if payload.startswith(HTTP_REQUEST_PREFIXES) or payload.startswith(HTTP_RESPONSE_PREFIX):
        line = payload.split(b"\r\n", 1)[0][:200]
        return line.decode("latin-1", errors="replace")
    return ""


def _dns_info(dns):
    try:
        name = ""
        qtype = ""
        if dns.qdcount and dns.qd:
            question = dns.qd[0]
            name = question.qname.decode("utf-8", errors="replace").rstrip(".")
            qtype = DNS_QUERY_TYPES.get(question.qtype, str(question.qtype))
        kind = "Standard query response" if dns.qr else "Standard query"
        return f"{kind} 0x{dns.id:04x} {qtype} {name}".rstrip()
    except Exception:  # malformed DNS payloads should never break parsing
        return ""


def decode_record(record):
    """Rebuild the full scapy packet for a record (for detail views)."""
    cls = record.layer_cls or Ether
    pkt = cls(record.raw)
    pkt.time = record.timestamp
    return pkt


def write_records(records, path):
    """Save records back to a pcap file."""
    wrpcap(path, [decode_record(r) for r in records])
