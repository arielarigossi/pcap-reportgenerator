"""Plain data structures shared by the parser, statistics and UI layers."""

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class PacketRecord:
    """A lightweight, already-dissected view of one captured packet.

    The original bytes are kept in :attr:`raw` (together with the scapy
    layer class needed to decode them) so the full dissection can be
    rebuilt on demand, e.g. for the packet detail view or for saving a
    filtered capture.
    """

    number: int
    timestamp: float
    relative_time: float
    length: int
    src: str
    dst: str
    protocol: str
    app_protocol: str = ""
    sport: Optional[int] = None
    dport: Optional[int] = None
    info: str = ""
    src_mac: str = ""
    dst_mac: str = ""
    tcp_flags: str = ""
    ip_version: Optional[int] = None
    ttl: Optional[int] = None
    raw: bytes = field(default=b"", repr=False)
    layer_cls: Optional[type] = field(default=None, repr=False)

    @property
    def display_protocol(self):
        """Most specific protocol name (application layer if known)."""
        return self.app_protocol or self.protocol

    @property
    def ports(self):
        return tuple(p for p in (self.sport, self.dport) if p is not None)


@dataclass
class Conversation:
    """Bidirectional traffic between two endpoints (A <-> B)."""

    protocol: str
    addr_a: str
    port_a: Optional[int]
    addr_b: str
    port_b: Optional[int]
    packets_a_to_b: int = 0
    packets_b_to_a: int = 0
    bytes_a_to_b: int = 0
    bytes_b_to_a: int = 0
    first_seen: float = 0.0
    last_seen: float = 0.0

    @property
    def packets(self):
        return self.packets_a_to_b + self.packets_b_to_a

    @property
    def bytes(self):
        return self.bytes_a_to_b + self.bytes_b_to_a

    @property
    def duration(self):
        return self.last_seen - self.first_seen

    def label(self):
        a = self.addr_a if self.port_a is None else f"{self.addr_a}:{self.port_a}"
        b = self.addr_b if self.port_b is None else f"{self.addr_b}:{self.port_b}"
        return f"{a} ↔ {b} ({self.protocol})"

    def display_filter(self):
        """Display filter expression selecting this conversation's packets."""
        expr = f"ip.addr == {self.addr_a} and ip.addr == {self.addr_b}"
        if self.protocol in ("TCP", "UDP"):
            proto = self.protocol.lower()
            expr = f"{proto} and {expr}"
            if self.port_a is not None and self.port_b is not None:
                expr += f" and port == {self.port_a} and port == {self.port_b}"
        else:
            expr = f"proto == {self.protocol} and {expr}"
        return expr


@dataclass
class Endpoint:
    """Per-address traffic totals."""

    address: str
    packets_sent: int = 0
    packets_received: int = 0
    bytes_sent: int = 0
    bytes_received: int = 0

    @property
    def packets(self):
        return self.packets_sent + self.packets_received

    @property
    def bytes(self):
        return self.bytes_sent + self.bytes_received


@dataclass
class PortUsage:
    """How often a port number was seen as source and destination."""

    port: int
    service: str
    as_source: int = 0
    as_destination: int = 0

    @property
    def packets(self):
        return self.as_source + self.as_destination


@dataclass
class ProtocolUsage:
    name: str
    packets: int
    bytes: int
    percent: float
