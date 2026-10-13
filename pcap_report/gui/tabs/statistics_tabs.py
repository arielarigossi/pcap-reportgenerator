"""Conversations, endpoints, ports and protocol hierarchy tabs."""

from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtWidgets import QSplitter, QVBoxLayout, QWidget

from pcap_report.formatting import fmt_bytes, fmt_count
from pcap_report.gui.table_model import Column
from pcap_report.gui.tabs.table_tab import TableTab


def _num(key, getter, fmt=fmt_count):
    return Column(key, getter, fmt, numeric=True)


class ConversationsTab(TableTab):
    def __init__(self, tr, parent=None):
        columns = [
            Column("protocol", lambda c: c.protocol),
            Column("address_a", lambda c: c.addr_a),
            _num("port_a", lambda c: c.port_a, str),
            Column("address_b", lambda c: c.addr_b),
            _num("port_b", lambda c: c.port_b, str),
            _num("packets", lambda c: c.packets),
            _num("bytes", lambda c: c.bytes, fmt_bytes),
            _num("packets_a_to_b", lambda c: c.packets_a_to_b),
            _num("packets_b_to_a", lambda c: c.packets_b_to_a),
            _num("bytes_a_to_b", lambda c: c.bytes_a_to_b, fmt_bytes),
            _num("bytes_b_to_a", lambda c: c.bytes_b_to_a, fmt_bytes),
            _num("duration", lambda c: c.duration, lambda v: f"{v:.3f} s"),
        ]
        filters = [
            ("filter_conversation", lambda c: c.display_filter()),
            ("filter_address_a", lambda c: f"ip.addr == {c.addr_a}"),
            ("filter_address_b", lambda c: f"ip.addr == {c.addr_b}"),
        ]
        super().__init__(tr, columns, filters, parent=parent)

    def update_stats(self, stats, records):
        self.set_items(stats.conversations)


class EndpointsTab(TableTab):
    def __init__(self, tr, parent=None):
        columns = [
            Column("address", lambda e: e.address),
            _num("packets", lambda e: e.packets),
            _num("bytes", lambda e: e.bytes, fmt_bytes),
            _num("packets_sent", lambda e: e.packets_sent),
            _num("packets_received", lambda e: e.packets_received),
            _num("bytes_sent", lambda e: e.bytes_sent, fmt_bytes),
            _num("bytes_received", lambda e: e.bytes_received, fmt_bytes),
        ]
        filters = [
            ("filter_address", lambda e: f"ip.addr == {e.address}"),
            ("filter_as_source", lambda e: f"ip.src == {e.address}"),
            ("filter_as_destination", lambda e: f"ip.dst == {e.address}"),
        ]
        super().__init__(tr, columns, filters, parent=parent)

    def update_stats(self, stats, records):
        self.set_items(stats.endpoints)


class PortsTab(TableTab):
    def __init__(self, tr, parent=None):
        columns = [
            _num("port", lambda p: p.port, str),
            Column("service", lambda p: p.service),
            _num("packets", lambda p: p.packets),
            _num("as_source", lambda p: p.as_source),
            _num("as_destination", lambda p: p.as_destination),
        ]
        filters = [
            ("filter_port", lambda p: f"port == {p.port}"),
            ("filter_as_source", lambda p: f"srcport == {p.port}"),
            ("filter_as_destination", lambda p: f"dstport == {p.port}"),
        ]
        super().__init__(tr, columns, filters, parent=parent)

    def update_stats(self, stats, records):
        self.set_items(stats.ports)


def _protocol_columns():
    return [
        Column("protocol", lambda u: u.name),
        _num("packets", lambda u: u.packets),
        _num("bytes", lambda u: u.bytes, fmt_bytes),
        _num("percent_packets", lambda u: u.percent, lambda v: f"{v:.1f} %"),
    ]


class ProtocolsTab(QWidget):
    """Transport-level and application-level protocol distribution."""

    filter_requested = pyqtSignal(str)

    def __init__(self, tr, parent=None):
        super().__init__(parent)
        filters = [("filter_protocol", lambda u: f"proto == {u.name}")]
        self.transport = TableTab(tr, _protocol_columns(), filters, "transport_protocols")
        self.application = TableTab(tr, _protocol_columns(), filters, "application_protocols")
        for tab in (self.transport, self.application):
            tab.filter_requested.connect(self.filter_requested)

        splitter = QSplitter(Qt.Horizontal)
        splitter.addWidget(self.transport)
        splitter.addWidget(self.application)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(splitter)

    def update_stats(self, stats, records):
        self.transport.set_items(stats.protocol_usage())
        self.application.set_items(stats.app_protocol_usage())

    def retranslate(self):
        self.transport.retranslate()
        self.application.retranslate()
