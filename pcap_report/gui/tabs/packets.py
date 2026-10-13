"""Packet list with per-packet dissection tree and hex dump."""

from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtGui import QFontDatabase
from PyQt5.QtWidgets import (
    QMenu, QPlainTextEdit, QSplitter, QTreeWidget, QTreeWidgetItem, QVBoxLayout,
    QWidget,
)
from scapy.packet import NoPayload
from scapy.utils import hexdump

from pcap_report.core.parser import decode_record
from pcap_report.formatting import fmt_seconds
from pcap_report.gui.table_model import Column, ObjectTableModel, SearchProxyModel
from pcap_report.gui.tabs.table_tab import copy_selection, make_table_view

# Wireshark-like background colours per protocol.
PROTOCOL_COLORS = {
    "HTTP": "#e4ffc7",
    "DNS": "#daeeff",
    "mDNS": "#daeeff",
    "TLS": "#e7e6ff",
    "TCP": "#e7e6ff",
    "UDP": "#daeeff",
    "ICMP": "#fce0ff",
    "ICMPv6": "#fce0ff",
    "ARP": "#faf0d7",
    "DHCP": "#fff3d6",
    "SMB": "#feffd0",
    "NetBIOS": "#feffd0",
}
TCP_RESET_COLOR = "#ffb3b3"
TCP_SYN_FIN_COLOR = "#d0d0d0"


def packet_color(rec):
    if rec.protocol == "TCP" and rec.tcp_flags:
        if "R" in rec.tcp_flags:
            return TCP_RESET_COLOR
        if "S" in rec.tcp_flags or "F" in rec.tcp_flags:
            return TCP_SYN_FIN_COLOR
    return PROTOCOL_COLORS.get(rec.app_protocol) or PROTOCOL_COLORS.get(rec.protocol)


PACKET_COLUMNS = [
    Column("no", lambda r: r.number, numeric=True),
    Column("time", lambda r: r.relative_time, fmt_seconds, numeric=True),
    Column("source", lambda r: r.src),
    Column("destination", lambda r: r.dst),
    Column("protocol", lambda r: r.display_protocol),
    Column("length", lambda r: r.length, numeric=True),
    Column("info", lambda r: r.info),
]


class PacketsTab(QWidget):
    filter_requested = pyqtSignal(str)

    def __init__(self, tr, parent=None):
        super().__init__(parent)
        self.tr = tr

        self.model = ObjectTableModel(PACKET_COLUMNS, tr, row_color=packet_color)
        self.proxy = SearchProxyModel()
        self.proxy.setSourceModel(self.model)
        self.view = make_table_view(self.proxy)
        self.view.setAlternatingRowColors(False)
        self.view.selectionModel().currentRowChanged.connect(self._show_details)
        self.view.customContextMenuRequested.connect(self._show_menu)

        self.tree = QTreeWidget()
        self.tree.setHeaderHidden(True)
        self.hex = QPlainTextEdit()
        self.hex.setReadOnly(True)
        self.hex.setFont(QFontDatabase.systemFont(QFontDatabase.FixedFont))
        self.hex.setLineWrapMode(QPlainTextEdit.NoWrap)

        details = QSplitter(Qt.Horizontal)
        details.addWidget(self.tree)
        details.addWidget(self.hex)
        details.setSizes([500, 500])

        splitter = QSplitter(Qt.Vertical)
        splitter.addWidget(self.view)
        splitter.addWidget(details)
        splitter.setSizes([450, 250])

        layout = QVBoxLayout(self)
        layout.addWidget(splitter)

    def update_stats(self, stats, records):
        self.model.set_items(records)
        self.tree.clear()
        self.hex.clear()
        if records:
            self.view.resizeColumnsToContents()

    def retranslate(self):
        self.model.retranslate()

    # -- details ------------------------------------------------------------ #

    def _record_at(self, proxy_index):
        return self.model.item(self.proxy.mapToSource(proxy_index).row())

    def _show_details(self, current, _previous=None):
        self.tree.clear()
        self.hex.clear()
        if not current.isValid():
            return
        rec = self._record_at(current)
        try:
            pkt = decode_record(rec)
        except Exception as exc:  # undecodable bytes: show the error instead
            QTreeWidgetItem(self.tree, [f"{self.tr('decode_error')}: {exc}"])
        else:
            self._fill_tree(rec, pkt)
        self.hex.setPlainText(hexdump(rec.raw, dump=True))

    def _fill_tree(self, rec, pkt):
        frame = QTreeWidgetItem(self.tree, [self.tr(
            "frame_summary", number=rec.number, length=rec.length)])
        QTreeWidgetItem(frame, [f"{self.tr('time')}: {rec.relative_time:.6f}"])
        layer = pkt
        while layer is not None and not isinstance(layer, NoPayload):
            item = QTreeWidgetItem(self.tree, [layer.name])
            for field in layer.fields_desc:
                try:
                    value = field.i2repr(layer, layer.getfieldval(field.name))
                except Exception:
                    value = repr(layer.getfieldval(field.name))
                QTreeWidgetItem(item, [f"{field.name}: {value}"])
            item.setExpanded(layer.payload is None or isinstance(layer.payload, NoPayload))
            layer = layer.payload

    # -- context menu ------------------------------------------------------- #

    def _show_menu(self, pos):
        index = self.view.indexAt(pos)
        menu = QMenu(self)
        if index.isValid():
            rec = self._record_at(index)
            for key, text in self._filters_for(rec):
                action = menu.addAction(f"{self.tr(key)}: {text}")
                action.triggered.connect(lambda _, t=text: self.filter_requested.emit(t))
            menu.addSeparator()
        menu.addAction(self.tr("copy_rows"), lambda: copy_selection(self.view))
        menu.exec_(self.view.viewport().mapToGlobal(pos))

    @staticmethod
    def _filters_for(rec):
        options = []
        if rec.src:
            options.append(("filter_source", f"ip.src == {rec.src}"))
        if rec.dst:
            options.append(("filter_destination", f"ip.dst == {rec.dst}"))
        if rec.src and rec.dst:
            options.append(("filter_between",
                            f"ip.addr == {rec.src} and ip.addr == {rec.dst}"))
        options.append(("filter_protocol", f"proto == {rec.display_protocol}"))
        if rec.sport is not None:
            options.append(("filter_port", f"port == {rec.sport}"))
        if rec.dport is not None:
            options.append(("filter_port", f"port == {rec.dport}"))
        return options
