"""Capture overview: key figures at a glance."""

import os

from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QFrame, QGridLayout, QLabel, QVBoxLayout, QWidget

from pcap_report.formatting import (
    fmt_bytes, fmt_count, fmt_duration, fmt_rate_bits, fmt_timestamp,
)

CARD_STYLE = """
QFrame#card { border: 1px solid palette(mid); border-radius: 8px; }
QLabel#value { font-size: 20px; font-weight: 600; }
QLabel#caption { color: palette(dark); }
"""

# (translation key, function(stats, records, total_records, source_file) -> text)
METRICS = [
    ("capture_file", lambda s, r, t, f: os.path.basename(f) if f else "-"),
    ("displayed_packets", lambda s, r, t, f: f"{fmt_count(len(r))} / {fmt_count(t)}"),
    ("total_bytes", lambda s, r, t, f: fmt_bytes(s.total_bytes)),
    ("duration", lambda s, r, t, f: fmt_duration(s.duration)),
    ("avg_packet_size", lambda s, r, t, f: f"{s.average_packet_size:.1f} B"),
    ("packets_per_second", lambda s, r, t, f: f"{s.packets_per_second:.1f}"),
    ("throughput", lambda s, r, t, f: fmt_rate_bits(s.bits_per_second)),
    ("unique_src_ips", lambda s, r, t, f: fmt_count(s.unique_src_ips)),
    ("unique_dst_ips", lambda s, r, t, f: fmt_count(s.unique_dst_ips)),
    ("conversations", lambda s, r, t, f: fmt_count(len(s.conversations))),
    ("first_packet", lambda s, r, t, f: fmt_timestamp(s.first_timestamp)),
    ("last_packet", lambda s, r, t, f: fmt_timestamp(s.last_timestamp)),
]
COLUMNS = 3


class _Card(QFrame):
    def __init__(self):
        super().__init__()
        self.setObjectName("card")
        self.value = QLabel("-")
        self.value.setObjectName("value")
        self.value.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.caption = QLabel()
        self.caption.setObjectName("caption")
        layout = QVBoxLayout(self)
        layout.addWidget(self.value)
        layout.addWidget(self.caption)


class OverviewTab(QWidget):
    def __init__(self, tr, parent=None):
        super().__init__(parent)
        self.tr = tr
        self.source_file = None
        self.total_records = 0
        self.setStyleSheet(CARD_STYLE)

        self.hint = QLabel()
        self.hint.setWordWrap(True)
        self.hint.setAlignment(Qt.AlignCenter)
        self.cards = {}
        grid = QGridLayout()
        for i, (key, _) in enumerate(METRICS):
            card = _Card()
            self.cards[key] = card
            grid.addWidget(card, i // COLUMNS, i % COLUMNS)

        layout = QVBoxLayout(self)
        layout.addWidget(self.hint)
        layout.addLayout(grid)
        layout.addStretch()
        self.retranslate()

    def set_source(self, path, total_records):
        self.source_file = path
        self.total_records = total_records

    def update_stats(self, stats, records):
        self.hint.setVisible(False)
        for key, compute in METRICS:
            self.cards[key].value.setText(
                compute(stats, records, self.total_records, self.source_file))

    def retranslate(self):
        self.hint.setText(self.tr("overview_hint"))
        for key, card in self.cards.items():
            card.caption.setText(self.tr(key))
