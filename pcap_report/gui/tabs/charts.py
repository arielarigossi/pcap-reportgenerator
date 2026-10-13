"""Interactive charts embedded with matplotlib's Qt backend."""

from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg, NavigationToolbar2QT
from PyQt5.QtWidgets import QComboBox, QHBoxLayout, QLabel, QVBoxLayout, QWidget

from pcap_report.reporting.charts import CHARTS, build_chart, packet_size_histogram

PACKET_SIZES = "packet_sizes"


class ChartsTab(QWidget):
    def __init__(self, tr, parent=None):
        super().__init__(parent)
        self.tr = tr
        self.stats = None
        self.records = []

        self.label = QLabel()
        self.selector = QComboBox()
        self._fill_selector()
        self.selector.currentIndexChanged.connect(self._redraw)

        self.canvas = FigureCanvasQTAgg()
        self.toolbar = NavigationToolbar2QT(self.canvas, self)

        top = QHBoxLayout()
        top.addWidget(self.label)
        top.addWidget(self.selector)
        top.addStretch()
        layout = QVBoxLayout(self)
        layout.addLayout(top)
        layout.addWidget(self.toolbar)
        layout.addWidget(self.canvas, 1)
        self.retranslate()

    def _chart_keys(self):
        return list(CHARTS) + [PACKET_SIZES]

    def _fill_selector(self):
        current = self.selector.currentData()
        self.selector.blockSignals(True)
        self.selector.clear()
        for key in self._chart_keys():
            title_key = CHARTS[key][0] if key in CHARTS else PACKET_SIZES
            self.selector.addItem(self.tr(title_key), key)
        index = self.selector.findData(current)
        self.selector.setCurrentIndex(max(0, index))
        self.selector.blockSignals(False)

    def update_stats(self, stats, records):
        self.stats = stats
        self.records = records
        self._redraw()

    def retranslate(self):
        self.label.setText(self.tr("chart") + ":")
        self._fill_selector()
        self._redraw()

    def _redraw(self):
        if self.stats is None:
            return
        key = self.selector.currentData()
        figure = self.canvas.figure
        if key == PACKET_SIZES:
            packet_size_histogram(self.stats, self.tr, [r.length for r in self.records],
                                  fig=figure)
        else:
            build_chart(key, self.stats, self.tr, fig=figure)
        self.toolbar.update()  # reset zoom / pan history
        self.canvas.draw_idle()
