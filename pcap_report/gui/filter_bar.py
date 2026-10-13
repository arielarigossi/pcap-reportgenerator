"""Display filter input shared by every tab."""

from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtWidgets import (
    QComboBox, QHBoxLayout, QLabel, QMessageBox, QPushButton, QWidget,
)

from pcap_report.config import FILTER_PRESETS
from pcap_report.core.filters import FilterSyntaxError, compile_filter

VALID_STYLE = "QLineEdit { background-color: #d9f7d9; color: #1a1a1a; }"
INVALID_STYLE = "QLineEdit { background-color: #fbd5d5; color: #1a1a1a; }"
MAX_HISTORY = 20


class FilterBar(QWidget):
    """Editable combo box with validation, presets and history.

    Emits :attr:`filter_applied` with the (validated) filter text.
    """

    filter_applied = pyqtSignal(str)

    def __init__(self, tr, parent=None):
        super().__init__(parent)
        self.tr = tr

        self.label = QLabel()
        self.combo = QComboBox()
        self.combo.setEditable(True)
        self.combo.setInsertPolicy(QComboBox.NoInsert)
        self.combo.addItems(FILTER_PRESETS)
        self.combo.setCurrentIndex(-1)
        self.combo.lineEdit().textChanged.connect(self._validate)
        self.combo.lineEdit().returnPressed.connect(self.apply)
        self.combo.activated.connect(lambda _: self.apply())

        self.apply_button = QPushButton()
        self.apply_button.clicked.connect(self.apply)
        self.clear_button = QPushButton()
        self.clear_button.clicked.connect(self.clear)
        self.help_button = QPushButton("?")
        self.help_button.setFixedWidth(30)
        self.help_button.clicked.connect(self.show_help)
        self.status = QLabel()

        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self.label)
        layout.addWidget(self.combo, 1)
        layout.addWidget(self.apply_button)
        layout.addWidget(self.clear_button)
        layout.addWidget(self.help_button)
        layout.addWidget(self.status)
        self.retranslate()

    # -- public API --------------------------------------------------------- #

    def text(self):
        return self.combo.currentText().strip()

    def set_text(self, text, apply=True):
        self.combo.setEditText(text)
        if apply:
            self.apply()

    def set_counts(self, shown, total):
        self.status.setText(self.tr("displayed_count", shown=f"{shown:,}", total=f"{total:,}"))

    def retranslate(self):
        self.label.setText(self.tr("display_filter") + ":")
        self.combo.lineEdit().setPlaceholderText(self.tr("filter_placeholder"))
        self.apply_button.setText(self.tr("apply_filter"))
        self.clear_button.setText(self.tr("clear_filter"))
        self.help_button.setToolTip(self.tr("filter_help_title"))

    # -- slots -------------------------------------------------------------- #

    def apply(self):
        text = self.text()
        try:
            compile_filter(text)
        except FilterSyntaxError as exc:
            QMessageBox.warning(self, self.tr("invalid_filter"), str(exc))
            return
        if text:
            self._remember(text)
        self.filter_applied.emit(text)

    def clear(self):
        self.combo.setEditText("")
        self.filter_applied.emit("")

    def show_help(self):
        QMessageBox.information(self, self.tr("filter_help_title"), self.tr("filter_help"))

    def _validate(self, text):
        edit = self.combo.lineEdit()
        if not text.strip():
            edit.setStyleSheet("")
            edit.setToolTip("")
            return
        try:
            compile_filter(text)
        except FilterSyntaxError as exc:
            edit.setStyleSheet(INVALID_STYLE)
            edit.setToolTip(str(exc))
        else:
            edit.setStyleSheet(VALID_STYLE)
            edit.setToolTip("")

    def _remember(self, text):
        index = self.combo.findText(text, Qt.MatchExactly)
        if index >= 0:
            self.combo.removeItem(index)
        self.combo.insertItem(0, text)
        while self.combo.count() > MAX_HISTORY + len(FILTER_PRESETS):
            self.combo.removeItem(self.combo.count() - 1)
        self.combo.setCurrentIndex(0)
