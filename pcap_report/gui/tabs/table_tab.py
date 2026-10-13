"""Reusable tab: searchable, sortable table with "apply as filter" actions."""

from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtWidgets import (
    QAbstractItemView, QApplication, QHBoxLayout, QHeaderView, QLabel, QLineEdit,
    QMenu, QTableView, QVBoxLayout, QWidget,
)

from pcap_report.gui.table_model import ObjectTableModel, SearchProxyModel


def make_table_view(proxy):
    view = QTableView()
    view.setModel(proxy)
    view.setSortingEnabled(True)
    # Keep the model's own order until the user clicks a header.
    view.horizontalHeader().setSortIndicator(-1, Qt.AscendingOrder)
    view.setSelectionBehavior(QAbstractItemView.SelectRows)
    view.setSelectionMode(QAbstractItemView.ExtendedSelection)
    view.setAlternatingRowColors(True)
    view.verticalHeader().setVisible(False)
    view.verticalHeader().setDefaultSectionSize(22)
    view.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
    view.horizontalHeader().setStretchLastSection(True)
    view.setContextMenuPolicy(Qt.CustomContextMenu)
    return view


def copy_selection(view):
    """Copy the selected rows to the clipboard as tab-separated text."""
    rows = sorted({index.row() for index in view.selectionModel().selectedIndexes()})
    model = view.model()
    lines = [
        "\t".join(str(model.index(row, col).data() or "") for col in range(model.columnCount()))
        for row in rows
    ]
    QApplication.clipboard().setText("\n".join(lines))


class TableTab(QWidget):
    """A table of objects with a quick-search box.

    ``filters`` is a list of ``(translation_key, item -> filter_text)``
    pairs offered in the context menu; the first one is also used on
    double-click. Selecting one emits :attr:`filter_requested`.
    """

    filter_requested = pyqtSignal(str)

    def __init__(self, tr, columns, filters=(), title_key=None, parent=None):
        super().__init__(parent)
        self.tr = tr
        self.filters = list(filters)
        self.title_key = title_key

        self.model = ObjectTableModel(columns, tr)
        self.proxy = SearchProxyModel()
        self.proxy.setSourceModel(self.model)
        self.view = make_table_view(self.proxy)
        self.view.doubleClicked.connect(self._on_double_click)
        self.view.customContextMenuRequested.connect(self._show_menu)

        self.title = QLabel()
        self.title.setStyleSheet("font-weight: bold;")
        self.search = QLineEdit()
        self.search.setClearButtonEnabled(True)
        self.search.textChanged.connect(self.proxy.setFilterFixedString)
        self.count = QLabel()

        top = QHBoxLayout()
        top.addWidget(self.title)
        top.addStretch()
        top.addWidget(self.search)
        top.addWidget(self.count)
        layout = QVBoxLayout(self)
        layout.addLayout(top)
        layout.addWidget(self.view)
        self.title.setVisible(title_key is not None)
        self.retranslate()

    def set_items(self, items):
        self.model.set_items(items)
        self.view.resizeColumnsToContents()
        self.count.setText(self.tr("rows_count", count=f"{len(self.model.items):,}"))

    def retranslate(self):
        if self.title_key:
            self.title.setText(self.tr(self.title_key))
        self.search.setPlaceholderText(self.tr("quick_search"))
        self.count.setText(self.tr("rows_count", count=f"{len(self.model.items):,}"))
        self.model.retranslate()

    def _item_at(self, proxy_index):
        return self.model.item(self.proxy.mapToSource(proxy_index).row())

    def _on_double_click(self, index):
        if self.filters and index.isValid():
            self.filter_requested.emit(self.filters[0][1](self._item_at(index)))

    def _show_menu(self, pos):
        index = self.view.indexAt(pos)
        menu = QMenu(self)
        if index.isValid():
            item = self._item_at(index)
            for key, make_filter in self.filters:
                text = make_filter(item)
                action = menu.addAction(f"{self.tr(key)}: {text}")
                action.triggered.connect(lambda _, t=text: self.filter_requested.emit(t))
            if self.filters:
                menu.addSeparator()
        menu.addAction(self.tr("copy_rows"), lambda: copy_selection(self.view))
        menu.exec_(self.view.viewport().mapToGlobal(pos))
