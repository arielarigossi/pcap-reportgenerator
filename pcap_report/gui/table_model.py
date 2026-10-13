"""Generic, column-driven Qt table model over a list of Python objects."""

from dataclasses import dataclass
from typing import Callable, Optional

from PyQt5.QtCore import QAbstractTableModel, QModelIndex, QSortFilterProxyModel, Qt
from PyQt5.QtGui import QColor

SORT_ROLE = Qt.UserRole + 1
ITEM_ROLE = Qt.UserRole + 2


@dataclass
class Column:
    """Describes one table column.

    ``value`` extracts the raw (sortable) value from a row object;
    ``fmt`` optionally turns it into display text.
    """

    title_key: str
    value: Callable
    fmt: Optional[Callable] = None
    numeric: bool = False

    def display(self, item):
        value = self.value(item)
        if value is None:
            return ""
        return self.fmt(value) if self.fmt else str(value)


class ObjectTableModel(QAbstractTableModel):
    def __init__(self, columns, tr, row_color=None, parent=None):
        super().__init__(parent)
        self.columns = columns
        self.tr = tr
        self.row_color = row_color
        self.items = []

    def set_items(self, items):
        self.beginResetModel()
        self.items = list(items)
        self.endResetModel()

    def retranslate(self):
        self.headerDataChanged.emit(Qt.Horizontal, 0, len(self.columns) - 1)

    def item(self, row):
        return self.items[row]

    # -- Qt API ------------------------------------------------------------- #

    def rowCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(self.items)

    def columnCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(self.columns)

    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid():
            return None
        item = self.items[index.row()]
        column = self.columns[index.column()]
        if role == Qt.DisplayRole:
            return column.display(item)
        if role == SORT_ROLE:
            value = column.value(item)
            if value is None:
                return -1 if column.numeric else ""
            return value
        if role == ITEM_ROLE:
            return item
        if role == Qt.TextAlignmentRole and column.numeric:
            return int(Qt.AlignRight | Qt.AlignVCenter)
        if role == Qt.BackgroundRole and self.row_color is not None:
            color = self.row_color(item)
            return QColor(color) if color else None
        if role == Qt.ForegroundRole and self.row_color is not None:
            return QColor("#1a1a1a") if self.row_color(item) else None
        return None

    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if role == Qt.DisplayRole and orientation == Qt.Horizontal:
            return self.tr(self.columns[section].title_key)
        return None


class SearchProxyModel(QSortFilterProxyModel):
    """Sorts by raw values and filters rows by a case-insensitive substring."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setSortRole(SORT_ROLE)
        self.setFilterCaseSensitivity(Qt.CaseInsensitive)
        self.setFilterKeyColumn(-1)  # search every column

    def lessThan(self, left, right):
        a = left.data(SORT_ROLE)
        b = right.data(SORT_ROLE)
        try:
            return a < b
        except TypeError:
            return str(a) < str(b)
