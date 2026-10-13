"""Activity log tab."""

from datetime import datetime
from html import escape

from PyQt5.QtWidgets import QHBoxLayout, QPushButton, QTextEdit, QVBoxLayout, QWidget

LEVEL_COLORS = {"info": "#2a78d6", "success": "#1a8f4a", "warning": "#b8860b", "error": "#c62828"}


class LogTab(QWidget):
    def __init__(self, tr, parent=None):
        super().__init__(parent)
        self.tr = tr
        self.text = QTextEdit()
        self.text.setReadOnly(True)
        self.clear_button = QPushButton()
        self.clear_button.clicked.connect(self.text.clear)

        buttons = QHBoxLayout()
        buttons.addStretch()
        buttons.addWidget(self.clear_button)
        layout = QVBoxLayout(self)
        layout.addWidget(self.text)
        layout.addLayout(buttons)
        self.retranslate()

    def log(self, message, level="info"):
        color = LEVEL_COLORS.get(level, LEVEL_COLORS["info"])
        stamp = datetime.now().strftime("%H:%M:%S")
        body = escape(message).replace("\n", "<br>")
        self.text.append(f"<span style='color:gray'>[{stamp}]</span> "
                         f"<span style='color:{color}'>{body}</span>")

    def retranslate(self):
        self.clear_button.setText(self.tr("clear_log"))
