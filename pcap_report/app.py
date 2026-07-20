"""Application entry point."""

import sys

from PyQt5.QtWidgets import QApplication

from pcap_report.gui import PCAPAnalyzerGUI


def main():
    app = QApplication(sys.argv)
    gui = PCAPAnalyzerGUI()
    gui.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
