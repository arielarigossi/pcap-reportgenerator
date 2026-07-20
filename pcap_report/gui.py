"""Main GUI window for the PCAP Analyzer application."""

import os
import shutil
import subprocess
import sys

from PyQt5.QtCore import QThread
from PyQt5.QtWidgets import (
    QApplication,
    QComboBox,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QProgressBar,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from pcap_report.analyzer import PCAPAnalyzer
from pcap_report.config import (
    REPORT_SUBFOLDER_PREFIX, SUPPORTED_EXTENSIONS, TIMESTAMP_FORMAT,
)
from pcap_report.i18n import TRANSLATIONS, get_translation


class PCAPAnalyzerGUI(QWidget):
    """Application main window."""

    def __init__(self):
        super().__init__()
        self.current_lang = "en"
        self.t = TRANSLATIONS[self.current_lang]
        self.worker = None
        self.thread = None
        self.report_folder = None
        self._init_ui()

    # -- helpers ------------------------------------------------------------ #

    def _tr(self, key):
        return get_translation(self.current_lang, key)

    def _append_log(self, message):
        self.log_field.append(message)

    def _set_buttons(self, *, start=False, pause=False, resume=False,
                     cancel=False, export=False, open_report=False,
                     browse=False, lang_combo=False):
        self.start_button.setEnabled(start)
        self.pause_button.setEnabled(pause)
        self.resume_button.setEnabled(resume)
        self.cancel_button.setEnabled(cancel)
        self.export_button.setEnabled(export)
        self.open_report_button.setEnabled(open_report)
        self.pcap_browse.setEnabled(browse)
        self.output_browse.setEnabled(browse)
        self.lang_combo.setEnabled(lang_combo)

    # -- UI construction ---------------------------------------------------- #

    def _init_ui(self):
        layout = QVBoxLayout()

        # Language
        lang_layout = QHBoxLayout()
        self.lang_label = QLabel(self._tr("language"))
        self.lang_combo = QComboBox()
        self.lang_combo.addItem("English", "en")
        self.lang_combo.addItem("Espa\u00f1ol", "es")
        self.lang_combo.currentIndexChanged.connect(self._change_language)
        lang_layout.addWidget(self.lang_label)
        lang_layout.addWidget(self.lang_combo)
        lang_layout.addStretch()
        layout.addLayout(lang_layout)

        # PCAP file
        pcap_layout = QHBoxLayout()
        self.pcap_label = QLabel(self._tr("pcap_file"))
        self.pcap_input = QLineEdit()
        self.pcap_browse = QPushButton(self._tr("browse"))
        self.pcap_browse.clicked.connect(self._browse_pcap)
        pcap_layout.addWidget(self.pcap_label)
        pcap_layout.addWidget(self.pcap_input)
        pcap_layout.addWidget(self.pcap_browse)
        layout.addLayout(pcap_layout)

        # Output directory
        output_layout = QHBoxLayout()
        self.output_label = QLabel(self._tr("output_dir"))
        self.output_input = QLineEdit()
        self.output_browse = QPushButton(self._tr("browse"))
        self.output_browse.clicked.connect(self._browse_output)
        output_layout.addWidget(self.output_label)
        output_layout.addWidget(self.output_input)
        output_layout.addWidget(self.output_browse)
        layout.addLayout(output_layout)

        # Control buttons
        control_layout = QHBoxLayout()
        self.start_button = QPushButton(self._tr("start_analysis"))
        self.start_button.clicked.connect(self._start_analysis)
        self.pause_button = QPushButton(self._tr("pause"))
        self.pause_button.setEnabled(False)
        self.pause_button.clicked.connect(self._pause_analysis)
        self.resume_button = QPushButton(self._tr("resume"))
        self.resume_button.setEnabled(False)
        self.resume_button.clicked.connect(self._resume_analysis)
        self.cancel_button = QPushButton(self._tr("cancel"))
        self.cancel_button.setEnabled(False)
        self.cancel_button.clicked.connect(self._cancel_analysis)
        self.export_button = QPushButton(self._tr("export_button"))
        self.export_button.setEnabled(False)
        self.export_button.clicked.connect(self._export_csv)
        self.open_report_button = QPushButton(self._tr("open_report_button"))
        self.open_report_button.setEnabled(False)
        self.open_report_button.clicked.connect(self._open_report)
        for btn in (self.start_button, self.pause_button, self.resume_button,
                    self.cancel_button, self.export_button, self.open_report_button):
            control_layout.addWidget(btn)
        layout.addLayout(control_layout)

        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)
        layout.addWidget(self.progress_bar)

        # Log
        self.log_field = QTextEdit()
        self.log_field.setReadOnly(True)
        layout.addWidget(QLabel(self._tr("log")))
        layout.addWidget(self.log_field)

        # Summary
        self.summary_label = QLabel(self._tr("summary"))
        self.summary_text = QTextEdit()
        self.summary_text.setReadOnly(True)
        layout.addWidget(self.summary_label)
        layout.addWidget(self.summary_text)

        self.setLayout(layout)
        self.setWindowTitle(self._tr("title"))
        self.setGeometry(100, 100, 900, 700)

    # -- language switching ------------------------------------------------- #

    def _change_language(self):
        self.current_lang = self.lang_combo.currentData()
        self.t = TRANSLATIONS[self.current_lang]
        self._update_ui_texts()

    def _update_ui_texts(self):
        self.setWindowTitle(self._tr("title"))
        self.lang_label.setText(self._tr("language"))
        self.pcap_label.setText(self._tr("pcap_file"))
        self.pcap_browse.setText(self._tr("browse"))
        self.output_label.setText(self._tr("output_dir"))
        self.output_browse.setText(self._tr("browse"))
        self.start_button.setText(self._tr("start_analysis"))
        self.pause_button.setText(self._tr("pause"))
        self.resume_button.setText(self._tr("resume"))
        self.cancel_button.setText(self._tr("cancel"))
        self.export_button.setText(self._tr("export_button"))
        self.open_report_button.setText(self._tr("open_report_button"))
        self.summary_label.setText(self._tr("summary"))
        self.log_field.clear()
        self.summary_text.clear()
        self._append_log(
            f"<span style='color:green;'>{self._tr('language_changed')}</span>"
        )

    # -- file browsing ------------------------------------------------------ #

    def _browse_pcap(self):
        exts = " ".join(f"*{e}" for e in SUPPORTED_EXTENSIONS)
        path, _ = QFileDialog.getOpenFileName(
            self, "Select PCAP File", "",
            f"PCAP Files ({exts});;All Files (*)",
            options=QFileDialog.ReadOnly,
        )
        if path:
            self.pcap_input.setText(path)

    def _browse_output(self):
        path = QFileDialog.getExistingDirectory(
            self, self._tr("output_dir"), os.getcwd()
        )
        if path:
            self.output_input.setText(path)

    # -- analysis lifecycle ------------------------------------------------- #

    def _start_analysis(self):
        pcap_file = self.pcap_input.text()
        output_dir = self.output_input.text()

        if not pcap_file or not os.path.isfile(pcap_file):
            self._append_log(
                f"<span style='color:red;'>{self._tr('invalid_pcap')}</span>"
            )
            return
        if not output_dir or not os.path.isdir(output_dir):
            self._append_log(
                f"<span style='color:red;'>{self._tr('invalid_output')}</span>"
            )
            return

        timestamp = __import__("datetime").datetime.now().strftime(TIMESTAMP_FORMAT)
        report_folder = os.path.join(
            output_dir, f"{REPORT_SUBFOLDER_PREFIX}_{timestamp}"
        )

        self._set_buttons(start=False, browse=False, lang_combo=False,
                          pause=True, cancel=True)

        self.log_field.clear()
        self.summary_text.clear()
        self.progress_bar.setValue(0)

        self.thread = QThread()
        self.worker = PCAPAnalyzer(
            pcap_file, output_folder=output_dir,
            report_folder=report_folder, lang=self.current_lang,
        )
        self.worker.moveToThread(self.thread)

        self.thread.started.connect(self.worker.run)
        self.worker.progress.connect(self.progress_bar.setValue)
        self.worker.log.connect(self._append_log)
        self.worker.finished.connect(self._on_finished)
        self.worker.error.connect(self._on_error)
        self.worker.finished.connect(self.thread.quit)
        self.worker.finished.connect(self.worker.deleteLater)
        self.thread.finished.connect(self.thread.deleteLater)
        self.worker.error.connect(self.thread.quit)
        self.worker.error.connect(self.worker.deleteLater)

        self.thread.start()

    def _pause_analysis(self):
        if self.worker:
            self.worker.pause()
            self._append_log(
                f"<span style='color:yellow;'>{self._tr('processing_paused')}</span>"
            )
            self.pause_button.setEnabled(False)
            self.resume_button.setEnabled(True)

    def _resume_analysis(self):
        if self.worker:
            self.worker.resume()
            self._append_log(
                f"<span style='color:yellow;'>{self._tr('processing_resumed')}</span>"
            )
            self.pause_button.setEnabled(True)
            self.resume_button.setEnabled(False)

    def _cancel_analysis(self):
        if self.worker:
            self.worker.cancel()
            self._append_log(
                f"<span style='color:red;'>{self._tr('processing_cancelled')}</span>"
            )
            self._reset_buttons()

    # -- callbacks ---------------------------------------------------------- #

    def _on_finished(self, elapsed_time):
        msg = self._tr("analysis_completed").format(time=elapsed_time)
        self.summary_text.append(
            f"<span style='color:green;'>{msg}</span>"
        )
        self._set_buttons(start=True, browse=True, lang_combo=True,
                          export=True, open_report=True)

    def _on_error(self, error_message):
        self._append_log(error_message)
        self.summary_text.append(
            f"<span style='color:red;'>{self._tr('error_occurred_summary')}</span>"
        )
        self._reset_buttons()

    def _reset_buttons(self):
        self._set_buttons(start=True, browse=True, lang_combo=True)

    # -- export / open ------------------------------------------------------ #

    def _export_csv(self):
        try:
            csv_path = os.path.join(
                self.worker.report_folder, "pcap_analysis_summary.csv"
            )
            if not os.path.exists(csv_path):
                QMessageBox.warning(
                    self, "Export CSV", self._tr("export_failure")
                )
                return
            dest, _ = QFileDialog.getSaveFileName(
                self, "Save CSV", os.path.expanduser("~"), "CSV Files (*.csv)"
            )
            if dest:
                shutil.copy(csv_path, dest)
                QMessageBox.information(
                    self, "Export CSV", self._tr("export_success")
                )
        except Exception as e:
            QMessageBox.warning(
                self, "Export CSV",
                f"{self._tr('export_failure')}\n{e}",
            )

    def _open_report(self):
        try:
            html_path = os.path.join(
                self.worker.report_folder, "pcap_analysis_report.html"
            )
            if not os.path.exists(html_path):
                self._append_log(
                    f"<span style='color:red;'>{self._tr('open_report_failure')}</span>"
                )
                return
            if sys.platform.startswith("darwin"):
                subprocess.call(["open", html_path])
            elif os.name == "nt":
                os.startfile(html_path)
            elif os.name == "posix":
                subprocess.call(["xdg-open", html_path])
            self._append_log(
                f"<span style='color:green;'>{self._tr('open_report_success')}</span>"
            )
        except Exception as e:
            self._append_log(
                f"<span style='color:red;'>{self._tr('open_report_failure')}</span>\n{e}"
            )
