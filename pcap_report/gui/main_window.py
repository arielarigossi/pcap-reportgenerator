"""Main application window."""

import os

from PyQt5.QtCore import QSettings, Qt, QUrl
from PyQt5.QtGui import QDesktopServices, QKeySequence
from PyQt5.QtWidgets import (
    QAction, QActionGroup, QApplication, QFileDialog, QLabel, QMainWindow,
    QMessageBox, QProgressBar, QStyle, QTabWidget, QVBoxLayout, QWidget,
)

from pcap_report import __version__
from pcap_report.config import DEFAULT_LANGUAGE, SUPPORTED_EXTENSIONS
from pcap_report.core.filters import FilterSyntaxError, apply_filter
from pcap_report.core.parser import read_packets, write_records
from pcap_report.core.statistics import compute_statistics
from pcap_report.gui.filter_bar import FilterBar
from pcap_report.gui.tabs import (
    ChartsTab, ConversationsTab, EndpointsTab, LogTab, OverviewTab, PacketsTab,
    PortsTab, ProtocolsTab,
)
from pcap_report.gui.workers import create_worker
from pcap_report.i18n import LANGUAGES, Translator
from pcap_report.reporting.csv_export import write_conversations_csv, write_packets_csv
from pcap_report.reporting.pipeline import generate_report

SETTINGS_ORG = "pcap-reportgenerator"
SETTINGS_APP = "PCAP Analyzer"


class MainWindow(QMainWindow):
    def __init__(self, settings=None):
        super().__init__()
        self.settings = settings or QSettings(SETTINGS_ORG, SETTINGS_APP)
        self.tr_ = Translator(self.settings.value("language", DEFAULT_LANGUAGE))

        self.source_file = None
        self.all_records = []
        self.records = []
        self.stats = None
        self.current_filter = ""
        self.last_report = None
        self.worker = None

        self._build_tabs()
        self._build_actions()
        self._build_menus()
        self._build_toolbar()
        self._build_status_bar()

        central = QWidget()
        layout = QVBoxLayout(central)
        self.filter_bar = FilterBar(self.tr_)
        self.filter_bar.filter_applied.connect(self.apply_display_filter)
        layout.addWidget(self.filter_bar)
        layout.addWidget(self.tabs)
        self.setCentralWidget(central)

        self.setAcceptDrops(True)
        self.resize(1200, 800)
        self.retranslate()
        self._update_actions()

    # ------------------------------------------------------------------ #
    #  Construction
    # ------------------------------------------------------------------ #

    def _build_tabs(self):
        tr = self.tr_
        self.overview_tab = OverviewTab(tr)
        self.packets_tab = PacketsTab(tr)
        self.conversations_tab = ConversationsTab(tr)
        self.endpoints_tab = EndpointsTab(tr)
        self.ports_tab = PortsTab(tr)
        self.protocols_tab = ProtocolsTab(tr)
        self.charts_tab = ChartsTab(tr)
        self.log_tab = LogTab(tr)

        # (translation key, widget) in display order
        self.tab_entries = [
            ("tab_overview", self.overview_tab),
            ("tab_packets", self.packets_tab),
            ("tab_conversations", self.conversations_tab),
            ("tab_endpoints", self.endpoints_tab),
            ("tab_ports", self.ports_tab),
            ("tab_protocols", self.protocols_tab),
            ("tab_charts", self.charts_tab),
            ("tab_log", self.log_tab),
        ]
        self.data_tabs = [w for _, w in self.tab_entries if hasattr(w, "update_stats")]

        self.tabs = QTabWidget()
        for _, widget in self.tab_entries:
            self.tabs.addTab(widget, "")
            if hasattr(widget, "filter_requested"):
                widget.filter_requested.connect(self._on_filter_requested)

    def _action(self, icon=None, slot=None, shortcut=None, checkable=False):
        action = QAction(self)
        if icon is not None:
            action.setIcon(self.style().standardIcon(icon))
        if slot is not None:
            action.triggered.connect(slot)
        if shortcut is not None:
            action.setShortcut(QKeySequence(shortcut))
        action.setCheckable(checkable)
        return action

    def _build_actions(self):
        self.open_action = self._action(QStyle.SP_DialogOpenButton, self.open_file_dialog,
                                        QKeySequence.Open)
        self.save_pcap_action = self._action(QStyle.SP_DialogSaveButton, self.save_filtered_pcap,
                                             QKeySequence.Save)
        self.export_packets_action = self._action(None, self.export_packets_csv)
        self.export_conversations_action = self._action(None, self.export_conversations_csv)
        self.quit_action = self._action(None, self.close, QKeySequence.Quit)

        self.pause_action = self._action(QStyle.SP_MediaPause, self.pause_task)
        self.resume_action = self._action(QStyle.SP_MediaPlay, self.resume_task)
        self.cancel_action = self._action(QStyle.SP_BrowserStop, self.cancel_task)

        self.report_action = self._action(QStyle.SP_FileDialogDetailedView,
                                          self.generate_report_dialog, "Ctrl+R")
        self.open_report_action = self._action(QStyle.SP_DirOpenIcon, self.open_last_report)

        self.filter_help_action = self._action(None, self.filter_bar_help)
        self.about_action = self._action(None, self.show_about)

        self.language_group = QActionGroup(self)
        self.language_actions = {}
        for code, name in LANGUAGES.items():
            action = self._action(checkable=True)
            action.setText(name)
            action.setChecked(code == self.tr_.lang)
            action.triggered.connect(lambda _, c=code: self.set_language(c))
            self.language_group.addAction(action)
            self.language_actions[code] = action

    def _build_menus(self):
        bar = self.menuBar()
        self.file_menu = bar.addMenu("")
        for action in (self.open_action, self.save_pcap_action, self.export_packets_action,
                       self.export_conversations_action):
            self.file_menu.addAction(action)
        self.file_menu.addSeparator()
        self.file_menu.addAction(self.quit_action)

        self.capture_menu = bar.addMenu("")
        for action in (self.pause_action, self.resume_action, self.cancel_action):
            self.capture_menu.addAction(action)

        self.report_menu = bar.addMenu("")
        self.report_menu.addAction(self.report_action)
        self.report_menu.addAction(self.open_report_action)

        self.language_menu = bar.addMenu("")
        for action in self.language_actions.values():
            self.language_menu.addAction(action)

        self.help_menu = bar.addMenu("")
        self.help_menu.addAction(self.filter_help_action)
        self.help_menu.addAction(self.about_action)

    def _build_toolbar(self):
        self.toolbar = self.addToolBar("main")
        self.toolbar.setMovable(False)
        self.toolbar.setToolButtonStyle(Qt.ToolButtonTextBesideIcon)
        for action in (self.open_action, self.save_pcap_action, None, self.pause_action,
                       self.resume_action, self.cancel_action, None, self.report_action,
                       self.open_report_action):
            if action is None:
                self.toolbar.addSeparator()
            else:
                self.toolbar.addAction(action)

    def _build_status_bar(self):
        self.status_label = QLabel()
        self.progress = QProgressBar()
        self.progress.setMaximumWidth(250)
        self.progress.setVisible(False)
        self.statusBar().addWidget(self.status_label, 1)
        self.statusBar().addPermanentWidget(self.progress)

    # ------------------------------------------------------------------ #
    #  Translation
    # ------------------------------------------------------------------ #

    def set_language(self, lang):
        self.tr_.set_language(lang)
        self.settings.setValue("language", lang)
        self.retranslate()
        self.log(self.tr_("language_changed"), "success")

    def retranslate(self):
        tr = self.tr_
        self.setWindowTitle(self._window_title())
        for key, widget in self.tab_entries:
            self.tabs.setTabText(self.tabs.indexOf(widget), tr(key))
            widget.retranslate()
        self.filter_bar.retranslate()

        texts = {
            self.open_action: "open_capture", self.save_pcap_action: "save_filtered_pcap",
            self.export_packets_action: "export_packets_csv",
            self.export_conversations_action: "export_conversations_csv",
            self.quit_action: "quit", self.pause_action: "pause",
            self.resume_action: "resume", self.cancel_action: "cancel",
            self.report_action: "generate_report", self.open_report_action: "open_report",
            self.filter_help_action: "filter_help_title", self.about_action: "about",
        }
        for action, key in texts.items():
            action.setText(tr(key))
        for menu, key in ((self.file_menu, "menu_file"), (self.capture_menu, "menu_capture"),
                          (self.report_menu, "menu_report"),
                          (self.language_menu, "language"), (self.help_menu, "menu_help")):
            menu.setTitle(tr(key))
        if self.worker is None:
            self.status_label.setText(tr("ready") if not self.source_file else "")
        self._update_filter_counts()

    def _window_title(self):
        title = self.tr_("title")
        if self.source_file:
            title = f"{os.path.basename(self.source_file)} - {title}"
        return title

    # ------------------------------------------------------------------ #
    #  Helpers
    # ------------------------------------------------------------------ #

    def log(self, message, level="info"):
        self.log_tab.log(message, level)
        if level != "error":
            self.status_label.setText(message)

    def _busy(self):
        return self.worker is not None

    def _update_actions(self):
        busy = self._busy()
        has_data = bool(self.all_records)
        self.open_action.setEnabled(not busy)
        for action in (self.save_pcap_action, self.export_packets_action,
                       self.export_conversations_action, self.report_action):
            action.setEnabled(has_data and not busy)
        self.open_report_action.setEnabled(self.last_report is not None)
        paused = busy and self.worker.control.is_paused
        self.pause_action.setEnabled(busy and not paused)
        self.resume_action.setEnabled(busy and paused)
        self.cancel_action.setEnabled(busy)
        for action in self.language_actions.values():
            action.setEnabled(not busy)
        self.filter_bar.setEnabled(has_data and not busy)

    def _update_filter_counts(self):
        self.filter_bar.set_counts(len(self.records), len(self.all_records))

    def _ask_save_path(self, title_key, default_name, file_filter):
        start_dir = self.settings.value("last_dir", os.path.expanduser("~"))
        path, _ = QFileDialog.getSaveFileName(
            self, self.tr_(title_key), os.path.join(start_dir, default_name), file_filter)
        if path:
            self.settings.setValue("last_dir", os.path.dirname(path))
        return path

    def _start_task(self, func, on_success, busy_message):
        self.worker = create_worker(func, self)
        self.worker.progress.connect(self.progress.setValue)
        self.worker.message.connect(lambda m: self.log(m))
        self.worker.succeeded.connect(on_success)
        self.worker.failed.connect(self._on_task_failed)
        self.worker.cancelled.connect(lambda: self.log(self.tr_("processing_cancelled"), "warning"))
        self.worker.done.connect(self._on_task_done)
        self.worker.start()
        self.progress.setValue(0)
        self.progress.setVisible(True)
        self.log(busy_message)
        self._update_actions()

    def _on_task_failed(self, message):
        self.log(self.tr_("error_occurred", error=message), "error")
        self.status_label.setText(self.tr_("error_occurred_summary"))
        QMessageBox.critical(self, self.tr_("error"), message.split("\n", 1)[0])

    def _on_task_done(self):
        self.worker = None
        self.progress.setVisible(False)
        self._update_actions()

    # ------------------------------------------------------------------ #
    #  Loading captures
    # ------------------------------------------------------------------ #

    def open_file_dialog(self):
        exts = " ".join(f"*{e}" for e in SUPPORTED_EXTENSIONS)
        start_dir = self.settings.value("last_dir", os.path.expanduser("~"))
        path, _ = QFileDialog.getOpenFileName(
            self, self.tr_("open_capture"), start_dir,
            f"{self.tr_('capture_files')} ({exts});;{self.tr_('all_files')} (*)")
        if path:
            self.settings.setValue("last_dir", os.path.dirname(path))
            self.load_file(path)

    def load_file(self, path):
        if self._busy():
            return
        if not os.path.isfile(path):
            self.log(self.tr_("invalid_pcap"), "error")
            return
        self._pending_source = path

        def task(progress, control, log):
            return read_packets(path, progress=progress, control=control)

        self._start_task(task, self._on_loaded,
                         self.tr_("processing", file=os.path.basename(path)))

    def _on_loaded(self, records):
        self.source_file = self._pending_source
        self.all_records = records
        self.last_report = None
        self.setWindowTitle(self._window_title())
        self.log(self.tr_("loaded_packets", count=f"{len(records):,}"), "success")
        self.overview_tab.set_source(self.source_file, len(records))
        self.apply_display_filter(self.filter_bar.text(), quiet=True)

    # ------------------------------------------------------------------ #
    #  Filtering
    # ------------------------------------------------------------------ #

    def _on_filter_requested(self, text):
        self.filter_bar.set_text(text)
        self.tabs.setCurrentWidget(self.packets_tab)

    def apply_display_filter(self, text, quiet=False):
        try:
            records = apply_filter(self.all_records, text)
        except FilterSyntaxError as exc:
            if not quiet:
                QMessageBox.warning(self, self.tr_("invalid_filter"), str(exc))
            records = self.all_records
            text = ""
        QApplication.setOverrideCursor(Qt.WaitCursor)
        try:
            self.current_filter = text
            self.records = records
            self.stats = compute_statistics(records)
            for tab in self.data_tabs:
                tab.update_stats(self.stats, records)
        finally:
            QApplication.restoreOverrideCursor()
        self._update_filter_counts()
        self._update_actions()
        if text and not quiet:
            self.log(self.tr_("filter_applied", filter=text,
                              shown=f"{len(records):,}", total=f"{len(self.all_records):,}"))

    def filter_bar_help(self):
        self.filter_bar.show_help()

    # ------------------------------------------------------------------ #
    #  Pause / resume / cancel
    # ------------------------------------------------------------------ #

    def pause_task(self):
        if self.worker:
            self.worker.control.pause()
            self.log(self.tr_("processing_paused"), "warning")
            self._update_actions()

    def resume_task(self):
        if self.worker:
            self.worker.control.resume()
            self.log(self.tr_("processing_resumed"))
            self._update_actions()

    def cancel_task(self):
        if self.worker:
            self.worker.control.cancel()

    # ------------------------------------------------------------------ #
    #  Exports and reports
    # ------------------------------------------------------------------ #

    def _export(self, writer, items, title_key, default_name, file_filter):
        path = self._ask_save_path(title_key, default_name, file_filter)
        if not path:
            return
        try:
            writer(items, path)
        except Exception as exc:
            self.log(self.tr_("export_failure") + f" {exc}", "error")
            QMessageBox.warning(self, self.tr_(title_key), f"{self.tr_('export_failure')}\n{exc}")
        else:
            self.log(self.tr_("export_success_path", path=path), "success")

    def save_filtered_pcap(self):
        self._export(write_records, self.records, "save_filtered_pcap", "filtered.pcap",
                     f"{self.tr_('capture_files')} (*.pcap)")

    def export_packets_csv(self):
        self._export(write_packets_csv, self.records, "export_packets_csv", "packets.csv",
                     "CSV (*.csv)")

    def export_conversations_csv(self):
        self._export(write_conversations_csv, self.stats.conversations,
                     "export_conversations_csv", "conversations.csv", "CSV (*.csv)")

    def generate_report_dialog(self):
        start_dir = self.settings.value("report_dir", self.settings.value(
            "last_dir", os.path.expanduser("~")))
        output_dir = QFileDialog.getExistingDirectory(self, self.tr_("output_dir"), start_dir)
        if output_dir:
            self.settings.setValue("report_dir", output_dir)
            self.generate_report(output_dir)

    def generate_report(self, output_dir):
        if self._busy() or not self.all_records:
            return
        records, stats, lang = self.records, self.stats, self.tr_.lang
        source, display_filter = self.source_file, self.current_filter
        step_keys = {"charts": "generating_charts", "csv": "generating_summary",
                     "html": "generating_html_report"}
        tr = Translator(lang)  # private copy: the worker must not see language switches

        def task(progress, control, log):
            return generate_report(records, output_dir, lang=lang, source_file=source,
                                   display_filter=display_filter, stats=stats,
                                   log=lambda step: log(tr(step_keys[step])))

        self._start_task(task, self._on_report_ready, self.tr_("generating_report"))

    def _on_report_ready(self, result):
        self.last_report = result
        self.log(self.tr_("complete_report", path=result.html_path), "success")
        self._update_actions()
        answer = QMessageBox.question(self, self.tr_("generate_report"),
                                      self.tr_("report_ready_open"))
        if answer == QMessageBox.Yes:
            self.open_last_report()

    def open_last_report(self):
        if self.last_report and os.path.exists(self.last_report.html_path):
            QDesktopServices.openUrl(QUrl.fromLocalFile(self.last_report.html_path))
            self.log(self.tr_("open_report_success"), "success")
        else:
            self.log(self.tr_("open_report_failure"), "error")

    def show_about(self):
        QMessageBox.about(self, self.tr_("about"), self.tr_("about_text", version=__version__))

    # ------------------------------------------------------------------ #
    #  Qt events
    # ------------------------------------------------------------------ #

    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls() and not self._busy():
            event.acceptProposedAction()

    def dropEvent(self, event):
        urls = [u for u in event.mimeData().urls() if u.isLocalFile()]
        if urls:
            self.load_file(urls[0].toLocalFile())

    def closeEvent(self, event):
        if self.worker is not None:
            self.worker.control.cancel()
            thread = getattr(self.worker, "thread_ref", None)
            if thread is not None:
                thread.quit()
                thread.wait(3000)
        super().closeEvent(event)
