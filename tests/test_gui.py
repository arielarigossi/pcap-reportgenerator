"""Offscreen smoke tests for the PyQt5 GUI."""

import os
import time

import pytest

pytest.importorskip("PyQt5")

from PyQt5.QtCore import QEventLoop, QSettings, Qt  # noqa: E402
from PyQt5.QtWidgets import QApplication, QMessageBox  # noqa: E402


@pytest.fixture(scope="module")
def qapp():
    return QApplication.instance() or QApplication([])


@pytest.fixture
def window(qapp, tmp_path, monkeypatch):
    from pcap_report.gui.main_window import MainWindow

    # Never block on modal dialogs during tests.
    monkeypatch.setattr(QMessageBox, "question", staticmethod(lambda *a, **k: QMessageBox.No))
    monkeypatch.setattr(QMessageBox, "warning", staticmethod(lambda *a, **k: None))
    monkeypatch.setattr(QMessageBox, "critical", staticmethod(lambda *a, **k: None))
    settings = QSettings(str(tmp_path / "settings.ini"), QSettings.IniFormat)
    win = MainWindow(settings=settings)
    win.show()
    yield win
    win.close()


def wait_for_worker(qapp, window, timeout=30):
    deadline = time.time() + timeout
    while window.worker is not None:
        assert time.time() < deadline, "worker did not finish"
        qapp.processEvents(QEventLoop.AllEvents, 50)
        time.sleep(0.01)
    qapp.processEvents()


@pytest.fixture
def loaded(qapp, window, sample_pcap):
    window.load_file(sample_pcap)
    wait_for_worker(qapp, window)
    return window


def test_initial_state(window):
    assert not window.report_action.isEnabled()
    assert not window.filter_bar.isEnabled()
    assert window.tabs.count() == 8


def test_load_populates_tabs(loaded):
    assert len(loaded.all_records) == 12
    assert loaded.packets_tab.model.rowCount() == 12
    assert loaded.conversations_tab.model.rowCount() == 7
    assert loaded.endpoints_tab.model.rowCount() > 0
    assert loaded.protocols_tab.application.model.rowCount() == 3
    assert loaded.report_action.isEnabled()
    assert loaded.filter_bar.status.text() == "Displayed: 12 of 12"


def test_packet_details(qapp, loaded):
    tab = loaded.packets_tab
    tab.view.selectRow(2)
    qapp.processEvents()
    names = [tab.tree.topLevelItem(i).text(0) for i in range(tab.tree.topLevelItemCount())]
    assert "TCP" in names and "Ethernet" in names
    assert tab.hex.toPlainText().startswith("0000")


def test_display_filter_updates_every_tab(loaded):
    loaded.filter_bar.set_text("dns")
    assert [r.number for r in loaded.records] == [5, 6]
    assert loaded.packets_tab.model.rowCount() == 2
    assert loaded.conversations_tab.model.rowCount() == 1
    assert loaded.filter_bar.status.text() == "Displayed: 2 of 12"
    loaded.filter_bar.clear()
    assert len(loaded.records) == 12


def test_invalid_filter_keeps_current_view(loaded):
    loaded.filter_bar.set_text("tcp")
    loaded.filter_bar.set_text("ip.addr ==")
    assert loaded.current_filter == "tcp"


def test_filter_requested_from_tab(loaded):
    conv = loaded.stats.conversations[0]
    loaded.conversations_tab.filter_requested.emit(conv.display_filter())
    assert len(loaded.records) == conv.packets
    assert loaded.tabs.currentWidget() is loaded.packets_tab


def test_quick_search_and_sorting(loaded):
    tab = loaded.endpoints_tab
    tab.search.setText("8.8.8.8")
    assert tab.proxy.rowCount() == 1
    tab.search.clear()
    tab.view.sortByColumn(1, Qt.AscendingOrder)  # packets
    first = tab.proxy.index(0, 1).data()
    last = tab.proxy.index(tab.proxy.rowCount() - 1, 1).data()
    assert int(first) <= int(last)


def test_language_switch(loaded):
    loaded.set_language("es")
    assert loaded.tabs.tabText(1) == "Paquetes"
    assert loaded.packets_tab.model.headerData(0, Qt.Horizontal) == "N.º"
    loaded.set_language("en")
    assert loaded.tabs.tabText(1) == "Packets"


def test_charts_tab_draws_each_chart(qapp, loaded):
    tab = loaded.charts_tab
    for i in range(tab.selector.count()):
        tab.selector.setCurrentIndex(i)
        qapp.processEvents()
        assert tab.canvas.figure.axes


def test_exports(loaded, tmp_path, monkeypatch):
    loaded.filter_bar.set_text("tcp")
    targets = iter([str(tmp_path / "out.pcap"), str(tmp_path / "out.csv"),
                    str(tmp_path / "conv.csv")])
    monkeypatch.setattr(loaded, "_ask_save_path", lambda *a: next(targets))
    loaded.save_filtered_pcap()
    loaded.export_packets_csv()
    loaded.export_conversations_csv()
    from pcap_report.core.parser import read_packets
    assert len(read_packets(str(tmp_path / "out.pcap"))) == 5
    assert os.path.getsize(tmp_path / "out.csv") > 0
    assert os.path.getsize(tmp_path / "conv.csv") > 0


def test_generate_report(qapp, loaded, tmp_path):
    loaded.filter_bar.set_text("not arp")
    loaded.generate_report(str(tmp_path))
    wait_for_worker(qapp, loaded)
    assert loaded.last_report is not None
    assert os.path.isfile(loaded.last_report.html_path)
    assert loaded.open_report_action.isEnabled()
    with open(loaded.last_report.html_path, encoding="utf-8") as f:
        assert "<code>not arp</code>" in f.read()


def test_cancel_loading(qapp, window, sample_pcap, monkeypatch):
    def endless_read(path, progress=None, control=None):
        while True:  # only cancellation can end this "load"
            control.checkpoint()
            time.sleep(0.005)

    monkeypatch.setattr("pcap_report.gui.main_window.read_packets", endless_read)
    window.load_file(sample_pcap)
    window.pause_task()
    assert window.resume_action.isEnabled() and not window.pause_action.isEnabled()
    window.cancel_task()
    wait_for_worker(qapp, window)
    assert window.all_records == []
    assert window.open_action.isEnabled()
