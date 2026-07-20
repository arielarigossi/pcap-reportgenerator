"""PCAP analysis worker running in a QThread."""

import os
import traceback
from collections import Counter
from datetime import datetime

from PyQt5.QtCore import QObject, QMutex, QWaitCondition, pyqtSignal
from scapy.all import rdpcap, TCP, UDP, IP

from pcap_report.charts import generate_all_charts
from pcap_report.config import (
    PROGRESS_PACKET_INTERVAL, REPORT_SUBFOLDER_PREFIX, TIMESTAMP_FORMAT,
)
from pcap_report.csv_export import generate_csv_summary
from pcap_report.i18n import get_translation
from pcap_report.report import generate_html_report


class PCAPAnalyzer(QObject):
    """Worker that reads a PCAP file and produces analysis artefacts.

    Intended to be moved to a :class:`QThread` before calling :meth:`run`.
    """

    progress = pyqtSignal(int)
    log = pyqtSignal(str)
    finished = pyqtSignal(float)
    error = pyqtSignal(str)

    def __init__(self, pcap_file, output_folder, report_folder, lang="en"):
        super().__init__()
        self.pcap_file = pcap_file
        self.output_folder = output_folder
        self.report_folder = report_folder
        self.lang = lang
        self.statistics = {}
        self.chart_paths = {}

        self._pause = False
        self._cancel = False
        self._mutex = QMutex()
        self._condition = QWaitCondition()

    # -- helpers ------------------------------------------------------------ #

    def _tr(self, key):
        return get_translation(self.lang, key)

    def _emit_log(self, key, **kwargs):
        self.log.emit(f"<span style='color:blue;'>{self._tr(key).format(**kwargs)}</span>")

    # -- pause / resume / cancel ------------------------------------------- #

    def pause(self):
        self._mutex.lock()
        self._pause = True
        self._mutex.unlock()

    def resume(self):
        self._mutex.lock()
        self._pause = False
        self._condition.wakeAll()
        self._mutex.unlock()

    def cancel(self):
        self._mutex.lock()
        self._cancel = True
        self._condition.wakeAll()
        self._mutex.unlock()

    def _check_pause_cancel(self):
        self._mutex.lock()
        if self._cancel:
            self._mutex.unlock()
            raise Exception(self._tr("processing_cancelled"))
        while self._pause:
            self.log.emit(f"<span style='color:yellow;'>{self._tr('processing_paused')}</span>")
            self._condition.wait(self._mutex)
            if self._cancel:
                self._mutex.unlock()
                raise Exception(self._tr("processing_cancelled"))
        self._mutex.unlock()

    # -- main pipeline ------------------------------------------------------ #

    def run(self):
        start_time = datetime.now()
        try:
            os.makedirs(self.report_folder, exist_ok=True)
            self._emit_log("generating_summary")
            self.progress.emit(5)

            if not os.path.isfile(self.pcap_file):
                raise FileNotFoundError(self._tr("invalid_pcap"))
            self.progress.emit(10)

            self.log.emit("<span style='color:blue;'>Loading PCAP file...</span>")
            try:
                packets = rdpcap(self.pcap_file)
                self.log.emit(
                    f"<span style='color:green;'>[Success]</span> Loaded {len(packets)} packets."
                )
            except Exception as e:
                raise Exception(f"Failed to read pcap file: {e}")
            self.progress.emit(20)

            self.log.emit("<span style='color:blue;'>Analyzing packets...</span>")
            self._analyze_packets(packets)
            self.progress.emit(50)

            self.log.emit("<span style='color:blue;'>Generating charts...</span>")
            self.chart_paths = generate_all_charts(self.statistics, self.report_folder)
            self.progress.emit(75)

            self._emit_log("generating_html_report")
            generate_html_report(
                self.statistics, self.chart_paths, self.report_folder, lang=self.lang
            )
            self.progress.emit(100)

            elapsed = (datetime.now() - start_time).total_seconds()
            self.log.emit(
                f"<span style='color:green;'>{self._tr('analysis_completed').format(time=elapsed)}</span>"
            )
            self.finished.emit(elapsed)

        except Exception as e:
            msg = self._tr("error_occurred").format(error=str(e))
            self.error.emit(
                f"<span style='color:red;'>{msg}</span>\n{traceback.format_exc()}"
            )

    # -- packet analysis ---------------------------------------------------- #

    def _analyze_packets(self, packets):
        total = len(packets)
        protocol_counter = Counter()
        src_ip_counter = Counter()
        dst_ip_counter = Counter()
        src_port_counter = Counter()
        dst_port_counter = Counter()
        conversations = Counter()

        for idx, packet in enumerate(packets):
            self._check_pause_cancel()

            if IP in packet:
                ip_layer = packet[IP]
                src_ip = ip_layer.src
                dst_ip = ip_layer.dst

                src_ip_counter[src_ip] += 1
                dst_ip_counter[dst_ip] += 1

                if TCP in packet:
                    protocol = "TCP"
                    sport = packet[TCP].sport
                    dport = packet[TCP].dport
                elif UDP in packet:
                    protocol = "UDP"
                    sport = packet[UDP].sport
                    dport = packet[UDP].dport
                else:
                    protocol = ip_layer.proto
                    sport = "N/A"
                    dport = "N/A"

                protocol_counter[protocol] += 1
                if sport != "N/A":
                    src_port_counter[sport] += 1
                if dport != "N/A":
                    dst_port_counter[dport] += 1

                conversations[(src_ip, dst_ip, protocol, sport, dport)] += 1

            if idx % PROGRESS_PACKET_INTERVAL == 0 and idx != 0:
                self.progress.emit(int((idx / total) * 50))

        self.statistics = {
            "total_packets": total,
            "protocol_distribution": protocol_counter,
            "top_talkers_src": src_ip_counter.most_common(10),
            "top_talkers_dst": dst_ip_counter.most_common(10),
            "top_source_ports": src_port_counter.most_common(10),
            "top_destination_ports": dst_port_counter.most_common(10),
            "top_conversations": conversations.most_common(10),
        }

        csv_path = generate_csv_summary(self.statistics, self.report_folder)
        self.log.emit(
            f"<span style='color:green;'>CSV summary generated at {csv_path}</span>"
        )
