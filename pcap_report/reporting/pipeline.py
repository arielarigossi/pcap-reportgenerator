"""End-to-end report generation (charts + HTML + CSV) for a set of packets."""

import os
from dataclasses import dataclass
from datetime import datetime

from pcap_report.config import REPORT_SUBFOLDER_PREFIX, TIMESTAMP_FORMAT
from pcap_report.core.statistics import compute_statistics
from pcap_report.reporting.charts import save_all_charts
from pcap_report.reporting.csv_export import generate_csv_summary
from pcap_report.reporting.html_report import generate_html_report


@dataclass
class ReportResult:
    folder: str
    html_path: str
    csv_path: str
    chart_paths: dict


def make_report_folder(output_dir, now=None):
    timestamp = (now or datetime.now()).strftime(TIMESTAMP_FORMAT)
    folder = os.path.join(output_dir, f"{REPORT_SUBFOLDER_PREFIX}_{timestamp}")
    os.makedirs(folder, exist_ok=True)
    return folder


def generate_report(records, output_dir, lang="en", source_file=None,
                    display_filter=None, stats=None, log=None):
    """Generate all report artefacts in a new timestamped sub-folder.

    *stats* may be passed when already computed for *records*.
    *log* is an optional callable receiving progress messages.
    """
    log = log or (lambda message: None)
    folder = make_report_folder(output_dir)
    if stats is None:
        stats = compute_statistics(records)

    log("charts")
    chart_paths = save_all_charts(stats, folder, lang=lang)
    log("csv")
    csv_path = generate_csv_summary(stats, folder)
    log("html")
    html_path = generate_html_report(stats, chart_paths, folder, lang=lang,
                                     source_file=source_file, display_filter=display_filter)
    return ReportResult(folder, html_path, csv_path, chart_paths)
