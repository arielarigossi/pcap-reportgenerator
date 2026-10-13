"""Tests for charts, CSV and HTML report generation."""

import csv
import os

from pcap_report.core.statistics import compute_statistics
from pcap_report.i18n import Translator
from pcap_report.reporting.charts import CHARTS, build_chart, save_all_charts
from pcap_report.reporting.csv_export import (
    generate_csv_summary, write_conversations_csv, write_packets_csv,
)
from pcap_report.reporting.html_report import generate_html_report
from pcap_report.reporting.pipeline import generate_report


def test_save_all_charts(stats, tmp_path):
    paths = save_all_charts(stats, str(tmp_path))
    assert set(paths) == set(CHARTS)
    for filename in paths.values():
        assert (tmp_path / filename).stat().st_size > 0


def test_charts_with_empty_statistics(tmp_path):
    paths = save_all_charts(compute_statistics([]), str(tmp_path), lang="es")
    assert len(paths) == len(CHARTS)


def test_build_chart_reuses_given_figure(stats):
    from matplotlib.figure import Figure

    fig = Figure()
    assert build_chart("protocol_distribution", stats, Translator(), fig=fig) is fig


def test_csv_summary(stats, tmp_path):
    path = generate_csv_summary(stats, str(tmp_path))
    with open(path, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    assert rows[0]["Total Packets"] == "12"
    assert "192.168.1.10" in rows[0]["Top Source IPs"]


def test_packets_and_conversations_csv(records, stats, tmp_path):
    packets = write_packets_csv(records, str(tmp_path / "p.csv"))
    with open(packets, newline="", encoding="utf-8") as f:
        rows = list(csv.reader(f))
    assert len(rows) == 13
    assert rows[3][-1] == "GET /index.html HTTP/1.1"

    convs = write_conversations_csv(stats.conversations, str(tmp_path / "c.csv"))
    with open(convs, newline="", encoding="utf-8") as f:
        assert len(list(csv.reader(f))) == len(stats.conversations) + 1


def _render(stats, tmp_path, **kwargs):
    path = generate_html_report(stats, {}, str(tmp_path), **kwargs)
    with open(path, encoding="utf-8") as f:
        return f.read()


def test_html_report_content(stats, tmp_path):
    html = _render(stats, tmp_path, source_file="/x/sample.pcap", display_filter="tcp")
    assert "REPORT_DATA" in html
    assert "applyFilter" in html and "performQuery" in html
    assert "sample.pcap" in html and "<code>tcp</code>" in html
    assert '"DNS": 2' in html  # protocol queries count application protocols


def test_html_report_escapes_packet_data(stats, tmp_path):
    stats = compute_statistics([])
    stats.src_ip_counts["<script>alert(1)</script>"] = 3
    stats.protocol_counts["</script><b>"] = 1
    html = _render(stats, tmp_path)
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html
    assert "</script><b>" not in html


def test_html_report_spanish(stats, tmp_path):
    assert "Reporte de Análisis de PCAP" in _render(stats, tmp_path, lang="es")


def test_generate_report_pipeline(records, tmp_path):
    steps = []
    result = generate_report(records, str(tmp_path), log=steps.append)
    assert os.path.isfile(result.html_path) and os.path.isfile(result.csv_path)
    assert os.path.dirname(result.html_path) == result.folder
    assert steps == ["charts", "csv", "html"]
