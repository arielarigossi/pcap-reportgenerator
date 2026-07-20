"""Tests for the report module."""

import os
import tempfile

from collections import Counter

from pcap_report.report import generate_html_report


def _make_statistics():
    return {
        "total_packets": 100,
        "protocol_distribution": Counter({"TCP": 70, "UDP": 30}),
        "top_talkers_src": [("192.168.1.1", 50), ("10.0.0.5", 30)],
        "top_talkers_dst": [("172.16.0.1", 60), ("10.0.0.1", 25)],
        "top_source_ports": [(443, 40), (80, 25)],
        "top_destination_ports": [(54321, 45), (8080, 20)],
        "top_conversations": [
            (("192.168.1.1", "172.16.0.1", "TCP", 443, 54321), 35),
        ],
    }


def _make_chart_paths():
    return {
        "protocol_distribution": "protocol_distribution.png",
        "top_source_ips": "top_source_ips.png",
        "top_destination_ips": "top_destination_ips.png",
        "top_source_ports": "top_source_ports.png",
        "top_destination_ports": "top_destination_ports.png",
        "top_conversations": "top_conversations.png",
    }


def test_generate_html_report_creates_file():
    with tempfile.TemporaryDirectory() as tmpdir:
        html_path = generate_html_report(
            _make_statistics(), _make_chart_paths(), tmpdir, lang="en"
        )
        assert os.path.exists(html_path)
        assert html_path.endswith(".html")


def test_generate_html_report_escapes_special_characters():
    stats = _make_statistics()
    stats["top_talkers_src"] = [("192.168.1.<script>alert(1)</script>", 10)]
    with tempfile.TemporaryDirectory() as tmpdir:
        html_path = generate_html_report(
            stats, _make_chart_paths(), tmpdir, lang="en"
        )
        with open(html_path, "r") as f:
            content = f.read()
        assert "<script>alert(1)</script>" not in content
        assert "&lt;script&gt;" in content


def test_generate_html_report_spanish():
    with tempfile.TemporaryDirectory() as tmpdir:
        html_path = generate_html_report(
            _make_statistics(), _make_chart_paths(), tmpdir, lang="es"
        )
        with open(html_path, "r") as f:
            content = f.read()
        assert "Reporte de" in content


def test_generate_html_report_contains_data_js():
    with tempfile.TemporaryDirectory() as tmpdir:
        html_path = generate_html_report(
            _make_statistics(), _make_chart_paths(), tmpdir, lang="en"
        )
        with open(html_path, "r") as f:
            content = f.read()
        assert "REPORT_DATA" in content
        assert "applyFilter" in content
        assert "performQuery" in content
