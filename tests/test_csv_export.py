"""Tests for the csv_export module."""

import os
import tempfile

from collections import Counter

from pcap_report.csv_export import generate_csv_summary


def _make_statistics():
    return {
        "total_packets": 42,
        "protocol_distribution": Counter({"TCP": 30, "UDP": 12}),
        "top_talkers_src": [("192.168.1.1", 20), ("10.0.0.5", 15)],
        "top_talkers_dst": [("172.16.0.1", 25), ("10.0.0.1", 10)],
        "top_source_ports": [(443, 18), (80, 12)],
        "top_destination_ports": [(54321, 20), (8080, 10)],
        "top_conversations": [
            (("192.168.1.1", "172.16.0.1", "TCP", 443, 54321), 15),
            (("10.0.0.5", "10.0.0.1", "UDP", 12345, 8080), 8),
        ],
    }


def test_generate_csv_summary_creates_file():
    with tempfile.TemporaryDirectory() as tmpdir:
        stats = _make_statistics()
        csv_path = generate_csv_summary(stats, tmpdir)
        assert os.path.exists(csv_path)
        assert csv_path.endswith(".csv")


def test_generate_csv_summary_content():
    with tempfile.TemporaryDirectory() as tmpdir:
        stats = _make_statistics()
        csv_path = generate_csv_summary(stats, tmpdir)
        with open(csv_path, "r") as f:
            content = f.read()
        assert "Total Packets" in content
        assert "42" in content
        assert "192.168.1.1" in content
