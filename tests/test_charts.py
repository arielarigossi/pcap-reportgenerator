"""Tests for the charts module."""

import os
import tempfile

from collections import Counter

from pcap_report.charts import generate_all_charts


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


def test_generate_all_charts_returns_keys():
    with tempfile.TemporaryDirectory() as tmpdir:
        paths = generate_all_charts(_make_statistics(), tmpdir)
        expected_keys = {
            "protocol_distribution", "top_source_ips", "top_destination_ips",
            "top_source_ports", "top_destination_ports", "top_conversations",
        }
        assert set(paths.keys()) == expected_keys


def test_generate_all_charts_creates_files():
    with tempfile.TemporaryDirectory() as tmpdir:
        paths = generate_all_charts(_make_statistics(), tmpdir)
        for key, filename in paths.items():
            full_path = os.path.join(tmpdir, filename)
            assert os.path.exists(full_path), f"Missing chart: {key} -> {filename}"


def test_generate_all_charts_empty_data():
    empty_stats = {
        "total_packets": 0,
        "protocol_distribution": Counter(),
        "top_talkers_src": [],
        "top_talkers_dst": [],
        "top_source_ports": [],
        "top_destination_ports": [],
        "top_conversations": [],
    }
    with tempfile.TemporaryDirectory() as tmpdir:
        paths = generate_all_charts(empty_stats, tmpdir)
        assert len(paths) == 6
        for key, filename in paths.items():
            assert os.path.exists(os.path.join(tmpdir, filename))
