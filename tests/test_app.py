"""Tests for the command line entry point (headless mode)."""

import os

import pytest

from pcap_report.app import main


def run(argv):
    with pytest.raises(SystemExit) as exc:
        main(argv)
    return exc.value.code


def test_headless_report(sample_pcap, tmp_path, capsys):
    assert run([sample_pcap, "--no-gui", "-o", str(tmp_path), "-f", "tcp", "--lang", "es"]) == 0
    out = capsys.readouterr().out
    assert "5 of 12 packets selected" in out
    folders = os.listdir(tmp_path)
    assert len(folders) == 1
    assert os.path.isfile(tmp_path / folders[0] / "pcap_analysis_report.html")


def test_headless_invalid_filter(sample_pcap, tmp_path, capsys):
    assert run([sample_pcap, "--no-gui", "-o", str(tmp_path), "-f", "ip.addr =="]) == 2
    assert "invalid filter" in capsys.readouterr().err
    assert not os.listdir(tmp_path)


def test_headless_missing_file(tmp_path):
    assert run([str(tmp_path / "nope.pcap"), "--no-gui"]) == 2
