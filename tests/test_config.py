"""Tests for the config module."""

from pcap_report.config import (
    PROGRESS_PACKET_INTERVAL,
    REPORT_CSV_FILENAME,
    REPORT_HTML_FILENAME,
    REPORT_SUBFOLDER_PREFIX,
    SUPPORTED_EXTENSIONS,
    TIMESTAMP_FORMAT,
    TOP_N_ENTRIES,
)


def test_constants_are_strings_or_ints():
    assert isinstance(REPORT_SUBFOLDER_PREFIX, str)
    assert isinstance(TIMESTAMP_FORMAT, str)
    assert isinstance(REPORT_HTML_FILENAME, str)
    assert isinstance(REPORT_CSV_FILENAME, str)
    assert isinstance(SUPPORTED_EXTENSIONS, tuple)
    assert isinstance(PROGRESS_PACKET_INTERVAL, int)
    assert isinstance(TOP_N_ENTRIES, int)


def test_supported_extensions_contain_pcap():
    assert ".pcap" in SUPPORTED_EXTENSIONS
    assert ".pcapng" in SUPPORTED_EXTENSIONS
