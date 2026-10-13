#!/usr/bin/env python3
"""Run PCAP Analyzer from a source checkout (``python pcap-report.py``).

The application lives in the :mod:`pcap_report` package; this script is
kept for backwards compatibility with the original single-file version.
"""

from pcap_report.app import main

if __name__ == "__main__":
    main()
