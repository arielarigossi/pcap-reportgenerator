"""Application entry point: GUI by default, or headless report generation.

Usage::

    pcap-report                         # launch the GUI
    pcap-report capture.pcap            # launch the GUI and open a file
    pcap-report capture.pcap --no-gui -o reports/ [-f "tcp.port == 443"] [--lang es]
"""

import argparse
import os
import sys

from pcap_report import __version__
from pcap_report.i18n import LANGUAGES


def build_parser():
    parser = argparse.ArgumentParser(
        prog="pcap-report",
        description="Analyze PCAP/PCAPNG captures and generate HTML/CSV reports.",
    )
    parser.add_argument("pcap", nargs="?", help="capture file to open")
    parser.add_argument("--no-gui", action="store_true",
                        help="generate a report without opening the GUI")
    parser.add_argument("-o", "--output", default=".",
                        help="output directory for --no-gui reports (default: .)")
    parser.add_argument("-f", "--filter", default="",
                        help="display filter applied before reporting (--no-gui)")
    parser.add_argument("--lang", choices=sorted(LANGUAGES), default=None,
                        help="report / interface language")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def run_headless(args):
    from pcap_report.core.filters import FilterSyntaxError, apply_filter, compile_filter
    from pcap_report.core.parser import read_packets
    from pcap_report.reporting.pipeline import generate_report

    if not args.pcap or not os.path.isfile(args.pcap):
        print(f"error: capture file not found: {args.pcap}", file=sys.stderr)
        return 2
    try:
        compile_filter(args.filter)
    except FilterSyntaxError as exc:
        print(f"error: invalid filter: {exc}", file=sys.stderr)
        return 2
    os.makedirs(args.output, exist_ok=True)

    records = read_packets(args.pcap)
    selected = apply_filter(records, args.filter)
    print(f"{len(selected)} of {len(records)} packets selected")

    result = generate_report(selected, args.output, lang=args.lang or "en",
                             source_file=args.pcap, display_filter=args.filter or None)
    print(f"HTML report: {result.html_path}")
    print(f"CSV summary: {result.csv_path}")
    return 0


def run_gui(args):
    from PyQt5.QtWidgets import QApplication

    from pcap_report.gui.main_window import MainWindow

    app = QApplication(sys.argv[:1])
    app.setApplicationName("PCAP Analyzer")
    window = MainWindow()
    if args.lang:
        window.set_language(args.lang)
    window.show()
    if args.pcap:
        window.load_file(os.path.abspath(args.pcap))
    return app.exec_()


def main(argv=None):
    args = build_parser().parse_args(argv)
    code = run_headless(args) if args.no_gui else run_gui(args)
    sys.exit(code)


if __name__ == "__main__":
    main()
