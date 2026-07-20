"""CSV summary export functionality."""

import os

import pandas as pd

from pcap_report.config import REPORT_CSV_FILENAME


def generate_csv_summary(statistics, report_folder):
    """Write a single-row CSV summary of the analysis results.

    Parameters
    ----------
    statistics : dict
        Output of :func:`PCAPAnalyzer.analyze_packets`.
    report_folder : str
        Directory where the CSV file will be written.

    Returns
    -------
    str
        Absolute path of the generated CSV file.
    """
    def _fmt_list(items, fmt="{item} ({count})"):
        return ", ".join(fmt.format(item=item, count=count) for item, count in items)

    def _fmt_conversations(items):
        parts = []
        for (src, dst, proto, sport, dport), count in items:
            parts.append(f"{src} \u2192 {dst} ({proto}) [{sport}\u2192{dport}] ({count})")
        return ", ".join(parts)

    data = {
        "Total Packets": [statistics["total_packets"]],
        "Top Source IPs": [_fmt_list(statistics["top_talkers_src"])],
        "Top Destination IPs": [_fmt_list(statistics["top_talkers_dst"])],
        "Top Source Ports": [_fmt_list(statistics["top_source_ports"])],
        "Top Destination Ports": [_fmt_list(statistics["top_destination_ports"])],
        "Top Conversations": [_fmt_conversations(statistics["top_conversations"])],
    }

    csv_path = os.path.join(report_folder, REPORT_CSV_FILENAME)
    df = pd.DataFrame(data)
    df.to_csv(csv_path, index=False)
    return csv_path
