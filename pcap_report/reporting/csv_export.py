"""CSV export of statistics, packets and conversations."""

import csv
import os

from pcap_report.config import REPORT_CSV_FILENAME, TOP_N_ENTRIES


def _fmt_items(items):
    return ", ".join(f"{item} ({count})" for item, count in items)


def generate_csv_summary(stats, report_folder, top_n=TOP_N_ENTRIES):
    """Write a one-row summary CSV into *report_folder* and return its path."""
    row = {
        "Total Packets": stats.total_packets,
        "Total Bytes": stats.total_bytes,
        "Duration (s)": f"{stats.duration:.3f}",
        "Protocols": _fmt_items(stats.protocol_counts.most_common()),
        "Application Protocols": _fmt_items(stats.app_protocol_counts.most_common()),
        "Top Source IPs": _fmt_items(stats.top_sources(top_n)),
        "Top Destination IPs": _fmt_items(stats.top_destinations(top_n)),
        "Top Source Ports": _fmt_items(stats.top_source_ports(top_n)),
        "Top Destination Ports": _fmt_items(stats.top_destination_ports(top_n)),
        "Top Conversations": _fmt_items(
            (c.label(), c.packets) for c in stats.top_conversations(top_n)
        ),
    }
    csv_path = os.path.join(report_folder, REPORT_CSV_FILENAME)
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(row))
        writer.writeheader()
        writer.writerow(row)
    return csv_path


PACKET_COLUMNS = ("No.", "Time", "Source", "Destination", "Protocol",
                  "Source Port", "Destination Port", "Length", "Info")


def write_packets_csv(records, path):
    """Write one line per packet record."""
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(PACKET_COLUMNS)
        for r in records:
            writer.writerow([
                r.number, f"{r.relative_time:.6f}", r.src, r.dst, r.display_protocol,
                "" if r.sport is None else r.sport,
                "" if r.dport is None else r.dport,
                r.length, r.info,
            ])
    return path


CONVERSATION_COLUMNS = ("Protocol", "Address A", "Port A", "Address B", "Port B",
                        "Packets", "Bytes", "Packets A->B", "Packets B->A",
                        "Bytes A->B", "Bytes B->A", "Duration (s)")


def write_conversations_csv(conversations, path):
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(CONVERSATION_COLUMNS)
        for c in conversations:
            writer.writerow([
                c.protocol, c.addr_a, "" if c.port_a is None else c.port_a,
                c.addr_b, "" if c.port_b is None else c.port_b,
                c.packets, c.bytes, c.packets_a_to_b, c.packets_b_to_a,
                c.bytes_a_to_b, c.bytes_b_to_a, f"{c.duration:.3f}",
            ])
    return path
