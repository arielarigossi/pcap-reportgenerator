"""Chart generation for PCAP analysis results."""

import os

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt


def generate_all_charts(statistics, report_folder):
    """Generate all analysis charts and return their relative paths.

    Parameters
    ----------
    statistics : dict
        Output of :func:`PCAPAnalyzer.analyze_packets`.
    report_folder : str
        Directory where chart PNG files will be saved.

    Returns
    -------
    dict
        Mapping of chart key to relative filename (e.g. ``{'protocol_distribution': 'protocol_distribution.png'}``).
    """
    chart_paths = {}

    chart_paths["protocol_distribution"] = _pie_chart(
        statistics["protocol_distribution"], report_folder
    )
    chart_paths["top_source_ips"] = _bar_chart(
        statistics["top_talkers_src"], report_folder,
        filename="top_source_ips.png",
        title="Top Source IPs by Packet Count",
        xlabel="Source IP",
    )
    chart_paths["top_destination_ips"] = _bar_chart(
        statistics["top_talkers_dst"], report_folder,
        filename="top_destination_ips.png",
        title="Top Destination IPs by Packet Count",
        xlabel="Destination IP",
    )
    chart_paths["top_source_ports"] = _bar_chart(
        statistics["top_source_ports"], report_folder,
        filename="top_source_ports.png",
        title="Top Source Ports by Packet Count",
        xlabel="Source Port",
        str_labels=True,
    )
    chart_paths["top_destination_ports"] = _bar_chart(
        statistics["top_destination_ports"], report_folder,
        filename="top_destination_ports.png",
        title="Top Destination Ports by Packet Count",
        xlabel="Destination Port",
        str_labels=True,
    )
    chart_paths["top_conversations"] = _conversation_chart(
        statistics["top_conversations"], report_folder
    )

    return chart_paths


def _pie_chart(protocol_counter, report_folder):
    """Create a pie chart of protocol distribution."""
    protocols = list(protocol_counter.keys())
    counts = list(protocol_counter.values())

    if not counts:
        return _empty_chart(report_folder, "protocol_distribution.png",
                            "Protocol Distribution")

    plt.figure(figsize=(8, 8))
    plt.pie(counts, labels=protocols, autopct="%1.1f%%", startangle=140,
            colors=plt.cm.tab20.colors)
    plt.title("Protocol Distribution")
    plt.tight_layout()

    filename = "protocol_distribution.png"
    plt.savefig(os.path.join(report_folder, filename))
    plt.close()
    return filename


def _bar_chart(counter_items, report_folder, filename, title, xlabel,
               str_labels=False):
    """Create a generic bar chart from a list of (label, count) pairs."""
    if not counter_items:
        return _empty_chart(report_folder, filename, title)

    labels, counts = zip(*counter_items)
    if str_labels:
        labels = [str(l) for l in labels]

    plt.figure(figsize=(10, 6))
    plt.bar(labels, counts, color=plt.cm.Paired.colors)
    plt.xlabel(xlabel)
    plt.ylabel("Number of Packets")
    plt.title(title)
    plt.xticks(rotation=45, ha="right")
    plt.tight_layout()

    plt.savefig(os.path.join(report_folder, filename))
    plt.close()
    return filename


def _conversation_chart(conversations, report_folder):
    """Create a bar chart of top conversations."""
    if not conversations:
        return _empty_chart(report_folder, "top_conversations.png",
                            "Top Conversations")

    items, counts = zip(*conversations)
    labels = [f"{c[0]} \u2192 {c[1]} ({c[2]}) [{c[3]}\u2192{c[4]}]" for c in items]

    plt.figure(figsize=(12, 7))
    plt.bar(labels, counts, color=plt.cm.Paired.colors)
    plt.xlabel("Conversations")
    plt.ylabel("Number of Packets")
    plt.title("Top Conversations by Packet Count")
    plt.xticks(rotation=45, ha="right")
    plt.tight_layout()

    filename = "top_conversations.png"
    plt.savefig(os.path.join(report_folder, filename))
    plt.close()
    return filename


def _empty_chart(report_folder, filename, title):
    """Create a placeholder chart when there is no data."""
    plt.figure(figsize=(8, 4))
    plt.text(0.5, 0.5, "No data available", ha="center", va="center",
             fontsize=14, color="gray")
    plt.title(title)
    plt.axis("off")
    plt.tight_layout()

    plt.savefig(os.path.join(report_folder, filename))
    plt.close()
    return filename
