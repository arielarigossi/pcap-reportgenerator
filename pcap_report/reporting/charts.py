"""Chart builders shared by the GUI and the HTML report.

Charts are built with matplotlib's object-oriented API (``Figure``) rather
than ``pyplot``, so they are safe to create from worker threads and can be
embedded directly in a Qt canvas.
"""

import os

from matplotlib.figure import Figure

from pcap_report.config import TOP_N_ENTRIES
from pcap_report.i18n import Translator

BAR_COLOR = "#2a78d6"
SECONDARY_COLOR = "#1baf7a"


def _figure(fig, size):
    """Reuse *fig* (cleared) when given, e.g. a GUI canvas figure."""
    if fig is None:
        fig = Figure(figsize=size)
    else:
        fig.clear()
    fig.set_layout_engine("tight")  # re-applied on every draw / resize
    return fig


def protocol_pie(stats, tr, fig=None):
    fig = _figure(fig, (7, 6))
    ax = fig.add_subplot()
    items = stats.protocol_counts.most_common()
    if not items:
        return _empty(fig, ax, tr("protocol_distribution"), tr)
    # Group the long tail into "Other" so the pie stays readable.
    if len(items) > 8:
        other = sum(count for _, count in items[7:])
        items = items[:7] + [(tr("other"), other)]
    labels, counts = zip(*items)
    ax.pie(counts, labels=labels, autopct="%1.1f%%", startangle=140,
           wedgeprops={"edgecolor": "white", "linewidth": 2})
    ax.set_title(tr("protocol_distribution"))
    return fig


def app_protocol_bar(stats, tr, fig=None):
    return _bar(stats.app_protocol_counts.most_common(TOP_N_ENTRIES),
                tr("application_protocols"), tr("protocol"), tr, fig=fig)


def top_sources_bar(stats, tr, fig=None):
    return _bar(stats.top_sources(TOP_N_ENTRIES), tr("top_source_ips"), tr("source_ip"),
                tr, fig=fig)


def top_destinations_bar(stats, tr, fig=None):
    return _bar(stats.top_destinations(TOP_N_ENTRIES), tr("top_destination_ips"),
                tr("destination_ip"), tr, fig=fig)


def top_source_ports_bar(stats, tr, fig=None):
    return _bar(stats.top_source_ports(TOP_N_ENTRIES), tr("source_ports"), tr("source_port"),
                tr, fig=fig)


def top_destination_ports_bar(stats, tr, fig=None):
    return _bar(stats.top_destination_ports(TOP_N_ENTRIES), tr("destination_ports"),
                tr("destination_port"), tr, fig=fig)


def top_conversations_bar(stats, tr, fig=None):
    items = [(c.label(), c.packets) for c in stats.top_conversations(TOP_N_ENTRIES)]
    return _bar(items, tr("top_conversations"), "", tr, fig=fig, horizontal=True)


def traffic_timeline(stats, tr, fig=None):
    fig = _figure(fig, (10, 5))
    ax = fig.add_subplot()
    if not stats.timeline:
        return _empty(fig, ax, tr("traffic_over_time"), tr)
    times = [t for t, _, _ in stats.timeline]
    packets = [p for _, p, _ in stats.timeline]
    ax.plot(times, packets, color=BAR_COLOR, linewidth=2)
    ax.fill_between(times, packets, color=BAR_COLOR, alpha=0.15)
    ax.set_xlabel(tr("time_seconds"))
    ax.set_ylabel(tr("packets_per_interval").format(interval=_fmt_interval(stats.timeline_bucket)))
    ax.set_title(tr("traffic_over_time"))
    ax.set_ylim(bottom=0)
    ax.grid(True, alpha=0.3)
    return fig


def packet_size_histogram(stats, tr, sizes=None, fig=None):
    """Histogram of packet sizes; *sizes* is the list of packet lengths."""
    fig = _figure(fig, (10, 5))
    ax = fig.add_subplot()
    if not sizes:
        return _empty(fig, ax, tr("packet_sizes"), tr)
    ax.hist(sizes, bins=min(50, max(5, len(set(sizes)))), color=SECONDARY_COLOR,
            edgecolor="white")
    ax.set_xlabel(tr("packet_size_bytes"))
    ax.set_ylabel(tr("packets"))
    ax.set_title(tr("packet_sizes"))
    ax.grid(True, axis="y", alpha=0.3)
    return fig


def _fmt_interval(seconds):
    if seconds < 1:
        return f"{seconds * 1000:g} ms"
    return f"{seconds:g} s"


def _bar(items, title, xlabel, tr, fig=None, horizontal=False):
    fig = _figure(fig, (10, 6))
    ax = fig.add_subplot()
    if not items:
        return _empty(fig, ax, title, tr)
    labels = [str(label) for label, _ in items]
    counts = [count for _, count in items]
    if horizontal:
        ax.barh(labels[::-1], counts[::-1], color=BAR_COLOR)
        ax.set_xlabel(tr("packets"))
        ax.grid(True, axis="x", alpha=0.3)
    else:
        ax.bar(labels, counts, color=BAR_COLOR)
        ax.set_xlabel(xlabel)
        ax.set_ylabel(tr("packets"))
        ax.tick_params(axis="x", labelrotation=45)
        for label in ax.get_xticklabels():
            label.set_horizontalalignment("right")
        ax.grid(True, axis="y", alpha=0.3)
    ax.set_title(title)
    ax.set_axisbelow(True)
    return fig


def _empty(fig, ax, title, tr):
    ax.text(0.5, 0.5, tr("no_data"), ha="center", va="center", fontsize=14, color="gray")
    ax.set_title(title)
    ax.axis("off")
    return fig


# key -> (title translation key, builder)
CHARTS = {
    "protocol_distribution": ("protocol_distribution", protocol_pie),
    "application_protocols": ("application_protocols", app_protocol_bar),
    "traffic_over_time": ("traffic_over_time", traffic_timeline),
    "top_source_ips": ("top_source_ips", top_sources_bar),
    "top_destination_ips": ("top_destination_ips", top_destinations_bar),
    "top_source_ports": ("source_ports", top_source_ports_bar),
    "top_destination_ports": ("destination_ports", top_destination_ports_bar),
    "top_conversations": ("top_conversations", top_conversations_bar),
}


def build_chart(key, stats, tr, fig=None):
    return CHARTS[key][1](stats, tr, fig=fig)


def save_all_charts(stats, folder, lang="en"):
    """Render every chart in :data:`CHARTS` as PNG into *folder*.

    Returns a mapping of chart key to file name (relative to *folder*).
    """
    tr = Translator(lang)
    paths = {}
    for key in CHARTS:
        filename = f"{key}.png"
        fig = build_chart(key, stats, tr)
        fig.savefig(os.path.join(folder, filename), dpi=100)
        paths[key] = filename
    return paths
