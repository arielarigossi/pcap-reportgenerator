"""Standalone HTML report generation."""

import json
import os
from datetime import datetime
from html import escape

from pcap_report.config import (
    REPORT_HTML_FILENAME, REPORT_MAX_CONVERSATIONS, TOP_N_ENTRIES,
)
from pcap_report.i18n import Translator
from pcap_report.reporting.charts import CHARTS

_HEAD_ASSETS = """
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdn.datatables.net/1.13.5/css/dataTables.bootstrap5.min.css" rel="stylesheet">"""

_BODY_ASSETS = """
    <script src="https://code.jquery.com/jquery-3.7.0.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script src="https://cdn.datatables.net/1.13.5/js/jquery.dataTables.min.js"></script>
    <script src="https://cdn.datatables.net/1.13.5/js/dataTables.bootstrap5.min.js"></script>"""

_STYLE = """
        body { background-color: #f0f2f5; padding: 20px 0; }
        h1 { text-align: center; color: #2c3e50; margin-bottom: 24px; }
        h2 { color: #34495e; margin-top: 32px; }
        .chart { text-align: center; margin-bottom: 32px; }
        .card-stat .value { font-size: 1.6em; font-weight: 600; }
        .card-stat .label { color: #6c757d; }
        .panel { background: #fff; border-radius: 8px; padding: 16px; margin-bottom: 20px; }
        .meta { color: #6c757d; text-align: center; }"""

# Client-side behaviour: conversation filtering and protocol queries.
# Values are always escaped before being inserted into the DOM.
_SCRIPT = """
        function esc(v) {
            return String(v).replace(/[&<>"']/g, function(c) {
                return {'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[c];
            });
        }

        // DataTables is optional: the report stays usable offline without the CDN.
        if (window.jQuery && jQuery.fn.DataTable) {
            jQuery(function() {
                jQuery('table.datatable').DataTable({ paging: true, searching: true,
                                                      info: false, order: [] });
            });
        }

        function applyFilter() {
            var srcIp = document.getElementById('source_ip').value.trim();
            var dstIp = document.getElementById('destination_ip').value.trim();
            var proto = document.getElementById('protocol').value;
            var filtered = REPORT_DATA.conversations.filter(function(c) {
                if (srcIp && c.a.indexOf(srcIp) === -1 && c.b.indexOf(srcIp) === -1) return false;
                if (dstIp && c.a.indexOf(dstIp) === -1 && c.b.indexOf(dstIp) === -1) return false;
                if (proto && c.proto !== proto) return false;
                return true;
            });
            var out = document.getElementById('filter_results');
            if (filtered.length === 0) {
                out.innerHTML = '<p>' + esc(REPORT_DATA.labels.no_matches) + '</p>';
                return;
            }
            var html = '<p><strong>' + filtered.length + '</strong> ' +
                       esc(REPORT_DATA.labels.matches) + '</p>' +
                       '<table class="table table-sm table-striped"><thead><tr>';
            REPORT_DATA.labels.columns.forEach(function(h) { html += '<th>' + esc(h) + '</th>'; });
            html += '</tr></thead><tbody>';
            filtered.forEach(function(c) {
                html += '<tr><td>' + esc(c.proto) + '</td><td>' + esc(c.a) + '</td><td>' +
                        esc(c.pa) + '</td><td>' + esc(c.b) + '</td><td>' + esc(c.pb) +
                        '</td><td>' + esc(c.packets) + '</td><td>' + esc(c.bytes) + '</td></tr>';
            });
            out.innerHTML = html + '</tbody></table>';
        }

        function clearFilter() {
            document.getElementById('source_ip').value = '';
            document.getElementById('destination_ip').value = '';
            document.getElementById('protocol').value = '';
            document.getElementById('filter_results').innerHTML =
                '<p>' + esc(REPORT_DATA.labels.no_filter) + '</p>';
        }

        function performQuery(name) {
            var count = REPORT_DATA.protocol_counts[name] || 0;
            document.getElementById('query_results').innerHTML =
                '<p><strong>' + esc(name) + ':</strong> ' + esc(count) + '</p>';
        }"""


def generate_html_report(stats, chart_paths, report_folder, lang="en",
                         source_file=None, display_filter=None):
    """Write the HTML report into *report_folder* and return its path."""
    html = HTMLReportBuilder(stats, chart_paths, lang, source_file, display_filter).render()
    report_path = os.path.join(report_folder, REPORT_HTML_FILENAME)
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(html)
    return report_path


def _esc(value):
    return escape(str(value))


def _port(value):
    return "" if value is None else value


class HTMLReportBuilder:
    """Builds the report HTML string from capture statistics."""

    def __init__(self, stats, chart_paths, lang="en", source_file=None, display_filter=None):
        self.stats = stats
        self.charts = chart_paths
        self.lang = lang
        self.tr = Translator(lang)
        self.source_file = source_file
        self.display_filter = display_filter

    def t(self, key, **kwargs):
        return _esc(self.tr(key, **kwargs))

    def render(self):
        return f"""<!DOCTYPE html>
<html lang="{_esc(self.lang)}">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>{self.t('report_title')}</title>{_HEAD_ASSETS}
    <style>{_STYLE}
    </style>
</head>
<body>
<div class="container">
    <h1>{self.t('report_title')}</h1>
    {self._meta()}
    {self._summary()}
    {self._charts()}
    {self._filters()}
    {self._queries()}
    {self._tables()}
</div>{_BODY_ASSETS}
    <script>
        var REPORT_DATA = {self._json_data()};
{_SCRIPT}
    </script>
</body>
</html>
"""

    # -- sections ----------------------------------------------------------- #

    def _meta(self):
        lines = [f"{self.t('generated_at')}: {_esc(datetime.now().strftime('%Y-%m-%d %H:%M:%S'))}"]
        if self.source_file:
            lines.append(f"{self.t('pcap_file')} {_esc(os.path.basename(self.source_file))}")
        if self.display_filter:
            lines.append(f"{self.t('display_filter')}: <code>{_esc(self.display_filter)}</code>")
        return '<p class="meta">' + "<br>".join(lines) + "</p>"

    def _summary(self):
        s = self.stats
        cards = [
            ("total_packets", f"{s.total_packets:,}"),
            ("total_bytes", f"{s.total_bytes:,}"),
            ("duration", f"{s.duration:.2f} s"),
            ("avg_packet_size", f"{s.average_packet_size:.1f} B"),
            ("unique_src_ips", s.unique_src_ips),
            ("unique_dst_ips", s.unique_dst_ips),
            ("conversations", len(s.conversations)),
            ("packets_per_second", f"{s.packets_per_second:.1f}"),
        ]
        cols = "".join(
            f'<div class="col-6 col-md-3"><div class="panel card-stat">'
            f'<div class="value">{_esc(value)}</div>'
            f'<div class="label">{self.t(key)}</div></div></div>'
            for key, value in cards
        )
        return f'<h2>{self.t("report_summary")}</h2><div class="row g-3">{cols}</div>'

    def _charts(self):
        parts = [f"<h2>{self.t('charts')}</h2>"]
        for key, (title_key, _) in CHARTS.items():
            filename = self.charts.get(key)
            if not filename:
                continue
            parts.append(
                f'<div class="chart panel"><h3>{self.t(title_key)}</h3>'
                f'<img src="{_esc(filename)}" alt="{self.t(title_key)}" class="img-fluid"></div>'
            )
        return "\n    ".join(parts)

    def _filters(self):
        options = "".join(
            f'<option value="{_esc(p)}">{_esc(p)}</option>' for p in self.stats.protocol_counts
        )
        return f"""<h2>{self.t('filters')}</h2>
    <div class="panel row g-2 align-items-end">
        <div class="col-md-3"><label class="form-label" for="source_ip">{self.t('source_ip')}</label>
            <input class="form-control" type="text" id="source_ip" placeholder="192.168.1.1"></div>
        <div class="col-md-3"><label class="form-label" for="destination_ip">{self.t('destination_ip')}</label>
            <input class="form-control" type="text" id="destination_ip" placeholder="10.0.0.5"></div>
        <div class="col-md-2"><label class="form-label" for="protocol">{self.t('protocol')}</label>
            <select class="form-select" id="protocol"><option value="">{self.t('all')}</option>{options}</select></div>
        <div class="col-md-4">
            <button class="btn btn-primary" onclick="applyFilter()">{self.t('apply_filter')}</button>
            <button class="btn btn-secondary" onclick="clearFilter()">{self.t('clear_filter')}</button>
        </div>
    </div>
    <h3>{self.t('filter_results')}</h3>
    <div id="filter_results"><p>{self.t('no_filter_applied')}</p></div>"""

    def _queries(self):
        names = sorted(set(self.stats.app_protocol_counts) | {"HTTP", "DNS", "SMTP", "TLS"})
        buttons = "".join(
            f'<button class="btn btn-outline-primary me-2 mb-2" '
            f'onclick="performQuery(&quot;{_esc(n)}&quot;)">{self.t("count_packets", name=n)}</button>'
            for n in names
        )
        return f"""<h2>{self.t('queries')}</h2>
    <div class="panel">{buttons}</div>
    <div id="query_results"><p>{self.t('no_query')}</p></div>"""

    def _tables(self):
        s = self.stats
        n = TOP_N_ENTRIES
        tr = self.tr
        parts = [f"<h2>{self.t('detailed_tables')}</h2>"]
        parts.append(self._table(
            tr("protocol_distribution"), [tr("protocol"), tr("packets"), tr("bytes"), "%"],
            [(u.name, u.packets, u.bytes, f"{u.percent:.1f}") for u in s.protocol_usage()]))
        parts.append(self._table(
            tr("application_protocols"), [tr("protocol"), tr("packets"), tr("bytes"), "%"],
            [(u.name, u.packets, u.bytes, f"{u.percent:.1f}") for u in s.app_protocol_usage()]))
        parts.append(self._table(tr("top_source_ips"), [tr("source_ip"), tr("packets")],
                                 s.top_sources(n)))
        parts.append(self._table(tr("top_destination_ips"), [tr("destination_ip"), tr("packets")],
                                 s.top_destinations(n)))
        parts.append(self._table(tr("source_ports"), [tr("source_port"), tr("packets")],
                                 s.top_source_ports(n)))
        parts.append(self._table(tr("destination_ports"), [tr("destination_port"), tr("packets")],
                                 s.top_destination_ports(n)))
        parts.append(self._table(
            tr("top_conversations"),
            [tr("protocol"), tr("address_a"), tr("port_a"), tr("address_b"), tr("port_b"),
             tr("packets"), tr("bytes")],
            [(c.protocol, c.addr_a, _port(c.port_a), c.addr_b, _port(c.port_b), c.packets, c.bytes)
             for c in s.conversations[:REPORT_MAX_CONVERSATIONS]]))
        parts.append(self._table(
            tr("endpoints"),
            [tr("address"), tr("packets"), tr("bytes"), tr("packets_sent"), tr("packets_received")],
            [(e.address, e.packets, e.bytes, e.packets_sent, e.packets_received)
             for e in s.endpoints[:REPORT_MAX_CONVERSATIONS]]))
        return "\n    ".join(parts)

    @staticmethod
    def _table(heading, headers, rows):
        head = "".join(f"<th>{_esc(h)}</th>" for h in headers)
        body = "\n".join(
            "<tr>" + "".join(f"<td>{_esc(cell)}</td>" for cell in row) + "</tr>" for row in rows
        )
        return f"""<div class="panel"><h3>{_esc(heading)}</h3>
        <table class="table table-striped datatable">
            <thead><tr>{head}</tr></thead>
            <tbody>{body}</tbody>
        </table></div>"""

    def _json_data(self):
        s = self.stats
        tr = self.tr
        data = {
            "total_packets": s.total_packets,
            "protocol_counts": {**dict(s.protocol_counts), **dict(s.app_protocol_counts)},
            "conversations": [
                {"proto": c.protocol, "a": c.addr_a, "pa": _port(c.port_a), "b": c.addr_b,
                 "pb": _port(c.port_b), "packets": c.packets, "bytes": c.bytes}
                for c in s.conversations[:REPORT_MAX_CONVERSATIONS]
            ],
            "labels": {
                "no_matches": tr("no_matches"),
                "matches": tr("matching_conversations"),
                "no_filter": tr("no_filter_applied"),
                "columns": [tr("protocol"), tr("address_a"), tr("port_a"), tr("address_b"),
                            tr("port_b"), tr("packets"), tr("bytes")],
            },
        }
        # Prevent a "</script>" inside packet data from closing the script tag.
        return json.dumps(data).replace("</", "<\\/")
