"""HTML report generation for PCAP analysis results."""

import json
import os
from html import escape as _html_escape

from pcap_report.config import REPORT_HTML_FILENAME


def generate_html_report(statistics, chart_paths, report_folder, lang="en"):
    """Build the complete HTML report file.

    Parameters
    ----------
    statistics : dict
        Output of :func:`PCAPAnalyzer.analyze_packets`.
    chart_paths : dict
        Mapping of chart key to relative filename.
    report_folder : str
        Directory where the HTML file will be written.
    lang : str
        Language code for embedded UI labels.

    Returns
    -------
    str
        Absolute path of the generated HTML file.
    """
    gen = _HTMLReportGenerator(statistics, chart_paths, lang)
    report_path = os.path.join(report_folder, REPORT_HTML_FILENAME)

    with open(report_path, "w", encoding="utf-8") as f:
        f.write(gen.render())

    return report_path


# --------------------------------------------------------------------------- #
#  HTML generation
# --------------------------------------------------------------------------- #

class _HTMLReportGenerator:
    """Internal class that builds the HTML report string."""

    def __init__(self, statistics, chart_paths, lang):
        self.stats = statistics
        self.charts = chart_paths
        self.lang = lang

        # Lazy-import translations to avoid circular imports at module level
        from pcap_report.i18n import TRANSLATIONS
        self._t = TRANSLATIONS.get(lang, TRANSLATIONS["en"])

    # -- helpers ------------------------------------------------------------ #

    def _tr(self, key):
        return self._t.get(key, f"[{key}]")

    @staticmethod
    def _esc(value):
        return _html_escape(str(value))

    # -- public API --------------------------------------------------------- #

    def render(self):
        return "\n".join([
            self._head(),
            self._body(),
            self._scripts(),
            self._foot(),
        ])

    # -- sections ----------------------------------------------------------- #

    def _head(self):
        return f"""<!DOCTYPE html>
<html lang="{self.lang}">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>{self._esc(self._tr('report_title'))}</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css"
          rel="stylesheet">
    <link rel="stylesheet" type="text/css"
          href="https://cdn.datatables.net/1.13.5/css/dataTables.bootstrap5.min.css">
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background-color: #f0f2f5; }}
        h1 {{ text-align: center; color: #2c3e50; }}
        h2 {{ color: #34495e; }}
        h3 {{ color: #34495e; }}
        table {{ border-collapse: collapse; width: 100%; margin-bottom: 20px; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #2980b9; color: white; }}
        tr:nth-child(even) {{ background-color: #ecf0f1; }}
        .chart {{ text-align: center; margin-bottom: 40px; }}
        .filter-section {{
            background-color: #ecf0f1; padding: 15px;
            border-radius: 5px; margin-bottom: 20px;
        }}
        .filter-section input, .filter-section select {{ margin-right: 10px; padding: 5px; }}
        .filter-section button {{
            padding: 5px 10px; background-color: #2980b9; color: white;
            border: none; border-radius: 3px; cursor: pointer; margin-right: 5px;
        }}
        .filter-section button:hover {{ background-color: #3498db; }}
        .summary-box {{
            background-color: #3498db; color: white; padding: 20px;
            border-radius: 10px; margin-bottom: 30px;
        }}
        .summary-box p {{ font-size: 1.1em; }}
    </style>
</head>"""

    def _body(self):
        parts = ["<body>", '<div class="container">', self._title_section(),
                 self._summary_section(), self._charts_section(),
                 self._filters_section(), self._queries_section(),
                 self._tables_section()]
        return "\n".join(parts)

    def _title_section(self):
        return f"<h1>{self._esc(self._tr('report_title'))}</h1>"

    def _summary_section(self):
        s = self.stats
        lines = [
            '<div class="summary-box">',
            f'  <h2>{self._esc(self._tr("report_summary"))}</h2>',
            f'  <p><strong>{self._esc(self._tr("total_packets"))}:</strong> {s["total_packets"]}</p>',
            f'  <p><strong>Unique Source IPs:</strong> {len(s["top_talkers_src"])}</p>',
            f'  <p><strong>Unique Destination IPs:</strong> {len(s["top_talkers_dst"])}</p>',
            f'  <p><strong>Unique Source Ports:</strong> {len(s["top_source_ports"])}</p>',
            f'  <p><strong>Unique Destination Ports:</strong> {len(s["top_destination_ports"])}</p>',
            "</div>",
        ]
        return "\n    ".join(lines)

    def _charts_section(self):
        sections = []
        sections.append(f"<h2>{self._esc(self._tr('protocol_distribution'))}</h2>")
        sections.append(self._chart_img("protocol_distribution", "Protocol Distribution"))

        sections.append(f"<h2>{self._esc(self._tr('top_talkers'))}</h2>")
        sections.append(f"<h3>Top Source IPs</h3>")
        sections.append(self._chart_img("top_source_ips", "Top Source IPs"))
        sections.append(f"<h3>Top Destination IPs</h3>")
        sections.append(self._chart_img("top_destination_ips", "Top Destination IPs"))

        sections.append(f"<h2>{self._esc(self._tr('source_ports'))}</h2>")
        sections.append(self._chart_img("top_source_ports", "Top Source Ports"))

        sections.append(f"<h2>{self._esc(self._tr('destination_ports'))}</h2>")
        sections.append(self._chart_img("top_destination_ports", "Top Destination Ports"))

        sections.append(f"<h2>{self._esc(self._tr('top_conversations'))}</h2>")
        sections.append(self._chart_img("top_conversations", "Top Conversations"))

        return "\n    ".join(sections)

    def _chart_img(self, key, alt):
        filename = self.charts.get(key, "")
        return (
            f'<div class="chart">'
            f'<img src="{self._esc(filename)}" alt="{self._esc(alt)}" class="img-fluid">'
            f'</div>'
        )

    def _filters_section(self):
        t = self._t
        return f"""<h2>{self._esc(t['filters'])}</h2>
        <div class="filter-section">
            <label for="source_ip">{self._esc(t['source_ip'])}:</label>
            <input type="text" id="source_ip" name="source_ip" placeholder="e.g., 192.168.1.1">
            <label for="destination_ip">{self._esc(t['destination_ip'])}:</label>
            <input type="text" id="destination_ip" name="destination_ip" placeholder="e.g., 10.0.0.5">
            <label for="protocol">{self._esc(t['protocol'])}:</label>
            <select id="protocol" name="protocol">
                <option value="">All</option>
                <option value="TCP">TCP</option>
                <option value="UDP">UDP</option>
                <option value="ICMP">ICMP</option>
                <option value="Other">Other</option>
            </select>
            <button onclick="applyFilter()">{self._esc(t['apply_filter'])}</button>
            <button onclick="clearFilter()">{self._esc(t['clear_filter'])}</button>
        </div>
        <h2>{self._esc(t['filter_results'])}</h2>
        <div id="filter_results"><p>No filter applied.</p></div>"""

    def _queries_section(self):
        t = self._t
        return f"""<h2>{self._esc(t['queries'])}</h2>
        <div class="filter-section">
            <button onclick="performQuery('HTTP')">Count HTTP Requests</button>
            <button onclick="performQuery('DNS')">Count DNS Queries</button>
            <button onclick="performQuery('SMTP')">Count SMTP Sessions</button>
        </div>
        <div id="query_results"><p>No query performed.</p></div>"""

    def _tables_section(self):
        parts = ["<h2>Detailed Tables</h2>"]

        parts.append(self._simple_table(
            "top_source_ips_table", "Top Source IPs",
            ["Source IP", "Packet Count"],
            [(ip, cnt) for ip, cnt in self.stats["top_talkers_src"]],
        ))
        parts.append(self._simple_table(
            "top_destination_ips_table", "Top Destination IPs",
            ["Destination IP", "Packet Count"],
            [(ip, cnt) for ip, cnt in self.stats["top_talkers_dst"]],
        ))
        parts.append(self._simple_table(
            "top_source_ports_table", "Top Source Ports",
            ["Source Port", "Packet Count"],
            [(p, cnt) for p, cnt in self.stats["top_source_ports"]],
        ))
        parts.append(self._simple_table(
            "top_destination_ports_table", "Top Destination Ports",
            ["Destination Port", "Packet Count"],
            [(p, cnt) for p, cnt in self.stats["top_destination_ports"]],
        ))
        parts.append(self._conversation_table())

        return "\n    ".join(parts)

    def _simple_table(self, table_id, heading, headers, rows):
        """Generic two-column table."""
        cols = "".join(f"<th>{self._esc(h)}</th>" for h in headers)
        body = "\n".join(
            f"<tr><td>{self._esc(r[0])}</td><td>{self._esc(r[1])}</td></tr>"
            for r in rows
        )
        return f"""<h3>{self._esc(heading)}</h3>
        <table id="{table_id}" class="table table-striped">
            <thead><tr>{cols}</tr></thead>
            <tbody>{body}</tbody>
        </table>"""

    def _conversation_table(self):
        headers = ["Source IP", "Destination IP", "Protocol",
                    "Source Port", "Destination Port", "Packet Count"]
        cols = "".join(f"<th>{h}</th>" for h in headers)

        rows = ""
        for (src, dst, proto, sport, dport), cnt in self.stats["top_conversations"]:
            rows += (
                f"<tr><td>{self._esc(src)}</td><td>{self._esc(dst)}</td>"
                f"<td>{self._esc(proto)}</td><td>{self._esc(sport)}</td>"
                f"<td>{self._esc(dport)}</td><td>{self._esc(cnt)}</td></tr>"
            )

        return f"""<h3>Top Conversations</h3>
        <table id="top_conversations_table" class="table table-striped">
            <thead><tr>{cols}</tr></thead>
            <tbody>{rows}</tbody>
        </table>"""

    # -- JavaScript --------------------------------------------------------- #

    def _scripts(self):
        stats_json = json.dumps(self._build_json_data())
        return f"""    <script src="https://code.jquery.com/jquery-3.7.0.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script src="https://cdn.datatables.net/1.13.5/js/jquery.dataTables.min.js"></script>
    <script src="https://cdn.datatables.net/1.13.5/js/dataTables.bootstrap5.min.js"></script>
    <script>
        var REPORT_DATA = {stats_json};

        $(document).ready(function() {{
            $('#top_source_ips_table').DataTable({{ paging: true, searching: true, info: false }});
            $('#top_destination_ips_table').DataTable({{ paging: true, searching: true, info: false }});
            $('#top_source_ports_table').DataTable({{ paging: true, searching: true, info: false }});
            $('#top_destination_ports_table').DataTable({{ paging: true, searching: true, info: false }});
            $('#top_conversations_table').DataTable({{ paging: true, searching: true, info: false }});
        }});

        function applyFilter() {{
            var srcIp = document.getElementById('source_ip').value.trim();
            var dstIp = document.getElementById('destination_ip').value.trim();
            var proto = document.getElementById('protocol').value.trim();

            var allConversations = REPORT_DATA.conversations;
            var filtered = allConversations.filter(function(c) {{
                if (srcIp && c.src.indexOf(srcIp) === -1) return false;
                if (dstIp && c.dst.indexOf(dstIp) === -1) return false;
                if (proto && c.proto !== proto) return false;
                return true;
            }});

            if (filtered.length === 0) {{
                document.getElementById('filter_results').innerHTML =
                    '<p>No matching packets found.</p>';
                return;
            }}

            var html = '<p><strong>' + filtered.length + ' matching conversation(s) found.</strong></p>';
            html += '<table class="table table-striped"><thead><tr>' +
                    '<th>Source IP</th><th>Destination IP</th>' +
                    '<th>Protocol</th><th>Src Port</th><th>Dst Port</th>' +
                    '<th>Packets</th></tr></thead><tbody>';
            filtered.forEach(function(c) {{
                html += '<tr><td>' + c.src + '</td><td>' + c.dst + '</td>' +
                        '<td>' + c.proto + '</td><td>' + c.sport + '</td>' +
                        '<td>' + c.dport + '</td><td>' + c.count + '</td></tr>';
            }});
            html += '</tbody></table>';
            document.getElementById('filter_results').innerHTML = html;
        }}

        function clearFilter() {{
            document.getElementById('source_ip').value = '';
            document.getElementById('destination_ip').value = '';
            document.getElementById('protocol').value = '';
            document.getElementById('filter_results').innerHTML = '<p>No filter applied.</p>';
        }}

        function performQuery(queryType) {{
            var packets = REPORT_DATA.all_packets;
            var count = packets.filter(function(p) {{
                return p.proto === queryType;
            }}).length;

            var label = queryType + ' Packets';
            document.getElementById('query_results').innerHTML =
                '<p><strong>' + label + ':</strong> ' + count + '</p>';
        }}
    </script>"""

    def _build_json_data(self):
        """Build JSON-serialisable data for client-side filtering/queries."""
        conversations = []
        for (src, dst, proto, sport, dport), count in self.stats["top_conversations"]:
            conversations.append({
                "src": src, "dst": dst, "proto": proto,
                "sport": sport, "dport": dport, "count": count,
            })

        all_packets = []
        proto_dist = self.stats.get("protocol_distribution", {})
        for proto, count in proto_dist.items():
            for _ in range(count):
                all_packets.append({"proto": proto})

        return {
            "conversations": conversations,
            "protocol_distribution": dict(proto_dist),
            "all_packets": all_packets,
            "total_packets": self.stats["total_packets"],
        }

    @staticmethod
    def _foot():
        return "</div></body></html>"
