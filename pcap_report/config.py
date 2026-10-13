"""Application configuration constants."""

REPORT_SUBFOLDER_PREFIX = "PCAP_Report"
TIMESTAMP_FORMAT = "%Y%m%d_%H%M%S"
REPORT_HTML_FILENAME = "pcap_analysis_report.html"
REPORT_CSV_FILENAME = "pcap_analysis_summary.csv"
SUPPORTED_EXTENSIONS = (".pcap", ".pcapng", ".cap")
TOP_N_ENTRIES = 10
PROGRESS_PACKET_INTERVAL = 1000

# Maximum number of time buckets used for the traffic timeline.
TIMELINE_MAX_BUCKETS = 200

# Maximum number of conversations embedded in the HTML report for
# client-side filtering (keeps the report size bounded).
REPORT_MAX_CONVERSATIONS = 500

DEFAULT_LANGUAGE = "en"

# Example display filters offered in the GUI filter bar.
FILTER_PRESETS = (
    "tcp",
    "udp",
    "dns",
    "http or tls",
    "icmp or icmpv6",
    "arp",
    "tcp.flags contains S",
    "len > 1000",
    "ip.addr == 192.168.0.0/16",
    "not (tcp or udp)",
)
