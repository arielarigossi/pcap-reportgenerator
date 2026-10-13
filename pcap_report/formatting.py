"""Human-friendly formatting helpers."""

from datetime import datetime


def fmt_bytes(value):
    size = float(value)
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024 or unit == "GB":
            return f"{int(size)} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"


def fmt_count(value):
    return f"{value:,}"


def fmt_seconds(value):
    return f"{value:.6f}"


def fmt_duration(seconds):
    if seconds < 60:
        return f"{seconds:.3f} s"
    minutes, secs = divmod(seconds, 60)
    hours, minutes = divmod(int(minutes), 60)
    return f"{hours:d}:{minutes:02d}:{secs:06.3f}"


def fmt_rate_bits(bits_per_second):
    value = float(bits_per_second)
    for unit in ("bit/s", "kbit/s", "Mbit/s", "Gbit/s"):
        if value < 1000 or unit == "Gbit/s":
            return f"{value:.1f} {unit}"
        value /= 1000
    return f"{value:.1f} Gbit/s"


def fmt_timestamp(epoch):
    if not epoch:
        return ""
    return datetime.fromtimestamp(epoch).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
