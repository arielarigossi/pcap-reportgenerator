"""Protocol name tables used to label packets."""

# IP protocol numbers -> names (IANA assigned numbers).
IP_PROTOCOLS = {
    1: "ICMP",
    2: "IGMP",
    4: "IPIP",
    6: "TCP",
    17: "UDP",
    41: "IPv6",
    47: "GRE",
    50: "ESP",
    51: "AH",
    58: "ICMPv6",
    89: "OSPF",
    103: "PIM",
    112: "VRRP",
    132: "SCTP",
}

# Well-known ports -> application protocol / service names.
WELL_KNOWN_PORTS = {
    20: "FTP-DATA",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    69: "TFTP",
    80: "HTTP",
    110: "POP3",
    123: "NTP",
    137: "NetBIOS",
    138: "NetBIOS",
    139: "NetBIOS",
    143: "IMAP",
    161: "SNMP",
    162: "SNMP",
    389: "LDAP",
    443: "TLS",
    445: "SMB",
    465: "SMTPS",
    514: "Syslog",
    587: "SMTP",
    636: "LDAPS",
    853: "DoT",
    993: "IMAPS",
    995: "POP3S",
    1194: "OpenVPN",
    1883: "MQTT",
    1900: "SSDP",
    3306: "MySQL",
    3389: "RDP",
    5060: "SIP",
    5353: "mDNS",
    5355: "LLMNR",
    5432: "PostgreSQL",
    6379: "Redis",
    8080: "HTTP",
    8443: "TLS",
    27017: "MongoDB",
}

HTTP_REQUEST_PREFIXES = (
    b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ", b"OPTIONS ",
    b"PATCH ", b"CONNECT ", b"TRACE ",
)
HTTP_RESPONSE_PREFIX = b"HTTP/1."


def ip_protocol_name(number):
    return IP_PROTOCOLS.get(number, f"IP-{number}")


def service_name(port):
    """Service name for a port number, or ``""`` if unknown."""
    return WELL_KNOWN_PORTS.get(port, "")


def guess_app_protocol(sport, dport):
    """Guess the application protocol from a source/destination port pair.

    The lower-numbered well-known port wins, since ephemeral client ports
    are usually high numbers.
    """
    candidates = sorted(p for p in (sport, dport) if p is not None)
    for port in candidates:
        name = WELL_KNOWN_PORTS.get(port)
        if name:
            return name
    return ""
