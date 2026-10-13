"""A small Wireshark-like display filter language.

Examples::

    tcp
    ip.src == 10.0.0.1 and tcp.port == 443
    ip.addr == 192.168.0.0/16 && !dns
    len > 1000 or (udp and not port 53)
    info contains "example.com"
    proto matches "^(HTTP|TLS)$"

Grammar::

    expr       := or_expr
    or_expr    := and_expr (("or" | "||") and_expr)*
    and_expr   := not_expr (("and" | "&&") not_expr)*
    not_expr   := ("not" | "!") not_expr | primary
    primary    := "(" expr ")" | FIELD [OP VALUE | VALUE] | PROTOCOL

``FIELD VALUE`` without an operator is shorthand for ``FIELD == VALUE``
(e.g. ``port 53``, ``host 10.0.0.1``). A bare word that is not a field
name matches packets whose protocol (transport or application) has that
name, e.g. ``dns`` or ``tls``.

Multi-valued fields such as ``ip.addr`` or ``port`` match when *any* of
their values match; ``!=`` matches only when *none* of them are equal.
"""

import ipaddress
import re

__all__ = ["FilterSyntaxError", "compile_filter", "FIELDS", "OPERATORS"]


class FilterSyntaxError(ValueError):
    """Raised when a display filter cannot be parsed."""

    def __init__(self, message, position=None):
        super().__init__(message)
        self.position = position


# --------------------------------------------------------------------------- #
#  Fields
# --------------------------------------------------------------------------- #

ADDRESS, NUMBER, TEXT = "address", "number", "text"


def _ports_if(protocol):
    return lambda r: r.ports if r.protocol == protocol else ()


def _maybe(value):
    return () if value is None else (value,)


# name -> (kind, getter returning an iterable of values)
FIELDS = {
    "ip.src": (ADDRESS, lambda r: (r.src,)),
    "ip.dst": (ADDRESS, lambda r: (r.dst,)),
    "ip.addr": (ADDRESS, lambda r: (r.src, r.dst)),
    "eth.src": (ADDRESS, lambda r: _maybe(r.src_mac or None)),
    "eth.dst": (ADDRESS, lambda r: _maybe(r.dst_mac or None)),
    "eth.addr": (ADDRESS, lambda r: tuple(m for m in (r.src_mac, r.dst_mac) if m)),
    "port": (NUMBER, lambda r: r.ports),
    "srcport": (NUMBER, lambda r: _maybe(r.sport)),
    "dstport": (NUMBER, lambda r: _maybe(r.dport)),
    "tcp.port": (NUMBER, _ports_if("TCP")),
    "udp.port": (NUMBER, _ports_if("UDP")),
    "tcp.srcport": (NUMBER, lambda r: _maybe(r.sport) if r.protocol == "TCP" else ()),
    "tcp.dstport": (NUMBER, lambda r: _maybe(r.dport) if r.protocol == "TCP" else ()),
    "udp.srcport": (NUMBER, lambda r: _maybe(r.sport) if r.protocol == "UDP" else ()),
    "udp.dstport": (NUMBER, lambda r: _maybe(r.dport) if r.protocol == "UDP" else ()),
    "tcp.flags": (TEXT, lambda r: _maybe(r.tcp_flags or None)),
    "proto": (TEXT, lambda r: tuple(p for p in (r.protocol, r.app_protocol) if p)),
    "frame.len": (NUMBER, lambda r: (r.length,)),
    "frame.number": (NUMBER, lambda r: (r.number,)),
    "frame.time_relative": (NUMBER, lambda r: (r.relative_time,)),
    "ip.ttl": (NUMBER, lambda r: _maybe(r.ttl)),
    "ip.version": (NUMBER, lambda r: _maybe(r.ip_version)),
    "info": (TEXT, lambda r: (r.info,)),
}

FIELD_ALIASES = {
    "src": "ip.src",
    "dst": "ip.dst",
    "addr": "ip.addr",
    "host": "ip.addr",
    "ipv6.src": "ip.src",
    "ipv6.dst": "ip.dst",
    "ipv6.addr": "ip.addr",
    "sport": "srcport",
    "dport": "dstport",
    "protocol": "proto",
    "len": "frame.len",
    "length": "frame.len",
    "frame.no": "frame.number",
    "no": "frame.number",
    "time": "frame.time_relative",
    "ttl": "ip.ttl",
}

# Bare words with a special meaning that is not a plain protocol name match.
SPECIAL_WORDS = {
    "ip": lambda r: r.ip_version == 4,
    "ipv4": lambda r: r.ip_version == 4,
    "ipv6": lambda r: r.ip_version == 6,
    "eth": lambda r: bool(r.src_mac),
}


# --------------------------------------------------------------------------- #
#  Operators
# --------------------------------------------------------------------------- #

OPERATORS = {
    "==": "==", "eq": "==",
    "!=": "!=", "ne": "!=",
    ">": ">", "gt": ">",
    "<": "<", "lt": "<",
    ">=": ">=", "ge": ">=",
    "<=": "<=", "le": "<=",
    "contains": "contains",
    "matches": "matches", "~": "matches",
}

_ORDERING = {
    ">": lambda a, b: a > b,
    "<": lambda a, b: a < b,
    ">=": lambda a, b: a >= b,
    "<=": lambda a, b: a <= b,
}


# --------------------------------------------------------------------------- #
#  Tokenizer
# --------------------------------------------------------------------------- #

_TOKEN_RE = re.compile(
    r"""
    \s*(?:
        (?P<lparen>\()
      | (?P<rparen>\))
      | (?P<op>==|!=|>=|<=|>|<|~)
      | (?P<and>&&)
      | (?P<or>\|\|)
      | (?P<not>!)
      | "(?P<string>(?:[^"\\]|\\.)*)"
      | (?P<word>[^\s()!=<>&|"~]+)
    )""",
    re.VERBOSE,
)


class _Token:
    __slots__ = ("kind", "value", "pos")

    def __init__(self, kind, value, pos):
        self.kind, self.value, self.pos = kind, value, pos

    def __repr__(self):
        return f"_Token({self.kind!r}, {self.value!r})"


def _tokenize(text):
    tokens = []
    pos = 0
    text = text.rstrip()
    while pos < len(text):
        match = _TOKEN_RE.match(text, pos)
        if not match or match.end() == pos:
            raise FilterSyntaxError(f"Unexpected character {text[pos]!r}", pos)
        kind = match.lastgroup
        value = match.group(kind)
        start = match.start(kind)
        if kind == "string":
            value = re.sub(r"\\(.)", r"\1", value)
        elif kind == "word":
            lowered = value.lower()
            if lowered in ("and", "or", "not"):
                kind = lowered
            elif lowered in OPERATORS:
                kind = "op"
        tokens.append(_Token(kind, value, start))
        pos = match.end()
    return tokens


# --------------------------------------------------------------------------- #
#  Parser
# --------------------------------------------------------------------------- #

class _Parser:
    def __init__(self, text):
        self.tokens = _tokenize(text)
        self.index = 0

    def _peek(self):
        return self.tokens[self.index] if self.index < len(self.tokens) else None

    def _next(self):
        tok = self._peek()
        if tok is None:
            raise FilterSyntaxError("Unexpected end of filter")
        self.index += 1
        return tok

    def parse(self):
        predicate = self._or()
        tok = self._peek()
        if tok is not None:
            raise FilterSyntaxError(f"Unexpected {tok.value!r}", tok.pos)
        return predicate

    def _or(self):
        parts = [self._and()]
        while self._peek() is not None and self._peek().kind == "or":
            self._next()
            parts.append(self._and())
        if len(parts) == 1:
            return parts[0]
        return lambda r: any(p(r) for p in parts)

    def _and(self):
        parts = [self._not()]
        while self._peek() is not None and self._peek().kind == "and":
            self._next()
            parts.append(self._not())
        if len(parts) == 1:
            return parts[0]
        return lambda r: all(p(r) for p in parts)

    def _not(self):
        tok = self._peek()
        if tok is not None and tok.kind == "not":
            self._next()
            inner = self._not()
            return lambda r: not inner(r)
        return self._primary()

    def _primary(self):
        tok = self._next()
        if tok.kind == "lparen":
            inner = self._or()
            closing = self._next()
            if closing.kind != "rparen":
                raise FilterSyntaxError("Expected ')'", closing.pos)
            return inner
        if tok.kind != "word":
            raise FilterSyntaxError(f"Unexpected {tok.value!r}", tok.pos)

        name = tok.value.lower()
        field = FIELD_ALIASES.get(name, name)
        if field not in FIELDS:
            return _bare_word(name)

        kind, getter = FIELDS[field]
        nxt = self._peek()
        if nxt is not None and nxt.kind == "op":
            op = OPERATORS[self._next().value.lower()]
            value_tok = self._next()
        elif nxt is not None and nxt.kind in ("word", "string"):
            op, value_tok = "==", self._next()  # "port 53" shorthand
        else:
            return lambda r: bool(getter(r))  # field presence test
        if value_tok.kind not in ("word", "string"):
            raise FilterSyntaxError(f"Expected a value after {op!r}", value_tok.pos)
        return _comparison(field, kind, getter, op, value_tok)


def _bare_word(name):
    if name in SPECIAL_WORDS:
        return SPECIAL_WORDS[name]
    if name in ("https", "ssl"):
        name = "tls"
    return lambda r: r.protocol.lower() == name or r.app_protocol.lower() == name


def _comparison(field, kind, getter, op, value_tok):
    raw = value_tok.value

    if op == "contains":
        needle = raw.lower()
        return lambda r: any(needle in str(v).lower() for v in getter(r))

    if op == "matches":
        try:
            regex = re.compile(raw, re.IGNORECASE)
        except re.error as exc:
            raise FilterSyntaxError(f"Invalid regular expression: {exc}", value_tok.pos)
        return lambda r: any(regex.search(str(v)) for v in getter(r))

    if kind == NUMBER:
        value = _parse_number(raw, value_tok.pos)
        test = _ORDERING.get(op, lambda a, b: a == b)
    elif kind == ADDRESS:
        value, test = _address_matcher(raw, field, op, value_tok.pos)
    else:
        if op in _ORDERING:
            raise FilterSyntaxError(f"Operator {op!r} is not valid for {field}", value_tok.pos)
        value = raw.lower()
        if field == "proto" and value in ("https", "ssl"):
            value = "tls"
        test = _text_equals

    if op == "!=":
        return lambda r: not any(test(v, value) for v in getter(r))
    return lambda r: any(test(v, value) for v in getter(r))


def _text_equals(actual, expected):
    return str(actual).lower() == expected


def _parse_number(raw, pos):
    try:
        return int(raw, 0)
    except ValueError:
        try:
            return float(raw)
        except ValueError:
            raise FilterSyntaxError(f"Expected a number, got {raw!r}", pos)


def _address_matcher(raw, field, op, pos):
    if op in _ORDERING:
        raise FilterSyntaxError(f"Operator {op!r} is not valid for {field}", pos)
    if "/" in raw:
        try:
            network = ipaddress.ip_network(raw, strict=False)
        except ValueError:
            raise FilterSyntaxError(f"Invalid network {raw!r}", pos)

        def in_network(address, net):
            try:
                return ipaddress.ip_address(address) in net
            except ValueError:
                return False
        return network, in_network
    return raw.lower(), lambda a, b: str(a).lower() == b


# --------------------------------------------------------------------------- #
#  Public API
# --------------------------------------------------------------------------- #

def compile_filter(text):
    """Compile *text* into a predicate ``record -> bool``.

    Returns ``None`` for an empty filter (meaning "match everything").
    Raises :class:`FilterSyntaxError` for invalid input.
    """
    if text is None or not text.strip():
        return None
    return _Parser(text).parse()


def apply_filter(records, text):
    """Return the records matching the display filter *text*."""
    predicate = compile_filter(text)
    if predicate is None:
        return list(records)
    return [r for r in records if predicate(r)]
