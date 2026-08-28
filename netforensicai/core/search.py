"""Content search across a capture: find packets whose bytes contain a
string, a regex, or a hex sequence, and show the match in context.

This is the one thing an analyst does constantly that the event pipeline
cannot do at all. Parsing normalizes packets into Events with a fixed set
of fields; it deliberately does not keep payload, because storing the
bytes of every packet in a case would defeat the streaming design. So
"where does the string `flag{` appear in this capture" - the first
question in most CTF network challenges, and a routine one in real
investigations chasing a token, a filename, or a hostname - had no answer.

Search therefore goes back to the CAPTURE FILE rather than to the event
store. That has three consequences worth understanding:

  - It needs tshark. There is no scapy fallback: the whole point is
    matching against raw frame bytes with Wireshark's own filter engine,
    and reimplementing that in Python would be both slower and subtly
    different from what the analyst gets in the GUI.
  - It is fast. Measured on a 1,000,000-packet / 132 MB capture, a
    content search completes in about six seconds - tshark reads the file
    linearly and never dissects more than it must.
  - Results are packet references, not Events. A hit names a frame
    number, which is exactly what `netforensic wireshark open` pivots on,
    so a search result leads straight to the packets in Wireshark.

Nothing here writes to the case. Searching is a read-only question asked
of evidence that stays hashed and untouched.
"""

import binascii
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from netforensicai.integrations import wireshark

logger = logging.getLogger(__name__)

TEXT = "text"
REGEX = "regex"
HEX = "hex"
SEARCH_MODES = (TEXT, REGEX, HEX)

DEFAULT_MAX_HITS = 200
DEFAULT_CONTEXT_BYTES = 48

# Fields fetched per hit. The payload fields are requested as hex so the
# match can be located and excerpted here rather than trusting tshark's
# text rendering, which drops non-printable bytes - exactly the bytes a
# CTF challenge tends to hide things in.
_FIELDS = (
    "frame.number",
    "frame.time_epoch",
    "ip.src",
    "ip.dst",
    "ipv6.src",
    "ipv6.dst",
    "tcp.srcport",
    "tcp.dstport",
    "udp.srcport",
    "udp.dstport",
    "tcp.stream",
    "udp.stream",
    "_ws.col.protocol",
    "_ws.col.info",
    "tcp.payload",
    "udp.payload",
    "data.data",
)


class SearchError(Exception):
    """Raised when a search cannot run: no tshark, or an unusable pattern."""


@dataclass
class SearchHit:
    frame_number: int
    timestamp: Optional[datetime]
    protocol: Optional[str]
    src: Optional[str]
    dst: Optional[str]
    stream: Optional[int]
    info: Optional[str]
    excerpt: Optional[str]
    matched: Optional[str]

    def to_dict(self):
        return {
            "frame_number": self.frame_number,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "protocol": self.protocol,
            "src": self.src,
            "dst": self.dst,
            "stream": self.stream,
            "info": self.info,
            "excerpt": self.excerpt,
            "matched": self.matched,
        }


@dataclass
class SearchResult:
    display_filter: str
    hits: list = field(default_factory=list)
    truncated: bool = False

    def to_dict(self):
        return {
            "display_filter": self.display_filter,
            "truncated": self.truncated,
            "hits": [hit.to_dict() for hit in self.hits],
        }


def _escape_filter_string(value):
    r"""Escape a Python string for a Wireshark double-quoted filter literal.

    Wireshark's filter parser processes backslash escapes inside double
    quotes, so a literal backslash or quote in the search term has to be
    doubled on the way in. Without this, searching for a Windows path or a
    quoted string would either fail to parse or silently match something
    else.
    """
    return value.replace("\\", "\\\\").replace('"', '\\"')


def _normalize_hex(value):
    """Accept 'aa:bb:cc', 'aabbcc', 'AA BB CC', or '\\xaa\\xbb' and return
    the colon-separated form Wireshark's `contains` operator expects."""
    cleaned = re.sub(r"(0x|\\x|[\s:_-])", "", value, flags=re.IGNORECASE)
    if not cleaned or len(cleaned) % 2 or not re.fullmatch(r"[0-9a-fA-F]+", cleaned):
        raise SearchError(f"'{value}' is not a valid hex byte sequence.")
    # Lower-cased so the same bytes always produce the same filter string,
    # whatever case they were pasted in - the filter is echoed back to the
    # analyst and recorded, and `4D5A` and `4d5a` are not two searches.
    cleaned = cleaned.lower()
    return ":".join(cleaned[i : i + 2] for i in range(0, len(cleaned), 2))


def build_display_filter(pattern, mode=TEXT, case_sensitive=False, scope="frame"):
    """Turn a search term into a Wireshark display filter.

    `contains` is a case-sensitive byte match; `matches` is a PCRE regex
    and is case-INsensitive by default. That asymmetry is why a
    case-insensitive text search is compiled to `matches` over an escaped
    regex rather than to `contains`: doing it any other way would mean
    lowercasing the evidence, which is not something a forensics tool
    should do to the bytes it is reporting on.
    """
    if mode not in SEARCH_MODES:
        raise SearchError(f"Unknown search mode '{mode}'. Choose one of: {', '.join(SEARCH_MODES)}.")
    if not pattern or not pattern.strip():
        raise SearchError("Search pattern is empty.")

    if mode == HEX:
        return f"{scope} contains {_normalize_hex(pattern)}"

    if mode == TEXT and case_sensitive:
        return f'{scope} contains "{_escape_filter_string(pattern)}"'

    expression = re.escape(pattern) if mode == TEXT else pattern
    if mode == REGEX:
        try:
            re.compile(expression)
        except re.error as e:
            # Caught here so the analyst gets "bad regex" rather than a
            # filter-syntax error from tshark that names a column number
            # in a string they never wrote.
            raise SearchError(f"Invalid regular expression: {e}") from e
    if mode == TEXT and not case_sensitive:
        # `matches` is case-insensitive already; the escape above makes the
        # term literal, so this stays a plain substring search.
        pass
    return f'{scope} matches "{_escape_filter_string(expression)}"'


def _hex_to_bytes(value):
    if not value:
        return b""
    cleaned = value.replace(":", "").strip()
    try:
        return binascii.unhexlify(cleaned)
    except (binascii.Error, ValueError):
        return b""


def _printable(raw):
    return "".join(chr(b) if 32 <= b < 127 else "." for b in raw)


def _excerpt(payload, pattern, mode, case_sensitive, context):
    """Return (excerpt, matched_text) showing where the pattern landed.

    Best-effort: the filter matched somewhere in the frame, but the match
    may be in a header rather than in the payload fields fetched here. In
    that case the payload is still shown - an excerpt that says "here is
    the data in the matching packet" is more useful than nothing, and the
    frame number is the authoritative answer either way.
    """
    if not payload:
        return None, None

    text = _printable(payload)
    index = -1
    matched = None

    if mode == HEX:
        try:
            needle = _hex_to_bytes(_normalize_hex(pattern))
            index = payload.find(needle)
            matched = needle.hex(":") if index >= 0 else None
        except SearchError:
            index = -1
    elif mode == REGEX:
        found = re.search(pattern, text, 0 if case_sensitive else re.IGNORECASE)
        if found:
            index, matched = found.start(), found.group(0)
    else:
        haystack = text if case_sensitive else text.lower()
        needle = pattern if case_sensitive else pattern.lower()
        index = haystack.find(needle)
        matched = text[index : index + len(pattern)] if index >= 0 else None

    if index < 0:
        return text[: context * 2], None

    start = max(0, index - context)
    end = min(len(text), index + len(matched or "") + context)
    prefix = "..." if start > 0 else ""
    suffix = "..." if end < len(text) else ""
    return f"{prefix}{text[start:end]}{suffix}", matched


def _first(layers, name):
    values = layers.get(name.replace(".", "_"))
    if not values:
        return None
    return values[0] if isinstance(values, list) else values


def _endpoint(layers, side):
    address = _first(layers, f"ip.{side}") or _first(layers, f"ipv6.{side}")
    port = _first(layers, f"tcp.{'srcport' if side == 'src' else 'dstport'}") or _first(
        layers, f"udp.{'srcport' if side == 'src' else 'dstport'}"
    )
    if address and port:
        return f"{address}:{port}"
    return address


def search_capture(
    pcap_path,
    pattern,
    mode=TEXT,
    case_sensitive=False,
    max_hits=DEFAULT_MAX_HITS,
    context=DEFAULT_CONTEXT_BYTES,
    display_filter=None,
):
    """Search a capture file's bytes and return a SearchResult.

    display_filter, when given, is ANDed with the content match, so a
    search can be narrowed to a host or protocol first - which on a large
    capture is the difference between reading the whole file and reading
    part of it.
    """
    if not wireshark.available():
        raise SearchError(
            "Content search needs tshark, which was not found. Install Wireshark, or set "
            "NETFORENSIC_TSHARK to its executable."
        )

    content_filter = build_display_filter(pattern, mode=mode, case_sensitive=case_sensitive)
    effective = f"({display_filter}) && ({content_filter})" if display_filter else content_filter

    valid, error = wireshark.validate_display_filter(effective)
    if not valid:
        raise SearchError(error)

    result = SearchResult(display_filter=effective)
    for layers in wireshark.iter_dissected_packets(pcap_path, _FIELDS, display_filter=effective):
        if len(result.hits) >= max_hits:
            # Stop reading rather than collecting and slicing: on a capture
            # where the term is everywhere, the remaining work is unbounded
            # and the analyst already has more than they can read.
            result.truncated = True
            break

        payload = b""
        for name in ("tcp.payload", "udp.payload", "data.data"):
            payload = _hex_to_bytes(_first(layers, name))
            if payload:
                break

        excerpt, matched = _excerpt(payload, pattern, mode, case_sensitive, context)

        epoch = _first(layers, "frame.time_epoch")
        try:
            timestamp = datetime.fromtimestamp(float(epoch), tz=timezone.utc) if epoch else None
        except (TypeError, ValueError, OverflowError, OSError):
            timestamp = None

        stream = _first(layers, "tcp.stream") or _first(layers, "udp.stream")
        try:
            stream = int(stream) if stream is not None else None
        except (TypeError, ValueError):
            stream = None

        result.hits.append(
            SearchHit(
                frame_number=int(_first(layers, "frame.number") or 0),
                timestamp=timestamp,
                protocol=_first(layers, "_ws.col.protocol"),
                src=_endpoint(layers, "src"),
                dst=_endpoint(layers, "dst"),
                stream=stream,
                info=_first(layers, "_ws.col.info"),
                excerpt=excerpt,
                matched=matched,
            )
        )

    return result
