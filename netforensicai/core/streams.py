"""Stream reassembly: list the conversations in a capture, and read one
back as the two sides actually exchanged it.

Individual packets are the wrong unit for a lot of analysis. A credential,
a command-and-control exchange, a CTF flag handed over in an HTTP response
- none of them live in "a packet", they live in a conversation that was
split across dozens of them by the network. Wireshark's "Follow Stream" is
the answer, and this exposes it without leaving the platform.

Two operations:

  list_streams()   which conversations exist, ranked by volume, so an
                   analyst can find the interesting one without guessing
                   an index.
  follow_stream()  one conversation reassembled into ordered turns, each
                   tagged with which side sent it.

Both need tshark. Reassembly is genuinely hard - retransmissions,
out-of-order segments, overlapping data - and Wireshark already does it
correctly; a hand-rolled version here would be a subtly wrong copy of
something the analyst can check against the GUI.

Streams are addressed by tshark's own stream index, which is also what
`netforensic search` reports on every hit. So a search result leads
directly to the conversation it appeared in.
"""

import logging
import re
from dataclasses import dataclass, field
from typing import Optional

from netforensicai.integrations import wireshark

logger = logging.getLogger(__name__)

TCP = "tcp"
UDP = "udp"
STREAM_PROTOCOLS = (TCP, UDP)

DEFAULT_STREAM_LIMIT = 25
# Reassembled conversations can be enormous - a file transfer is one
# stream. Truncate rather than hand back something no one will read and
# that would have to be held in memory to render.
DEFAULT_MAX_BYTES = 64 * 1024

_HEADER_NODE = re.compile(r"^Node (\d+): (.+)$")
# A chunk header is the byte count of the piece that follows. Indentation
# is how tshark marks direction: node 1 -> node 0 chunks are tab-indented,
# node 0 -> node 1 chunks are not.
_CHUNK_HEADER = re.compile(r"^(\t?)(\d+)$")
_SEPARATOR = "==================================================================="


class StreamError(Exception):
    """Raised when a stream cannot be listed or followed."""


@dataclass
class StreamSummary:
    stream: int
    protocol: str
    endpoint_a: Optional[str]
    endpoint_b: Optional[str]
    packets: int
    bytes: int
    first_frame: Optional[int]
    applications: list = field(default_factory=list)

    def to_dict(self):
        return {
            "stream": self.stream,
            "protocol": self.protocol,
            "endpoint_a": self.endpoint_a,
            "endpoint_b": self.endpoint_b,
            "packets": self.packets,
            "bytes": self.bytes,
            "first_frame": self.first_frame,
            "applications": self.applications,
        }


@dataclass
class StreamTurn:
    sender: str
    text: str
    byte_count: int

    def to_dict(self):
        return {"sender": self.sender, "text": self.text, "byte_count": self.byte_count}


@dataclass
class FollowedStream:
    stream: int
    protocol: str
    node_a: Optional[str]
    node_b: Optional[str]
    turns: list = field(default_factory=list)
    truncated: bool = False

    def to_dict(self):
        return {
            "stream": self.stream,
            "protocol": self.protocol,
            "node_a": self.node_a,
            "node_b": self.node_b,
            "truncated": self.truncated,
            "turns": [turn.to_dict() for turn in self.turns],
        }


def _require_tshark(action):
    if not wireshark.available():
        raise StreamError(
            f"{action} needs tshark, which was not found. Install Wireshark, or set "
            "NETFORENSIC_TSHARK to its executable."
        )


def _check_protocol(protocol):
    protocol = (protocol or "").strip().lower()
    if protocol not in STREAM_PROTOCOLS:
        raise StreamError(f"Unknown stream protocol '{protocol}'. Choose one of: {', '.join(STREAM_PROTOCOLS)}.")
    return protocol


def _first(layers, name):
    values = layers.get(name.replace(".", "_"))
    if not values:
        return None
    return values[0] if isinstance(values, list) else values


def list_streams(pcap_path, protocol=TCP, display_filter=None, limit=DEFAULT_STREAM_LIMIT):
    """Conversations in the capture, largest first.

    Aggregated from a single streaming pass rather than from tshark's
    `-z conv` table: that table does not report the stream index, which is
    the only thing follow_stream() can address a conversation by, and
    parsing its column layout would break the moment it changed.
    """
    protocol = _check_protocol(protocol)
    _require_tshark("Listing streams")

    fields = (
        f"{protocol}.stream",
        "frame.number",
        "frame.len",
        "ip.src",
        "ip.dst",
        "ipv6.src",
        "ipv6.dst",
        f"{protocol}.srcport",
        f"{protocol}.dstport",
        "_ws.col.protocol",
    )
    scoped = f"({display_filter}) && {protocol}" if display_filter else protocol

    summaries = {}
    for layers in wireshark.iter_dissected_packets(pcap_path, fields, display_filter=scoped):
        index = _first(layers, f"{protocol}.stream")
        if index is None:
            continue
        try:
            index = int(index)
        except (TypeError, ValueError):
            continue

        summary = summaries.get(index)
        if summary is None:
            src = _first(layers, "ip.src") or _first(layers, "ipv6.src")
            dst = _first(layers, "ip.dst") or _first(layers, "ipv6.dst")
            sport = _first(layers, f"{protocol}.srcport")
            dport = _first(layers, f"{protocol}.dstport")
            frame = _first(layers, "frame.number")
            summary = summaries[index] = StreamSummary(
                stream=index,
                protocol=protocol,
                endpoint_a=f"{src}:{sport}" if src and sport else src,
                endpoint_b=f"{dst}:{dport}" if dst and dport else dst,
                packets=0,
                bytes=0,
                first_frame=int(frame) if frame else None,
            )
        summary.packets += 1
        try:
            summary.bytes += int(_first(layers, "frame.len") or 0)
        except (TypeError, ValueError):
            pass
        application = _first(layers, "_ws.col.protocol")
        if application and application not in summary.applications:
            summary.applications.append(application)

    ranked = sorted(summaries.values(), key=lambda s: (s.bytes, s.packets), reverse=True)
    return ranked[:limit] if limit else ranked


def follow_stream(pcap_path, protocol=TCP, index=0, max_bytes=DEFAULT_MAX_BYTES):
    """Reassemble one conversation into ordered, direction-tagged turns."""
    protocol = _check_protocol(protocol)
    _require_tshark("Following a stream")
    try:
        index = int(index)
    except (TypeError, ValueError):
        raise StreamError(f"Stream index must be a number, got '{index}'.")
    if index < 0:
        raise StreamError("Stream index must not be negative.")

    binary = wireshark.tshark_path()
    # Raw bytes, not text: this output carries reassembled payload, and
    # text mode's universal-newline translation rewrites a lone CR as a
    # newline - inserting a blank line after every CRLF-terminated header
    # in the conversation being reported.
    completed = wireshark._run(
        [binary, "-r", str(pcap_path), "-q", "-z", f"follow,{protocol},ascii,{index}"],
        wireshark.SLICE_TIMEOUT_SECONDS,
        check=False,
        text=False,
    )
    if completed.returncode != 0:
        detail = (completed.stderr or b"").decode("utf-8", errors="replace").strip().splitlines()
        raise StreamError(detail[0] if detail else f"tshark exited {completed.returncode}")

    output = (completed.stdout or b"").decode("utf-8", errors="replace")
    return _parse_follow_output(output, protocol, index, max_bytes)


def _parse_follow_output(output, protocol, index, max_bytes):
    r"""Parse tshark's `-z follow,...,ascii` report.

    The format is a header naming the two endpoints, then alternating
    chunks. Each chunk is introduced by a line holding its byte count, and
    chunks travelling from node 1 back to node 0 are TAB-INDENTED - that
    indentation is the only direction marker in the output, which is why
    it is matched explicitly rather than stripped along with other
    whitespace.
    """
    followed = FollowedStream(stream=index, protocol=protocol, node_a=None, node_b=None)

    sender = None
    buffer = []
    total = 0

    def flush():
        nonlocal buffer, sender
        if sender is not None and buffer:
            text = "\n".join(buffer)
            followed.turns.append(StreamTurn(sender=sender, text=text, byte_count=len(text)))
        buffer = []

    # Split on newlines ONLY. str.splitlines() also breaks on a bare CR,
    # and payloads use CRLF line endings - so it would turn every header
    # line of a followed HTTP exchange into a line plus a spurious blank
    # one, and the reassembled conversation would not look like what
    # actually went over the wire.
    for line in (output or "").split("\n"):
        stripped = line.rstrip("\r")
        if stripped.startswith(_SEPARATOR) or stripped.startswith(("Follow:", "Filter:")):
            continue
        node = _HEADER_NODE.match(stripped)
        if node:
            if node.group(1) == "0":
                followed.node_a = node.group(2).strip()
            else:
                followed.node_b = node.group(2).strip()
            continue

        chunk = _CHUNK_HEADER.match(stripped)
        if chunk:
            flush()
            sender = "b" if chunk.group(1) else "a"
            continue

        if sender is None:
            continue
        if total >= max_bytes:
            followed.truncated = True
            continue
        buffer.append(stripped)
        total += len(stripped) + 1

    flush()
    if not followed.turns and not followed.node_a:
        raise StreamError(
            f"No {protocol} stream {index} in this capture. "
            f"Use `netforensic stream list` to see which streams exist."
        )
    return followed
