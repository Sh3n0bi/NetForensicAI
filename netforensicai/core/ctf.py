"""Triage presets: the first pass over an unfamiliar capture.

Everything here is a thin, opinionated layer over primitives that already
exist - content search (core/search.py), stream reassembly
(core/streams.py) and Wireshark's object export. It adds no new way of
reading evidence. What it adds is the set of questions worth asking
first, so an analyst handed a capture they know nothing about does not
have to remember all of them.

Named for the case it serves best - a CTF network challenge, where the
answer is deliberately hidden somewhere in the bytes and the clock is
running - but the questions are the same ones that open a real intrusion
investigation: what protocols are in here, what was transferred, what
looks like a credential, and what is the largest conversation.

TWO RULES THIS MODULE KEEPS.

It never writes to the case. Triage is a question asked of evidence, not
a modification of it, and nothing here creates a Finding - turning a hit
into a finding stays an explicit investigator action, exactly as it is
everywhere else in the platform.

It reports candidates, not verdicts. A regex that matches something
shaped like a password has found a string, not a credential. Results are
named after the pattern that matched so the analyst can judge, and every
one carries the frame and stream it came from so the judging can be done
against the packets rather than against this module's opinion.
"""

import hashlib
import logging
import re
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from netforensicai.core import search, streams
from netforensicai.integrations import wireshark

logger = logging.getLogger(__name__)

# Patterns are PCRE, evaluated by tshark against raw frame bytes and then
# re-applied here to name which one matched. Kept deliberately portable -
# no lookbehind, no named groups - because they have to compile in both
# Wireshark's regex engine and Python's.
# Every prefix is anchored with \b so it cannot match mid-token: without
# it, `myctf{...}` is reported as a `CTF{}` flag, because `CTF\{` matches
# the tail of the word. The prefix would then be wrong in the output an
# analyst copies the flag out of.
FLAG_PATTERNS = {
    "flag{}": r"\bflag\{[^}\r\n]{1,200}\}",
    "CTF{}": r"\bCTF\{[^}\r\n]{1,200}\}",
    "HTB{}": r"\bHTB\{[^}\r\n]{1,200}\}",
    "picoCTF{}": r"\bpicoCTF\{[^}\r\n]{1,200}\}",
    # Anything else shaped like a flag. Noisier by design: CTF authors use
    # their own prefixes, and missing the flag because the prefix was not
    # on a hardcoded list is the worse failure.
    "prefix{}": r"\b[A-Za-z][A-Za-z0-9_]{2,20}\{[ -~]{4,100}\}",
}

CREDENTIAL_PATTERNS = {
    "http-basic": r"Authorization: *Basic +[A-Za-z0-9+/=]{8,}",
    "http-bearer": r"Authorization: *Bearer +[A-Za-z0-9._\-]{10,}",
    "form-password": r"(?:password|passwd|pwd)=[^& \r\n\"]{1,64}",
    "form-username": r"(?:username|user|login|email)=[^& \r\n\"]{1,64}",
    "ftp-user": r"(?:\r\n|\A)USER +[^\r\n]{1,64}",
    "ftp-pass": r"(?:\r\n|\A)PASS +[^\r\n]{1,64}",
    "http-cookie": r"Cookie: *[^\r\n]{8,200}",
}

SECRET_PATTERNS = {
    "private-key": r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
    "aws-access-key": r"AKIA[0-9A-Z]{16}",
    "jwt": r"eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}",
    "slack-token": r"xox[abprs]-[A-Za-z0-9\-]{10,}",
    "generic-api-key": r"(?:api[_-]?key|access[_-]?token|secret[_-]?key)[\"' :=]{1,4}[A-Za-z0-9._\-]{16,}",
}

CATEGORIES = {
    "flags": FLAG_PATTERNS,
    "credentials": CREDENTIAL_PATTERNS,
    "secrets": SECRET_PATTERNS,
}

# Protocols worth calling out when present: either they carry credentials
# in the clear, or their presence in a capture is itself the finding.
NOTABLE_PROTOCOLS = {
    "telnet": "Telnet is unencrypted - credentials and session content are readable.",
    "ftp": "FTP authenticates in the clear; FTP-DATA carries transferred files.",
    "tftp": "TFTP has no authentication at all.",
    "http": "Cleartext HTTP - request bodies, cookies and credentials are readable.",
    "smtp": "SMTP may carry credentials and full message content in the clear.",
    "pop": "POP3 authenticates in the clear.",
    "imap": "IMAP may authenticate in the clear.",
    "snmp": "SNMP community strings are effectively passwords, sent in the clear.",
    "nbns": "NetBIOS name service leaks hostnames and can be poisoned.",
    "llmnr": "LLMNR is a classic credential-relay vector.",
    "kerberos": "Kerberos exchanges - check for AS-REP roasting and pre-auth failures.",
    "ntlmssp": "NTLM authentication - check for relayable exchanges.",
    "smb": "SMB - check for file access and authentication attempts.",
    "smb2": "SMB2 - check for file access and authentication attempts.",
    "icmp": "ICMP can carry tunnelled data in payloads.",
    "dns": "DNS can carry tunnelled data in long or numerous labels.",
}

DEFAULT_MAX_HITS_PER_CATEGORY = 50
EXPORT_PROTOCOLS = ("http", "smb", "ftp-data", "tftp", "imf")

_PHS_LINE = re.compile(r"^(\s*)(\S+)\s+frames:(\d+)\s+bytes:(\d+)")


class CtfError(Exception):
    """Raised when triage cannot run."""


@dataclass
class Candidate:
    category: str
    pattern: str
    value: str
    frame_number: int
    stream: int = None
    src: str = None
    dst: str = None
    protocol: str = None
    excerpt: str = None

    def to_dict(self):
        return {
            "category": self.category,
            "pattern": self.pattern,
            "value": self.value,
            "frame_number": self.frame_number,
            "stream": self.stream,
            "src": self.src,
            "dst": self.dst,
            "protocol": self.protocol,
            "excerpt": self.excerpt,
        }


@dataclass
class ProtocolCount:
    protocol: str
    depth: int
    frames: int
    bytes: int
    note: str = None

    def to_dict(self):
        return {
            "protocol": self.protocol,
            "depth": self.depth,
            "frames": self.frames,
            "bytes": self.bytes,
            "note": self.note,
        }


@dataclass
class ExtractedFile:
    name: str
    protocol: str
    size: int
    sha256: str
    path: str = None

    def to_dict(self):
        return {
            "name": self.name,
            "protocol": self.protocol,
            "size": self.size,
            "sha256": self.sha256,
            "path": self.path,
        }


@dataclass
class TriageReport:
    protocols: list = field(default_factory=list)
    candidates: list = field(default_factory=list)
    files: list = field(default_factory=list)
    top_streams: list = field(default_factory=list)
    truncated_categories: list = field(default_factory=list)

    def to_dict(self):
        return {
            "protocols": [p.to_dict() for p in self.protocols],
            "candidates": [c.to_dict() for c in self.candidates],
            "files": [f.to_dict() for f in self.files],
            "top_streams": [s.to_dict() for s in self.top_streams],
            "truncated_categories": list(self.truncated_categories),
        }


def _require_tshark():
    if not wireshark.available():
        raise CtfError(
            "Triage needs tshark, which was not found. Install Wireshark, or set "
            "NETFORENSIC_TSHARK to its executable."
        )


def combined_pattern(patterns):
    """One alternation over a category's patterns.

    A single tshark pass per category rather than one per pattern: each
    pass reads the whole capture, so on a large file the difference is
    minutes. Which pattern actually matched is worked out here afterwards,
    against the matched text.
    """
    return "|".join(f"(?:{expression})" for expression in patterns.values())


def classify(patterns, value):
    """Name the most specific pattern that matches `value`.

    Ordered by the category's own declaration order, so the specific
    entries (`flag{}`, `HTB{}`) win over the deliberately broad catch-all
    (`prefix{}`) that follows them.
    """
    for name, expression in patterns.items():
        if re.search(expression, value, re.IGNORECASE | re.DOTALL):
            return name
    return None


def hunt(pcap_path, category, max_hits=DEFAULT_MAX_HITS_PER_CATEGORY, display_filter=None):
    """Search a capture for one category of interesting string.

    Returns (candidates, truncated).
    """
    _require_tshark()
    patterns = CATEGORIES.get(category)
    if patterns is None:
        raise CtfError(f"Unknown category '{category}'. Choose one of: {', '.join(CATEGORIES)}.")

    result = search.search_capture(
        pcap_path,
        combined_pattern(patterns),
        mode=search.REGEX,
        max_hits=max_hits,
        display_filter=display_filter,
    )

    candidates = []
    seen = set()
    for hit in result.hits:
        # Every match in the packet, per pattern - not just the first.
        # One HTTP request routinely carries an Authorization header AND a
        # Cookie; one response can carry a private key AND a JWT. Taking
        # only the hit's own `matched` value reported the first and
        # silently dropped the rest, which for triage is the difference
        # between finding the answer and walking past it.
        found = []
        haystack = hit.payload or hit.excerpt or ""
        for name, expression in patterns.items():
            for match in re.finditer(expression, haystack, re.IGNORECASE):
                found.append((name, match.group(0).strip()))
        if not found and hit.matched:
            found = [(classify(patterns, hit.matched) or "unknown", hit.matched)]

        for name, value in found:
            if not value:
                continue
            # The same flag or credential usually recurs - a request and
            # its retransmission, or a value echoed back. Report it once,
            # at the first frame it was seen in. Keyed on the value alone
            # so the broad `prefix{}` catch-all cannot re-report a flag the
            # specific pattern already claimed.
            if value in seen:
                continue
            seen.add(value)
            candidates.append(
                Candidate(
                    category=category,
                    pattern=name,
                    value=value,
                    frame_number=hit.frame_number,
                    stream=hit.stream,
                    src=hit.src,
                    dst=hit.dst,
                    protocol=hit.protocol,
                    excerpt=hit.excerpt,
                )
            )
    return candidates, result.truncated


def protocol_summary(pcap_path):
    """What is actually in this capture, from tshark's protocol hierarchy.

    Uses `-z io,phs` rather than counting a dissection pass here: tshark
    computes it natively in a couple of seconds on a capture where a
    full field-extraction pass takes a minute.
    """
    _require_tshark()
    binary = wireshark.tshark_path()
    completed = wireshark._run(
        [binary, "-r", str(pcap_path), "-q", "-z", "io,phs"],
        wireshark.SLICE_TIMEOUT_SECONDS,
        check=False,
    )
    if completed.returncode != 0:
        raise CtfError(f"Could not read protocol hierarchy: {(completed.stderr or '').strip()}")

    counts = []
    for line in (completed.stdout or "").splitlines():
        match = _PHS_LINE.match(line.rstrip())
        if not match:
            continue
        indent, name, frames, size = match.groups()
        if name == "frame":
            continue
        counts.append(
            ProtocolCount(
                protocol=name,
                depth=len(indent) // 2,
                frames=int(frames),
                bytes=int(size),
                note=NOTABLE_PROTOCOLS.get(name),
            )
        )
    return counts


def extract_files(pcap_path, output_dir=None):
    """Recover transferred files via Wireshark's object export.

    output_dir=None extracts into a temporary directory purely to report
    what is recoverable, then discards it - triage must not scatter
    evidence-derived files outside a case.
    """
    _require_tshark()
    extracted = []
    for protocol in EXPORT_PROTOCOLS:
        with tempfile.TemporaryDirectory(prefix=f"netforensic_ctf_{protocol}_") as staging:
            try:
                files = wireshark.export_objects(pcap_path, protocol, staging)
            except wireshark.WiresharkError as e:
                logger.info(f"Object export for '{protocol}' did not run: {e}")
                continue
            for source in files:
                data = source.read_bytes()
                if not data:
                    continue
                stored = None
                if output_dir is not None:
                    destination = Path(output_dir) / protocol / source.name
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    destination.write_bytes(data)
                    stored = str(destination)
                extracted.append(
                    ExtractedFile(
                        name=source.name,
                        protocol=protocol,
                        size=len(data),
                        sha256=hashlib.sha256(data).hexdigest(),
                        path=stored,
                    )
                )
    return extracted


def triage(
    pcap_path,
    categories=None,
    max_hits=DEFAULT_MAX_HITS_PER_CATEGORY,
    output_dir=None,
    top_streams=10,
    display_filter=None,
):
    """Run every preset over one capture and return a TriageReport."""
    _require_tshark()
    report = TriageReport()

    report.protocols = protocol_summary(pcap_path)

    for category in categories or list(CATEGORIES):
        candidates, truncated = hunt(
            pcap_path, category, max_hits=max_hits, display_filter=display_filter
        )
        report.candidates.extend(candidates)
        if truncated:
            report.truncated_categories.append(category)

    report.files = extract_files(pcap_path, output_dir=output_dir)

    try:
        report.top_streams = streams.list_streams(
            pcap_path, protocol=streams.TCP, display_filter=display_filter, limit=top_streams
        )
    except streams.StreamError as e:
        # A capture with no TCP at all is a perfectly good capture; it just
        # has no conversations to rank.
        logger.info(f"Could not rank streams: {e}")

    return report
