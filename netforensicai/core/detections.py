"""Bundled offline detection rules: a small, fixed set of deterministic
pattern matches over normalized events, run automatically as part of
`analyze` - no AI, no external network call, no API key, nothing opt-in.

    Evidence -> Parsing -> Normalization -> Correlation -> Timeline
        -> Detections (this module) -> [optional: ATT&CK mapping,
           threat intel, AI hypothesis] -> Human validation -> Report

This sits alongside correlation as part of the automatic, deterministic
pipeline rather than behind an explicit command like `attack scan` or
`investigate --vt-api`: every rule here is a fixed, local, zero-cost
pattern match (a process name, a port number, a filename shape), with
none of the cost/privacy/rate-limit reasons threat intel and AI have for
staying opt-in. Like everything else in this pipeline, a detection is a
flag pointing at evidence, never a claim that something malicious
happened - the wording on every rule says "commonly associated with" or
"may indicate", not "this is". Nothing here writes a Finding automatically.

Always a full rescan of every event, recomputed the same way correlation
is (CaseStore.replace_detections deletes and reinserts) - a detection has
no investigator-set status to preserve across runs, unlike an ATT&CK
mapping. If a rule stops matching (the offending event was on evidence
that's since been corrected, for example), the next analyze simply drops
it - there's nothing to explicitly reject.

Deliberately a small starting set (four rules) rather than an attempt at
exhaustive coverage - same reasoning as core/attack.py's rule set: each
rule was chosen because the signal is specific enough to be worth an
investigator's attention on its own. Adding more follows the same
pattern - see CONTRIBUTING.md.
"""

import itertools
import logging
import re
from urllib.parse import unquote_plus

logger = logging.getLogger(__name__)

SEVERITIES = ("low", "medium", "high")

# Dual-use tools with legitimate uses (sysadmin, red team engagements) but
# whose presence is worth an investigator's attention regardless - matched
# on process_name, case-insensitively, exact basename match only (not a
# substring) to avoid flagging unrelated processes that merely contain
# one of these words.
_OFFENSIVE_TOOL_NAMES = {
    "mimikatz.exe",
    "procdump.exe",
    "psexec.exe",
    "psexec64.exe",
    "rubeus.exe",
    "wce.exe",
    "pwdump.exe",
    "pwdump7.exe",
    "nc.exe",
    "ncat.exe",
    "plink.exe",
}

# Ports with a long history of association with specific malware/C2
# frameworks (Metasploit's default 4444, Back Orifice's 31337, NetBus's
# 12345, etc.) - none of these are reserved exclusively for malicious use,
# so the basis text says "commonly associated with", not "is".
_SUSPICIOUS_PORTS = {
    4444: "Metasploit's default handler port",
    1337: "a port conventionally used by malware/C2 tooling ('leet')",
    31337: "Back Orifice's default port ('eleet')",
    12345: "NetBus's default port",
    6666: "a port commonly used by IRC-based botnet C2",
}

_EXECUTABLE_EXTENSIONS = {".exe", ".scr", ".bat", ".cmd", ".com", ".pif", ".vbs", ".js"}

# Substrings that appear in the User-Agent of well-known offensive
# security tools. Matched case-insensitively as substrings because these
# tools append version strings ("gobuster/3.6", "sqlmap/1.8.3#stable").
# Every one of these is dual-use - they are standard in authorized
# penetration tests - so the description says "commonly used for", and
# leaves the judgement to the investigator.
_ATTACK_TOOL_USER_AGENTS = {
    "gobuster": "directory/content brute-forcing",
    "sqlmap": "automated SQL injection",
    "nikto": "web vulnerability scanning",
    "dirbuster": "directory brute-forcing",
    "wfuzz": "web fuzzing",
    "ffuf": "web fuzzing",
    "nmap": "network/service scanning",
    "masscan": "high-speed port scanning",
    "nessus": "vulnerability scanning",
    "burp": "web proxy/attack tooling",
    "hydra": "credential brute-forcing",
    "havij": "automated SQL injection",
    "acunetix": "web vulnerability scanning",
    "zgrab": "internet-wide scanning",
}

# An HTTP client requesting this many distinct URL paths from one host is
# doing content discovery, not browsing. Set well above what a real page
# load pulls in (a heavy page is tens of assets, not hundreds) so ordinary
# traffic doesn't trip it.
_SCAN_DISTINCT_PATH_THRESHOLD = 100

# Fragments that indicate SQL-injection probing in a URL. Matched against
# the URL-decoded query string, since injection payloads are almost always
# percent-encoded on the wire. These are phrases that do not occur in
# ordinary URLs - deliberately not bare keywords like "select" or "union",
# which appear in perfectly normal query parameters.
_SQLI_URL_PATTERNS = (
    "union all select",
    "union select",
    "' or '1'='1",
    "or 1=1--",
    "sleep(",
    "benchmark(",
    "information_schema",
    "waitfor delay",
    "'; drop table",
    "extractvalue(",
    "updatexml(",
)

_CREDENTIAL_ARTIFACT_PATTERNS = (
    "system32\\config\\sam",
    "system32/config/sam",
    "ntds.dit",
    "lsass.dmp",
    "lsass.exe.dmp",
)


def _looks_like_sqli(url):
    """Whether a URL contains a recognizable SQL-injection payload.

    Decodes percent-encoding first: injection payloads are almost always
    encoded on the wire, so matching the raw URL would miss nearly all of
    them.
    """
    try:
        decoded = unquote_plus(str(url)).lower()
    except Exception:
        decoded = str(url).lower()
    return any(pattern in decoded for pattern in _SQLI_URL_PATTERNS)


def _clip(text, limit=90):
    """Shorten a value for display inside a detection description."""
    text = str(text)
    return text if len(text) <= limit else text[:limit] + "..."


def _looks_like_extension(part):
    """Whether a dot-separated fragment is plausibly a real file extension.

    Guards against dots that aren't extension separators at all. Found via a
    real capture: the pcap parser names carved files after the TCP stream
    ("73.124.22.98_80_to_111.224.250.131_43248.exe"), and the IP octets made
    every one of them look like a disguised double-extension executable.
    """
    return 1 <= len(part) <= 5 and part.isalnum() and not part.isdigit()


def _double_extension_match(file_name):
    """True if file_name has two extensions and the last one is
    executable - e.g. "invoice.pdf.exe". A single ".exe" alone (no
    disguise attempt) does not match; the whole point of this rule is the
    *disguise* pattern, not "is this an executable"."""
    if not file_name:
        return False
    parts = file_name.lower().rsplit(".", 2)
    if len(parts) != 3:
        return False
    _stem, first_ext, second_ext = parts
    # BOTH fragments must look like real extensions. The masquerade this
    # rule targets is "document extension followed by executable one"
    # (invoice.pdf.exe) - if the first fragment isn't a plausible
    # extension, the dots are just part of the name.
    return f".{second_ext}" in _EXECUTABLE_EXTENSIONS and _looks_like_extension(first_ext)


def _rules_for_event(event):
    if event.event_type == "process_start" and event.process_name:
        name = event.process_name.lower()
        if name in _OFFENSIVE_TOOL_NAMES:
            yield (
                "OFFENSIVE-TOOL-NAME",
                "Known offensive-security tool name",
                "high",
                f"Process name matches a tool commonly used for credential access or lateral "
                f"movement: {event.process_name}",
            )

    if event.event_type == "network_connection" and event.dst_port in _SUSPICIOUS_PORTS:
        reason = _SUSPICIOUS_PORTS[event.dst_port]
        yield (
            "SUSPICIOUS-PORT",
            "Connection to a historically suspicious port",
            "medium",
            f"Destination port {event.dst_port} is {reason} - not exclusively malicious, "
            f"worth checking the context.",
        )

    if event.file_name and _double_extension_match(event.file_name):
        yield (
            "DOUBLE-EXTENSION-FILE",
            "Disguised executable (double file extension)",
            "high",
            f"Filename has a double extension ending in an executable type, a common way to "
            f"disguise malware as a document: {event.file_name}",
        )

    combined_path = " ".join(filter(None, [event.file_name, event.file_path])).lower()
    for pattern in _CREDENTIAL_ARTIFACT_PATTERNS:
        if pattern in combined_path:
            yield (
                "CREDENTIAL-ARTIFACT",
                "Credential-store artifact accessed or extracted",
                "high",
                f"File path matches a known credential-store artifact pattern ('{pattern}') - "
                f"commonly seen in credential dumping.",
            )
            break


class _AggregateState:
    """Running state for rules that only make sense across many events.

    Separate from _rules_for_event because emitting one detection per
    matching packet is actively harmful here: a real directory brute-force
    is tens of thousands of requests, and reporting each one individually
    buries the single fact the investigator needs ("this host scanned that
    host") under 40,000 identical rows. These summarize instead, citing one
    representative event plus the totals.

    Written as feed()/results() rather than a function over a list so
    scan_case can drive it from the same streaming pass that runs the
    per-event rules, without ever holding the case's events in memory.
    """

    def __init__(self):
        self.tool_hits = {}     # (src_ip, tool) -> [count, first_event, sample_ua, purpose]
        self.path_probes = {}   # (src_ip, dst_ip) -> [set_of_paths, first_event, count]
        self.scan_results = {}  # (server_ip, client_ip) -> {"ok", "missing", "event"}
        self.sqli = {}          # (src_ip, dst_ip) -> {"attempts", "succeeded", "event"}

    def feed(self, event):
        if event.event_type == "http_response":
            self._feed_response(event)
        elif event.event_type == "http_request":
            self._feed_request(event)

    def _feed_response(self, event):
        status = (event.raw_event_reference or {}).get("status_code")
        if status is None:
            return

        # A response is the only place that shows whether an injection
        # attempt was actually served - the request alone proves intent,
        # not impact.
        if event.url and _looks_like_sqli(event.url):
            entry = self.sqli.setdefault(
                (event.dst_ip, event.src_ip), {"attempts": 0, "succeeded": set(), "event": event}
            )
            if 200 <= status < 300:
                entry["succeeded"].add(_clip(event.url, 120))

        # src of a response is the server; dst is the client that asked.
        entry = self.scan_results.setdefault(
            (event.src_ip, event.dst_ip), {"ok": set(), "missing": 0, "event": event}
        )
        if 200 <= status < 300 and event.url:
            entry["ok"].add(event.url)
        elif status == 404:
            entry["missing"] += 1

    def _feed_request(self, event):
        if event.url and _looks_like_sqli(event.url):
            entry = self.sqli.setdefault(
                (event.src_ip, event.dst_ip), {"attempts": 0, "succeeded": set(), "event": event}
            )
            entry["attempts"] += 1

        user_agent = (event.raw_event_reference or {}).get("user_agent") or ""
        lowered_ua = user_agent.lower()
        for tool, purpose in _ATTACK_TOOL_USER_AGENTS.items():
            if tool in lowered_ua:
                entry = self.tool_hits.setdefault(
                    (event.src_ip, tool), [0, event, user_agent, purpose]
                )
                entry[0] += 1
                break

        if event.url:
            entry = self.path_probes.setdefault((event.src_ip, event.dst_ip), [set(), event, 0])
            entry[0].add(event.url)
            entry[2] += 1

    def results(self):
        """Yield (rule_id, rule_name, severity, description, representative_event)."""
        for (src_ip, tool), (count, first_event, user_agent, purpose) in sorted(
            self.tool_hits.items(), key=lambda kv: (str(kv[0][0]), kv[0][1])
        ):
            yield (
                "ATTACK-TOOL-USER-AGENT",
                "Offensive security tool identified by User-Agent",
                "high",
                f"{count} HTTP request(s) from {src_ip} carry a User-Agent identifying '{tool}', a "
                f"tool commonly used for {purpose} ({user_agent}). These tools are also used in "
                f"authorized testing - confirm whether this activity was sanctioned.",
                first_event,
            )

        for (src_ip, dst_ip), (paths, first_event, count) in sorted(
            self.path_probes.items(), key=lambda kv: (str(kv[0][0]), str(kv[0][1]))
        ):
            if len(paths) < _SCAN_DISTINCT_PATH_THRESHOLD:
                continue
            yield (
                "HTTP-PATH-ENUMERATION",
                "High-volume distinct URL requests (possible content discovery)",
                "high",
                f"{src_ip} requested {len(paths)} distinct URL paths from {dst_ip} across {count} "
                f"request(s) - a volume consistent with automated content discovery or directory "
                f"brute-forcing rather than ordinary browsing.",
                first_event,
            )

        for (src_ip, dst_ip), info in sorted(
            self.sqli.items(), key=lambda kv: (str(kv[0][0]), str(kv[0][1]))
        ):
            if not info["attempts"]:
                continue
            if info["succeeded"]:
                sample = ", ".join(sorted(info["succeeded"])[:3])
                description = (
                    f"{info['attempts']} request(s) from {src_ip} to {dst_ip} contain SQL-injection "
                    f"payloads, and {len(info['succeeded'])} received a success response rather than "
                    f"an error - the server processed the injected query, so treat the underlying "
                    f"data as potentially exposed. Example: {sample}"
                )
                severity = "high"
            else:
                description = (
                    f"{info['attempts']} request(s) from {src_ip} to {dst_ip} contain SQL-injection "
                    f"payloads. None returned a success response in this capture, which suggests the "
                    f"attempts failed - but absence of a success here is not proof they all did."
                )
                severity = "medium"
            yield (
                "SQL-INJECTION-ATTEMPT",
                "SQL injection payloads in HTTP requests",
                severity,
                description,
                info["event"],
            )

        for (server_ip, client_ip), info in sorted(
            self.scan_results.items(), key=lambda kv: (str(kv[0][0]), str(kv[0][1]))
        ):
            # Only meaningful alongside a failed-heavy scan: a handful of 404s
            # is ordinary browsing, and reporting successes without that
            # context would flag every normal web session.
            if info["missing"] < _SCAN_DISTINCT_PATH_THRESHOLD or not info["ok"]:
                continue
            # Shortest first, and each one clipped: injection payloads show up
            # here as URLs thousands of characters long, and one of them
            # unclipped makes the whole finding unreadable in a table.
            found = sorted(info["ok"], key=lambda u: (len(u), u))
            sample = ", ".join(_clip(u) for u in found[:5]) + (" ..." if len(found) > 5 else "")
            yield (
                "SCAN-SUCCESSFUL-PATHS",
                "Paths that responded successfully during a failed-heavy scan",
                "high",
                f"Amid {info['missing']} '404 Not Found' responses to {client_ip}, {server_ip} "
                f"returned success for {len(found)} distinct path(s) - these are what the scan "
                f"actually found, and the first place to look: {sample}",
                info["event"],
            )


# --- network rules ----------------------------------------------------
#
# The rules above this point grew from endpoint and web-scan evidence.
# They fire on process names, disguised filenames and request floods -
# and on a capture containing a malware download, credentials in the
# clear, a stolen private key, a bulk upload to an external host and
# eight beacons, they matched NOTHING. These cover that surface.

# TLDs that are cheap, bulk-registrable and heavily abused. Presence is
# not proof - plenty of legitimate sites use them - so this is `low` and
# worded as something to check, not something to act on.
_SUSPICIOUS_TLDS = {
    "top", "xyz", "tk", "ml", "ga", "cf", "gq", "buzz", "click", "work",
    "surf", "rest", "cyou", "monster", "quest", "sbs", "cfd", "lol",
}

# Extensions that execute, or that carry something that does.
_EXECUTABLE_SUFFIXES = (
    ".exe", ".dll", ".scr", ".msi", ".bat", ".cmd", ".ps1", ".vbs", ".jar",
    ".hta", ".apk", ".elf", ".so", ".dylib", ".pyc",
)

# Field names that carry a secret when they appear in a cleartext body.
_CREDENTIAL_MARKERS = re.compile(
    r"(?:^|[?&\s])(?:password|passwd|pwd|pass|secret|token|api[_-]?key)=", re.IGNORECASE
)

# Filenames that are private key material by convention. Checked as well
# as content, because object export names a recovered file even when its
# bytes are not carried on any event.
_KEY_FILENAMES = (
    "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", ".pem", ".pfx", ".p12", ".jks", ".keystore",
)

# Material that is a compromise on sight, wherever it appears.
_KEY_MATERIAL = (
    ("private-key", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----")),
    ("aws-key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}")),
)

# Protocols that authenticate without encrypting. A credential seen here
# is disclosed, not merely at risk.
_CLEARTEXT_AUTH_PORTS = {21: "FTP", 23: "Telnet", 110: "POP3", 143: "IMAP", 80: "HTTP"}

# Bytes to one external destination before an upload is worth a look.
BULK_TRANSFER_BYTES = 4_096

# VOLUME ALONE IS THE WRONG DISCRIMINATOR, and this rule used to use it.
# Audited against generated benign office traffic, an absolute threshold
# fired on 11 ordinary browsing sessions: request headers, cookies and
# form posts to one web host add up past any floor low enough to still
# catch a small exfiltration. What actually separates the two is
# DIRECTION - a browser receives far more than it sends, an upload is the
# reverse. Requiring the outbound bytes to exceed what came back removed
# all 11 without weakening the real detections.
BULK_TRANSFER_MIN_RATIO = 1.0

# Above this, direction stops mattering. A very large upload is worth
# reporting even alongside a heavy download that would otherwise mask the
# ratio - which is exactly where a patient exfiltration would hide.
BULK_TRANSFER_ALWAYS_BYTES = 10_485_760

# A beacon is regular. These bound what counts as regular: enough repeats
# to be a pattern, and intervals that agree closely enough not to be a
# person clicking.
BEACON_MIN_CONNECTIONS = 5
BEACON_MAX_JITTER_RATIO = 0.25

# Below this, "periodic" is the wrong word. Flows a fraction of a second
# apart are one burst - a file transfer opening parallel connections, say
# - and reporting a "near-constant 0s interval" as a beacon is a false
# positive that teaches an analyst to distrust the rule.
BEACON_MIN_INTERVAL_SECONDS = 1.0

# A beacon is a small, regular CHECK-IN. A chunked upload is also regular
# - six file parts two seconds apart fit "periodic" perfectly - but it is
# an exfiltration, not an implant calling home, and the two want different
# responses. Volume is what separates them.
BEACON_MAX_MEAN_BYTES = 2_048


def _is_private(address):
    """RFC1918 / loopback / link-local. Used to tell "left the network"
    from "stayed inside it" - the difference between an upload and a file
    copy."""
    if not address:
        return False
    try:
        import ipaddress

        return ipaddress.ip_address(str(address)).is_private or ipaddress.ip_address(str(address)).is_loopback
    except ValueError:
        return False


def _suspicious_tld(domain):
    if not domain or "." not in domain:
        return None
    tld = domain.rsplit(".", 1)[-1].lower()
    return tld if tld in _SUSPICIOUS_TLDS else None


def _network_rules_for_event(event):
    """Per-event network rules. Same contract as _rules_for_event."""

    # A domain on a bulk-registrable TLD.
    tld = _suspicious_tld(event.domain)
    if tld and event.event_type in ("dns_query", "dns_response", "http_request", "tls_handshake"):
        yield (
            "SUSPICIOUS-TLD",
            "Domain on a commonly abused top-level domain",
            "low",
            f"'{event.domain}' is registered under .{tld}, a TLD cheap enough to be used in bulk "
            f"by phishing and malware infrastructure. Common in legitimate use too - worth checking, "
            f"not evidence on its own.",
        )

    # An executable arriving over an UNENCRYPTED channel.
    #
    # Not merely "an executable": fetching setup.exe over HTTPS from a
    # vendor is ordinary, and flagging it would train people to ignore
    # this rule. What makes it a finding is the cleartext - anyone on the
    # path can substitute the binary before it lands.
    target = event.url or event.file_name or ""
    over_cleartext = event.dst_port in _CLEARTEXT_AUTH_PORTS or (event.url or "").startswith("http://")
    if event.event_type in ("http_request", "http_response") and target and over_cleartext:
        lowered = target.split("?", 1)[0].lower()
        if lowered.endswith(_EXECUTABLE_SUFFIXES):
            yield (
                "EXECUTABLE-DOWNLOAD",
                "Executable retrieved over the network",
                "high",
                f"'{_clip(target)}' has an executable extension. Retrieving one over cleartext HTTP "
                f"gives anyone on the path the ability to substitute it.",
            )

    # Credentials submitted where anyone on the path can read them.
    #
    # Driven by the parser's credential_exposure event rather than by
    # pattern-matching a message string. Normalized events carry no
    # payload by design, so a credential is simply not visible from here -
    # only the parser, holding the dissected packet, ever saw it. That
    # event carries a HASH of the secret, never the secret.
    if event.event_type == "credential_exposure":
        reference = event.raw_event_reference or {}
        protocol = reference.get("protocol", "an unencrypted protocol")
        field_name = reference.get("field", "credential")
        yield (
            "CLEARTEXT-CREDENTIALS",
            "Credentials submitted without encryption",
            "high",
            f"A {field_name} field"
            + (f" for user '{event.user}'" if event.user else "")
            + f" crossed the network over {protocol} to {event.dst_ip or 'an external host'}. "
            f"Anyone on the path could read it: treat the credential as disclosed rather than at "
            f"risk, and rotate it.",
        )

    # Key material in transit. A private key that crossed the network
    # shows up two ways: named in a URL or a carved filename, or matched
    # in content. Both are checked - a key served as `/backup/id_rsa` and
    # one recovered by object export are the same incident.
    named = f"{event.file_name or ''} {event.url or ''}".lower()
    if any(marker in named for marker in _KEY_FILENAMES):
        yield (
            "KEY-MATERIAL-IN-TRANSIT",
            "Private key material crossed the network",
            "high",
            f"'{_clip(event.file_name or event.url)}' names private key material. If this was not "
            f"encrypted end to end, the key should be treated as compromised and rotated.",
        )
    elif event.message:
        for label, pattern in _KEY_MATERIAL:
            if pattern.search(event.message):
                yield (
                    "KEY-MATERIAL-IN-TRANSIT",
                    "Secret material observed on the wire",
                    "high",
                    f"Content matching {label} crossed the network. If this was not encrypted end "
                    f"to end, the secret should be treated as compromised and rotated.",
                )
                break


class _NetworkAggregateState:
    """Cross-event network rules: exfiltration, beaconing, credential reuse.

    These are the ones that cannot be seen one packet at a time. A single
    upload chunk is unremarkable; six of them to an external host is an
    exfiltration. One TLS connection means nothing; eight at thirty-second
    intervals is a beacon. And a password is just a string until it turns
    up a second time on a different protocol - THAT is the finding, and it
    is invisible to any rule that looks at one event.
    """

    def __init__(self):
        self.outbound = {}     # (src, dst) -> [bytes, events, first_event]
        self.inbound = {}      # (internal, external) -> bytes that came back
        self.beacons = {}      # (src, dst, port) -> [timestamps, first_event]
        self.secrets = {}      # secret -> [(event, protocol)]

    def feed(self, event):
        self._feed_transfer(event)
        self._feed_beacon(event)
        self._feed_secret(event)

    def _feed_transfer(self, event):
        if event.event_type != "network_connection":
            return
        if not event.src_ip or not event.dst_ip:
            return
        size = (event.raw_event_reference or {}).get("byte_count") or 0

        # The return direction is not noise to be discarded - it is the
        # context that makes the outbound figure mean anything. 8 KB sent
        # to a host that sent back 40 KB is a browser; 8 KB sent to a host
        # that sent back nothing is an upload.
        if _is_private(event.dst_ip) and not _is_private(event.src_ip):
            self.inbound[(event.dst_ip, event.src_ip)] = (
                self.inbound.get((event.dst_ip, event.src_ip), 0) + size
            )
            return

        # Outbound only: a copy between two internal hosts is not
        # exfiltration, and flagging it would bury the case that is.
        if not _is_private(event.src_ip) or _is_private(event.dst_ip):
            return
        key = (event.src_ip, event.dst_ip)
        entry = self.outbound.setdefault(key, [0, 0, event])
        entry[0] += size
        entry[1] += 1

    def _feed_beacon(self, event):
        if event.event_type != "network_connection" or not event.timestamp:
            return
        if not event.src_ip or not event.dst_ip or _is_private(event.dst_ip):
            return
        key = (event.src_ip, event.dst_ip, event.dst_port)
        entry = self.beacons.setdefault(key, [[], event, 0])
        entry[0].append(event.timestamp)
        entry[2] += (event.raw_event_reference or {}).get("byte_count") or 0

    def _feed_secret(self, event):
        """Remember where each credential was seen, keyed on its HASH.

        The hash is what makes this rule possible without the store ever
        holding a password: two credential_exposure events carrying the
        same secret_sha256 are the same secret, and that is the only fact
        this rule needs. The plaintext never leaves the evidence file.
        """
        if event.event_type != "credential_exposure":
            return
        reference = event.raw_event_reference or {}
        digest = reference.get("secret_sha256")
        if not digest:
            return
        self.secrets.setdefault(digest, []).append((event, reference.get("protocol", "unknown")))

    def results(self):
        out = []
        bulk_pairs = set()

        for (src, dst), (size, count, event) in self.outbound.items():
            if size < BULK_TRANSFER_BYTES:
                continue
            returned = self.inbound.get((src, dst), 0)
            outbound_dominant = size > returned * BULK_TRANSFER_MIN_RATIO
            if not outbound_dominant and size < BULK_TRANSFER_ALWAYS_BYTES:
                # More came back than went out: this is a download, and
                # the bytes going the other way are the request that asked
                # for it.
                continue
            bulk_pairs.add((src, dst))
            ratio = f"{size / returned:.1f}x more than it received" if returned else "and received nothing back"
            out.append(
                (
                    "OUTBOUND-BULK-TRANSFER",
                    "Bulk transfer to an external host",
                    "high" if size >= BULK_TRANSFER_BYTES * 4 else "medium",
                    f"{src} sent {size:,} bytes to {dst} across {count} flow(s), {ratio}. "
                    f"Volume alone is not exfiltration - check what was transferred and whether "
                    f"the destination is expected.",
                    event,
                )
            )

        for (src, dst, port), (times, event, total_bytes) in self.beacons.items():
            if len(times) < BEACON_MIN_CONNECTIONS:
                continue
            if total_bytes / max(len(times), 1) > BEACON_MAX_MEAN_BYTES:
                # Regular, but carrying too much to be a check-in.
                continue
            if (src, dst) in bulk_pairs:
                # This pair is already reported as a bulk transfer. A
                # chunked upload is regular by nature, so it satisfies
                # "periodic" too - but it is ONE activity, and naming it
                # twice makes an analyst chase two leads to one place.
                # The more specific rule keeps it.
                continue
            ordered = sorted(times)
            gaps = [
                (b - a).total_seconds() for a, b in zip(ordered, ordered[1:]) if (b - a).total_seconds() > 0
            ]
            if len(gaps) < BEACON_MIN_CONNECTIONS - 1:
                continue
            mean = sum(gaps) / len(gaps)
            if mean < BEACON_MIN_INTERVAL_SECONDS:
                continue
            # Regularity, not frequency: a human browsing produces wildly
            # uneven gaps, an implant on a timer does not.
            jitter = max(abs(gap - mean) for gap in gaps) / mean
            if jitter > BEACON_MAX_JITTER_RATIO:
                continue
            out.append(
                (
                    "PERIODIC-BEACON",
                    "Regular repeated contact with one external host",
                    "high",
                    f"{src} contacted {dst}:{port} {len(ordered)} times at a near-constant "
                    f"{mean:.0f}s interval (jitter {jitter:.0%}). Machine-regular timing is "
                    f"characteristic of an implant checking in.",
                    event,
                )
            )

        for _digest, seen in self.secrets.items():
            protocols = {protocol for _event, protocol in seen}
            if len(protocols) < 2:
                continue
            first_event = seen[0][0]
            out.append(
                (
                    "CREDENTIAL-REUSE",
                    "One credential used across several protocols",
                    "high",
                    f"The same password was observed on {', '.join(sorted(protocols))}. Reuse turns "
                    f"a single cleartext disclosure into access everywhere that credential is "
                    f"accepted.",
                    first_event,
                )
            )

        return out


def _aggregate_rules(events):
    """Convenience wrapper over _AggregateState for callers that already have
    every event in hand (tests, mostly)."""
    state = _AggregateState()
    for event in events:
        state.feed(event)
    yield from state.results()


def scan_case(store):
    """Recompute every detection for the whole case (all events, not just
    newly parsed ones - same reasoning as correlation) and persist via
    CaseStore.replace_detections. Returns the list of detection dicts."""
    from datetime import datetime, timezone

    detected_at = datetime.now(timezone.utc)
    # One streaming pass drives both rule kinds. Loading every event first
    # cost hundreds of megabytes on a real capture, and nothing here needs
    # random access - the per-event rules are stateless and the aggregate
    # ones keep their own small accumulators.
    aggregate = _AggregateState()
    network = _NetworkAggregateState()
    detections = []
    for event in store.iter_events():
        aggregate.feed(event)
        network.feed(event)
        for rule_id, rule_name, severity, description in itertools.chain(
            _rules_for_event(event), _network_rules_for_event(event)
        ):
            detections.append(
                {
                    "detection_id": f"DET-{rule_id}-{event.event_id}",
                    "rule_id": rule_id,
                    "rule_name": rule_name,
                    "severity": severity,
                    "event_id": event.event_id,
                    "evidence_id": event.evidence_id,
                    "description": description,
                    "detected_at": detected_at,
                }
            )

    for rule_id, rule_name, severity, description, event in itertools.chain(
        aggregate.results(), network.results()
    ):
        detections.append(
            {
                # Keyed by the representative event so re-running analyze on
                # unchanged evidence produces the same detection_id.
                "detection_id": f"DET-{rule_id}-{event.event_id}",
                "rule_id": rule_id,
                "rule_name": rule_name,
                "severity": severity,
                "event_id": event.event_id,
                "evidence_id": event.evidence_id,
                "description": description,
                "detected_at": detected_at,
            }
        )

    store.replace_detections(detections)
    return detections
