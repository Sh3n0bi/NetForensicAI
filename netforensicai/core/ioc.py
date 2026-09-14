"""Indicators of compromise: import a threat-intelligence feed into a case
and find every place the evidence touches it.

This is the first thing an analyst does with intel - "does anything in
here match what we were sent?" - and doing it by hand means grepping a
capture for a list of addresses, which misses subdomains, misses defanged
indicators copied out of a report, and leaves no record of which intel
the conclusion rested on.

THREE DECISIONS SHAPE THIS MODULE.

MATCHES ARE DETECTIONS, NOT A SIDE TABLE. Every analyze rebuilds the
detections table from scratch, so anything written there from outside
scan_case would silently disappear on the next run. Indicators are stored
in the case; matching runs inside the same pass as every other rule. The
result reaches the story, the report and the dashboard with no extra
wiring - and a match found today is still there after tomorrow's analyze.

ONE FINDING PER INDICATOR, NOT PER PACKET. A known-bad address in a busy
capture can appear in thousands of flows. Thousands of identical rows bury
the one fact that matters - THIS indicator was seen - so each indicator
produces one detection that states how many events touched it and when.

A BAD FEED IS REJECTED LINE BY LINE, AND SAYS WHY. Feeds are messy: blank
lines, comments, defanged values, private addresses, a /8 someone pasted
by mistake. A broad CIDR is the dangerous one - a single "10.0.0.0/8" line
would flag every internal flow and teach the analyst to ignore the rule.
Every rejected line is reported with its reason rather than skipped
silently, because "we imported 4,000 indicators" is only meaningful next
to "and refused 37, here is why".

Nothing here touches the network. A feed is a file the investigator
supplies; this module never fetches one.
"""

import csv
import hashlib
import io
import ipaddress
import json
import re
from dataclasses import dataclass, field
from urllib.parse import urlsplit, urlunsplit

IOC_TYPES = ("ip", "cidr", "domain", "url", "md5", "sha1", "sha256", "email")

# Largest feed accepted, and most indicators kept from one. Generous for
# any real feed; the point is that a mistaken multi-gigabyte upload fails
# with a message instead of exhausting memory.
MAX_FEED_BYTES = 64 * 1024 * 1024
MAX_INDICATORS = 500_000

# A network broader than this is refused. A /16 is already 65,536
# addresses; anything wider in a threat feed is almost always a mistake,
# and one that would match large parts of a normal network.
MIN_IPV4_PREFIX = 16
MIN_IPV6_PREFIX = 48

# How confident a match on each type is, as a severity. An exact file hash
# or URL identifies one thing. An address does not: shared hosting and
# CDNs put unrelated sites behind one IP, so a feed's bad address is often
# also somebody's harmless one.
TYPE_SEVERITY = {
    "md5": "high",
    "sha1": "high",
    "sha256": "high",
    "url": "high",
    "domain": "high",
    "email": "medium",
    "ip": "medium",
    "cidr": "medium",
}

_HEX = re.compile(r"^[0-9a-f]+$")
_HASH_LENGTHS = {32: "md5", 40: "sha1", 64: "sha256"}
_DOMAIN = re.compile(
    r"^(?=.{1,253}$)(?!-)(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,62}$"
)
_SINGLE_LABEL = re.compile(r"^[a-z0-9_-]{1,63}$")
_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+$")

# Defanging, as it appears in reports and tickets: hxxp://evil[.]com,
# 1.2.3[.]4, user[@]example(.)org. Analysts paste these straight from a
# PDF, and an importer that refuses them - or worse, accepts them
# verbatim and never matches - fails the most common real input.
_REFANG = (
    (re.compile(r"^hxxp", re.IGNORECASE), "http"),
    (re.compile(r"^fxp", re.IGNORECASE), "ftp"),
    (re.compile(r"\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)", re.IGNORECASE), "."),
    (re.compile(r"\[:\]"), ":"),
    (re.compile(r"\[@\]|\[at\]|\(at\)", re.IGNORECASE), "@"),
    (re.compile(r"\[/\]"), "/"),
)

# MISP attribute types, mapped to ours. Composite types ("filename|sha256")
# carry the indicator in one half; the index says which.
_MISP_TYPES = {
    "ip-src": ("ip", None), "ip-dst": ("ip", None),
    "ip-src|port": ("ip", 0), "ip-dst|port": ("ip", 0),
    "domain": ("domain", None), "hostname": ("domain", None),
    "domain|ip": ("domain", 0),
    "url": ("url", None), "uri": ("url", None), "link": ("url", None),
    "md5": ("md5", None), "sha1": ("sha1", None), "sha256": ("sha256", None),
    "filename|md5": ("md5", 1), "filename|sha1": ("sha1", 1), "filename|sha256": ("sha256", 1),
    "email": ("email", None), "email-src": ("email", None), "email-dst": ("email", None),
}

# STIX 2.1 pattern comparisons this importer understands.
_STIX_PATH_TYPES = {
    "ipv4-addr:value": "ip",
    "ipv6-addr:value": "ip",
    "domain-name:value": "domain",
    "url:value": "url",
    "email-addr:value": "email",
    "file:hashes.md5": "md5",
    "file:hashes.'md5'": "md5",
    "file:hashes.'sha-1'": "sha1",
    "file:hashes.sha1": "sha1",
    "file:hashes.'sha-256'": "sha256",
    "file:hashes.sha256": "sha256",
}
_STIX_COMPARISON = re.compile(r"([a-z0-9-]+:[a-z0-9_.'\-]+)\s*=\s*'((?:[^'\\]|\\.)*)'", re.IGNORECASE)
# Pattern operators whose meaning depends on MORE than one comparison.
# "[a] AND [b]" is an indicator only when both hold; importing a and b
# separately would match far more than the author meant.
_STIX_LITERAL = re.compile(r"'(?:[^'\\]|\\.)*'")
_STIX_UNSUPPORTED = re.compile(r"\b(AND|FOLLOWEDBY|WITHIN|REPEATS|START|STOP|NOT)\b|!=|\bLIKE\b|\bMATCHES\b")


class IocError(Exception):
    """Raised when a feed cannot be read at all (as opposed to individual
    indicators being rejected, which is reported, not raised)."""


@dataclass
class Indicator:
    ioc_type: str
    value: str
    description: str = ""

    @property
    def ioc_id(self):
        digest = hashlib.sha256(f"{self.ioc_type}:{self.value}".encode("utf-8")).hexdigest()
        return f"IOC-{self.ioc_type}-{digest[:12]}"


@dataclass
class ImportResult:
    """What a feed produced. `rejected` is (raw value, reason) - kept so the
    investigator can see what was refused, not merely how much."""

    indicators: list = field(default_factory=list)
    rejected: list = field(default_factory=list)
    skipped_non_ids: int = 0
    duplicates: int = 0
    feed_format: str = "text"

    def counts_by_type(self):
        counts = {}
        for indicator in self.indicators:
            counts[indicator.ioc_type] = counts.get(indicator.ioc_type, 0) + 1
        return counts


# --- normalization -------------------------------------------------------


def refang(value):
    text = str(value).strip().strip("\"'")
    for pattern, replacement in _REFANG:
        text = pattern.sub(replacement, text)
    return text


def normalize_domain(value):
    return str(value).strip().rstrip(".").lower()


def normalize_url(value):
    """Scheme and host are case-insensitive; the path is not. A default
    port is dropped so http://x/ and http://x:80/ are the same URL."""
    parts = urlsplit(str(value).strip())
    host = (parts.hostname or "").rstrip(".").lower()
    port = parts.port
    scheme = parts.scheme.lower()
    if port and not ((scheme == "http" and port == 80) or (scheme == "https" and port == 443)):
        host = f"{host}:{port}"
    path = parts.path or "/"
    return urlunsplit((scheme, host, path, parts.query, ""))


def classify(raw, hinted_type=None):
    """Return (Indicator, None) or (None, reason).

    `hinted_type` comes from a feed that states the type. It is trusted
    only as far as the value agrees with it: a "sha256" column holding 32
    hex characters is an md5, and silently storing it as a sha256 would
    guarantee it never matches.
    """
    value = refang(raw)
    if not value:
        return None, "empty"

    lowered = value.lower()

    # Hashes
    if _HEX.match(lowered) and len(lowered) in _HASH_LENGTHS:
        detected = _HASH_LENGTHS[len(lowered)]
        if hinted_type in ("md5", "sha1", "sha256") and hinted_type != detected:
            return None, f"declared {hinted_type} but is {len(lowered)} hex characters ({detected})"
        return Indicator(detected, lowered), None

    # URLs
    if "://" in value:
        parts = urlsplit(value)
        if parts.scheme.lower() not in ("http", "https", "ftp") or not parts.hostname:
            return None, "not an http, https or ftp URL"
        return Indicator("url", normalize_url(value)), None

    # Email
    if "@" in value:
        if _EMAIL.match(value) and _DOMAIN.match(normalize_domain(value.split("@", 1)[1])):
            return Indicator("email", lowered), None
        return None, "not a valid email address"

    # Addresses and networks
    try:
        if "/" in value:
            network = ipaddress.ip_network(value, strict=False)
            minimum = MIN_IPV4_PREFIX if network.version == 4 else MIN_IPV6_PREFIX
            if network.prefixlen < minimum:
                return None, (
                    f"/{network.prefixlen} is too broad - it would match {network.num_addresses:,} "
                    f"addresses (narrowest accepted: /{minimum})"
                )
            if network.num_addresses == 1:
                return Indicator("ip", str(network.network_address)), None
            return Indicator("cidr", str(network)), None
        address = ipaddress.ip_address(value)
        if address.is_unspecified or address.is_loopback:
            return None, "loopback or unspecified address"
        return Indicator("ip", str(address)), None
    except ValueError:
        pass

    # Domains
    domain = normalize_domain(value)
    if "." not in domain and _SINGLE_LABEL.match(domain):
        # Checked before the domain pattern, which requires a dot and would
        # otherwise refuse "localhost" with a vaguer reason than the real one.
        return None, "single-label name (would match too broadly)"
    if _DOMAIN.match(domain):
        if "." not in domain:
            return None, "single-label name (would match too broadly)"
        return Indicator("domain", domain), None

    return None, "not a recognisable IP, network, domain, URL, hash or email"


# --- feed formats --------------------------------------------------------


def _add(result, seen, raw, hinted_type=None, description=""):
    indicator, reason = classify(raw, hinted_type)
    if indicator is None:
        result.rejected.append((str(raw)[:200], reason))
        return
    if indicator.ioc_id in seen:
        result.duplicates += 1
        return
    if len(result.indicators) >= MAX_INDICATORS:
        raise IocError(f"Feed has more than {MAX_INDICATORS:,} indicators; split it into smaller files.")
    indicator.description = str(description or "")[:300]
    seen.add(indicator.ioc_id)
    result.indicators.append(indicator)


def _parse_text(text, result, seen):
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(("#", "//", ";")):
            continue
        # "value  # comment" is common in hand-kept lists.
        value, _, comment = line.partition(" #")
        _add(result, seen, value.strip(), description=comment.strip())


_CSV_VALUE_COLUMNS = ("indicator", "value", "ioc", "observable", "ip", "domain", "url", "hash")
_CSV_TYPE_COLUMNS = ("type", "indicator_type", "ioc_type", "kind")
_CSV_DESC_COLUMNS = ("description", "comment", "comments", "tags", "notes", "threat")


def _parse_csv(text, result, seen):
    reader = csv.DictReader(io.StringIO(text))
    header = {name.strip().lower(): name for name in (reader.fieldnames or []) if name}
    value_col = next((header[c] for c in _CSV_VALUE_COLUMNS if c in header), None)
    if value_col is None:
        # No recognisable header: rows of "indicator, note...". The first
        # column is the indicator and the rest its description. Splitting
        # every cell into its own indicator would report each note as a
        # rejected line, burying the rejections that actually matter.
        for row in csv.reader(io.StringIO(text)):
            if not row or not row[0].strip() or row[0].strip().startswith("#"):
                continue
            value, _, comment = row[0].partition(" #")
            notes = [comment.strip()] + [c.strip() for c in row[1:]]
            _add(result, seen, value.strip(), description=", ".join(n for n in notes if n))
        return
    type_col = next((header[c] for c in _CSV_TYPE_COLUMNS if c in header), None)
    desc_col = next((header[c] for c in _CSV_DESC_COLUMNS if c in header), None)
    for row in reader:
        raw = (row.get(value_col) or "").strip()
        if not raw:
            continue
        hinted = _hint_from_label((row.get(type_col) or "") if type_col else "")
        _add(result, seen, raw, hinted, row.get(desc_col) if desc_col else "")


def _hint_from_label(label):
    label = label.strip().lower().replace("_", "-")
    if label in ("md5", "sha1", "sha-1", "sha256", "sha-256"):
        return label.replace("-", "")
    return None


def _parse_misp(data, result, seen):
    """MISP event exports: {"Event": ...}, {"response": [{"Event": ...}]},
    or a bare list of attributes.

    Attributes with to_ids = false are SKIPPED, and counted. That flag is
    how a MISP analyst says "this is context, not something to alert on" -
    the benign resolver an implant used, the victim's own mail server. A
    matcher that ignored it would alert on exactly what the author said not
    to.
    """
    events = []
    if isinstance(data, dict) and "response" in data:
        events = [item.get("Event", item) for item in data.get("response") or []]
    elif isinstance(data, dict) and "Event" in data:
        events = [data["Event"]]
    elif isinstance(data, list):
        events = [{"Attribute": data}]

    for event in events:
        attributes = list(event.get("Attribute") or [])
        for obj in event.get("Object") or []:
            attributes.extend(obj.get("Attribute") or [])
        info = event.get("info") or ""
        for attribute in attributes:
            mapped = _MISP_TYPES.get(str(attribute.get("type", "")).lower())
            if mapped is None:
                continue
            if attribute.get("to_ids") in (False, 0, "0", "false"):
                result.skipped_non_ids += 1
                continue
            ioc_type, index = mapped
            raw = str(attribute.get("value", ""))
            if index is not None:
                pieces = raw.split("|")
                raw = pieces[index] if len(pieces) > index else ""
            description = attribute.get("comment") or info
            _add(result, seen, raw, ioc_type if ioc_type in ("md5", "sha1", "sha256") else None, description)


def _parse_stix(data, result, seen):
    """STIX 2.1 bundles: `indicator` objects with a pattern, and bare
    cyber-observable objects.

    Only patterns made of single comparisons, optionally OR'd together,
    are imported. A pattern using AND, FOLLOWEDBY or a time window means
    "all of these, together" - splitting it into separate indicators would
    match far more than its author meant - so it is rejected with that
    reason rather than approximated.
    """
    objects = data.get("objects", []) if isinstance(data, dict) else data
    for obj in objects or []:
        kind = obj.get("type")
        if kind == "indicator":
            pattern = obj.get("pattern") or ""
            if obj.get("pattern_type", "stix") != "stix":
                result.rejected.append((pattern[:200], f"{obj.get('pattern_type')} patterns are not supported"))
                continue
            # Test operators OUTSIDE quoted literals only: a URL value that
            # happens to contain "AND" is still a single comparison.
            if _STIX_UNSUPPORTED.search(_STIX_LITERAL.sub("''", pattern)):
                result.rejected.append(
                    (pattern[:200], "compound pattern (AND / FOLLOWEDBY / time window) cannot be split safely")
                )
                continue
            comparisons = _STIX_COMPARISON.findall(pattern)
            if not comparisons:
                result.rejected.append((pattern[:200], "no supported comparison in pattern"))
                continue
            for path, raw in comparisons:
                mapped = _STIX_PATH_TYPES.get(path.lower())
                if mapped is None:
                    result.rejected.append((f"{path} = {raw}"[:200], f"unsupported object path {path}"))
                    continue
                hinted = mapped if mapped in ("md5", "sha1", "sha256") else None
                _add(result, seen, raw.replace("\\'", "'"), hinted, obj.get("name") or obj.get("description"))
        elif kind in ("ipv4-addr", "ipv6-addr", "domain-name", "url", "email-addr"):
            _add(result, seen, obj.get("value", ""))
        elif kind == "file":
            for algorithm, digest in (obj.get("hashes") or {}).items():
                _add(result, seen, digest, _hint_from_label(algorithm), obj.get("name"))


def _looks_like_csv(text, filename):
    """Decide text versus CSV from the first line that carries data.

    Judging the first line of the file was wrong in exactly the way real
    feeds break it: "# Campaign feed, pasted from a vendor PDF" has a
    comma, flipped the whole feed to CSV, left inline notes attached to
    their values, and got three of four good indicators refused. The
    extension is honoured when it is unambiguous.
    """
    name = filename.lower()
    if name.endswith(".csv"):
        return True
    if name.endswith((".txt", ".list", ".ioc")):
        return False
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(("#", "//", ";")):
            continue
        return "," in line.partition(" #")[0]
    return False


def parse_feed(content, filename=""):
    """Parse a feed from bytes or text. The format is taken from the
    content, with the filename as a tie-breaker - feeds are routinely
    saved with the wrong extension."""
    if isinstance(content, bytes):
        if len(content) > MAX_FEED_BYTES:
            raise IocError(f"Feed is larger than {MAX_FEED_BYTES // (1024 * 1024)} MB.")
        text = content.decode("utf-8-sig", errors="replace")
    else:
        text = content

    result = ImportResult()
    seen = set()
    stripped = text.lstrip()

    if stripped.startswith(("{", "[")):
        try:
            data = json.loads(stripped)
        except json.JSONDecodeError as e:
            raise IocError(f"File looks like JSON but does not parse: {e}")
        is_stix = (isinstance(data, dict) and data.get("type") == "bundle") or (
            isinstance(data, dict) and any(o.get("spec_version") for o in data.get("objects", []) if isinstance(o, dict))
        )
        if is_stix:
            result.feed_format = "stix"
            _parse_stix(data, result, seen)
        else:
            result.feed_format = "misp"
            _parse_misp(data, result, seen)
    elif _looks_like_csv(text, filename):
        result.feed_format = "csv"
        _parse_csv(text, result, seen)
    else:
        _parse_text(text, result, seen)

    return result


def feed_sha256(content):
    if isinstance(content, str):
        content = content.encode("utf-8")
    return hashlib.sha256(content).hexdigest()


# --- matching ------------------------------------------------------------


class Matcher:
    """Tests events against a case's indicators.

    Built once per scan. Lookups are set membership, so the cost per event
    is independent of how many indicators were imported - except networks,
    which are tested one by one and are typically few.
    """

    def __init__(self, indicators):
        self.exact = {}      # (type, value) -> indicator
        self.domains = {}    # domain -> indicator
        self.networks = []   # (network, indicator)
        for indicator in indicators:
            if indicator["ioc_type"] == "domain":
                self.domains[indicator["value"]] = indicator
            elif indicator["ioc_type"] == "cidr":
                self.networks.append((ipaddress.ip_network(indicator["value"]), indicator))
            else:
                self.exact[(indicator["ioc_type"], indicator["value"])] = indicator

    def __bool__(self):
        return bool(self.exact or self.domains or self.networks)

    def _domain(self, name):
        """A match on the domain OR any parent of it: an indicator for
        evil.top should catch cdn.evil.top, which is how the same
        infrastructure usually shows up in traffic."""
        name = normalize_domain(name)
        labels = name.split(".")
        for i in range(len(labels) - 1):
            hit = self.domains.get(".".join(labels[i:]))
            if hit:
                return hit
        return None

    def _address(self, value):
        try:
            address = ipaddress.ip_address(str(value))
        except ValueError:
            return None
        hit = self.exact.get(("ip", str(address)))
        if hit:
            return hit
        for network, indicator in self.networks:
            if address.version == network.version and address in network:
                return indicator
        return None

    def matches(self, event):
        """Yield (indicator, field, observed value) for each indicator this
        event touches. One event may touch several - an HTTP request to a
        bad URL on a bad domain at a bad address is three matches, each of
        which an analyst may want to see independently."""
        seen = set()

        def emit(indicator, field_name, observed):
            if indicator and indicator["ioc_id"] not in seen:
                seen.add(indicator["ioc_id"])
                return (indicator, field_name, observed)
            return None

        candidates = []
        for field_name in ("src_ip", "dst_ip"):
            value = getattr(event, field_name, None)
            if value:
                candidates.append(emit(self._address(value), field_name, value))

        domain = getattr(event, "domain", None)
        if domain:
            candidates.append(emit(self._domain(domain), "domain", domain))

        url = getattr(event, "url", None)
        if url and "://" in str(url):
            try:
                normalized = normalize_url(url)
            except ValueError:
                normalized = None
            if normalized:
                candidates.append(emit(self.exact.get(("url", normalized)), "url", url))
                host = urlsplit(normalized).hostname
                if host:
                    candidates.append(emit(self._domain(host), "url", url))

        file_hash = getattr(event, "file_hash", None)
        if file_hash:
            lowered = str(file_hash).strip().lower()
            ioc_type = _HASH_LENGTHS.get(len(lowered))
            if ioc_type:
                candidates.append(emit(self.exact.get((ioc_type, lowered)), "file_hash", file_hash))

        user = getattr(event, "user", None)
        if user and "@" in str(user):
            candidates.append(emit(self.exact.get(("email", str(user).strip().lower())), "user", user))

        yield from (c for c in candidates if c)


class MatchState:
    """Accumulates matches across a streaming scan into one detection per
    indicator."""

    def __init__(self, indicators):
        self.matcher = Matcher(indicators)
        self.hits = {}  # ioc_id -> [indicator, first_event, count, first_ts, last_ts, fields]

    def feed(self, event):
        if not self.matcher:
            return
        for indicator, field_name, observed in self.matcher.matches(event):
            entry = self.hits.get(indicator["ioc_id"])
            if entry is None:
                entry = self.hits[indicator["ioc_id"]] = [indicator, event, 0, None, None, {}]
            entry[2] += 1
            if event.timestamp:
                if entry[3] is None or event.timestamp < entry[3]:
                    entry[3] = event.timestamp
                    entry[1] = event
                if entry[4] is None or event.timestamp > entry[4]:
                    entry[4] = event.timestamp
            entry[5][field_name] = str(observed)

    def results(self):
        """Yield (rule_id, rule_name, severity, description, event, ioc_id)."""
        for ioc_id, (indicator, event, count, first, last, fields) in sorted(self.hits.items()):
            # Name the field alone when the observed value IS the indicator;
            # repeating a long URL twice in one sentence helps nobody.
            observed = ", ".join(
                name if str(seen_value).lower() == str(indicator['value']).lower() else f"{name} {seen_value}"
                for name, seen_value in sorted(fields.items())
            )
            # Compared at the precision shown: "between 22:13:39 and 22:13:39"
            # is noise, which is what comparing raw timestamps produced.
            first_s = first.isoformat(timespec="seconds") if first else None
            last_s = last.isoformat(timespec="seconds") if last else None
            span = f" between {first_s} and {last_s}" if first_s and last_s and first_s != last_s else ""
            source = f" ({indicator['source']})" if indicator.get("source") else ""
            note = f" Feed note: {indicator['description']}." if indicator.get("description") else ""
            description = (
                f"Imported indicator {indicator['ioc_type']} '{indicator['value']}'{source} was seen in "
                f"{count} event(s){span} (matched on {observed}).{note} A feed match says this value was "
                f"reported as malicious somewhere; confirm it is malicious here."
            )
            yield (
                "IOC-MATCH",
                "Known indicator observed",
                TYPE_SEVERITY.get(indicator["ioc_type"], "medium"),
                description,
                event,
                ioc_id,
            )


# --- case operations (shared by the CLI and the web API) ------------------


MAX_REJECTED_REPORTED = 50


def import_into_case(store, case_dir, content, filename, source=None, actor=None):
    """Parse a feed, add its indicators to the case, record it in the chain
    of custody, and re-run detections so matches appear immediately.

    One function for both interfaces so an import from the web UI leaves
    exactly the same custody record as one from the CLI. The record names
    the feed by its SHA-256, not just its filename: "matched against
    feed.csv" is unverifiable months later, a hash is not.
    """
    from datetime import datetime, timezone

    from netforensicai.core import audit
    from netforensicai.core.detections import scan_case

    result = parse_feed(content, filename)
    digest = feed_sha256(content)
    source = (source or filename or "feed")[:120]
    added_at = datetime.now(timezone.utc)

    added = store.add_iocs(
        {
            "ioc_id": indicator.ioc_id,
            "ioc_type": indicator.ioc_type,
            "value": indicator.value,
            "description": indicator.description,
            "source": source,
            "feed_sha256": digest,
            "added_at": added_at,
        }
        for indicator in result.indicators
    )
    already_present = len(result.indicators) - added

    detections = scan_case(store)
    matches = [d for d in detections if d["rule_id"] == "IOC-MATCH"]

    summary = {
        "source": source,
        "feed_format": result.feed_format,
        "feed_sha256": digest,
        "parsed": len(result.indicators),
        "added": added,
        "already_present": already_present,
        "duplicates_in_feed": result.duplicates,
        "skipped_non_ids": result.skipped_non_ids,
        "rejected_count": len(result.rejected),
        "rejected": [{"value": v, "reason": r} for v, r in result.rejected[:MAX_REJECTED_REPORTED]],
        "by_type": result.counts_by_type(),
        "total_indicators": store.count_iocs(),
        "match_count": len(matches),
        "matches": matches,
    }
    audit.record(
        case_dir,
        audit.IOC_IMPORTED,
        {
            "source": source,
            "filename": filename,
            "feed_sha256": digest,
            "feed_format": result.feed_format,
            "added": added,
            "already_present": already_present,
            "rejected": len(result.rejected),
            "skipped_non_ids": result.skipped_non_ids,
            "matches": len(matches),
        },
        actor=actor,
    )
    return summary


def clear_from_case(store, case_dir, source=None, actor=None):
    """Remove indicators (all, or one source's) and re-run detections, so
    matches that rested on them disappear with them."""
    from netforensicai.core import audit
    from netforensicai.core.detections import scan_case

    removed = store.clear_iocs(source=source)
    scan_case(store)
    audit.record(case_dir, audit.IOC_CLEARED, {"source": source, "removed": removed}, actor=actor)
    return removed
