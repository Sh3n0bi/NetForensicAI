"""Credentials crossing the network in the clear.

WHY THIS IS ITS OWN MODULE. Both pcap engines need to answer the same
question and neither can share the other's code: the tshark engine reads
dissected fields and must import nothing that pulls in scapy, while the
scapy engine has only raw bytes and no dissector at all. Left in the two
engines, the rules drifted - credential detection existed in tshark and
silently did not exist in scapy, so CLEARTEXT-CREDENTIALS and
CREDENTIAL-REUSE quietly reported nothing on a machine without Wireshark
installed. That is the worst kind of gap: not a wrong answer, an absent
one.

So the vocabulary and the judgement live here, in a module that imports
nothing beyond the standard library, and each engine supplies what it can
see. tshark passes already-parsed field pairs; scapy passes raw payload
and gets it parsed here.

THE SECRET IS NEVER RETURNED TO THE CASE. `digest()` produces a SHA-256,
which answers the one question that matters across events - "is this the
same credential used somewhere else" - without putting a working password
into a case database, where it would ride along in every export, report
and backup. The plaintext stays in the evidence file, which is already
hashed, read-only, and reachable through content search.
"""

import base64
import hashlib
import re
from urllib.parse import parse_qsl, urlsplit

# Field names that carry a secret, and field names that carry the identity
# it belongs to. Kept as names rather than patterns because a form field
# called "password" is a credential regardless of what its value looks
# like, and a high-entropy string is not one merely for being random.
SECRET_FIELDS = {"password", "passwd", "pwd", "pass", "secret", "token", "api_key", "apikey"}
IDENTITY_FIELDS = {"username", "user", "login", "email", "userid", "uid"}

# Ports whose protocols authenticate without encrypting. A credential seen
# on one of these is disclosed, not merely at risk.
CLEARTEXT_PROTOCOLS = {21: "FTP", 23: "Telnet", 25: "SMTP", 80: "HTTP", 110: "POP3", 143: "IMAP"}

# Line-oriented logins the scapy engine has to read itself, since it has
# no dissector. Telnet is deliberately absent: it negotiates in-band and
# sends a character per packet, so a line-based reader produces confident
# nonsense on it. Reporting nothing is better than that.
_FTP_POP_LINE = re.compile(rb"^(USER|PASS)[ \t]+(.+?)\r?$", re.IGNORECASE | re.MULTILINE)
_IMAP_LOGIN = re.compile(rb"^\S+[ \t]+LOGIN[ \t]+(\S+)[ \t]+(\S+)\r?$", re.IGNORECASE | re.MULTILINE)
_SMTP_AUTH_PLAIN = re.compile(rb"^AUTH[ \t]+PLAIN[ \t]+(\S+)\r?$", re.IGNORECASE | re.MULTILINE)

MAX_SCAN_BYTES = 8192
MAX_VALUE_CHARS = 512


def digest(value):
    """A stable identifier for a secret that is not the secret."""
    return hashlib.sha256(str(value).encode("utf-8", errors="ignore")).hexdigest()


def protocol_for(port, fallback=None):
    return CLEARTEXT_PROTOCOLS.get(port) or (fallback or "?").upper()


def _text(value):
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="replace")
    return str(value)[:MAX_VALUE_CHARS]


def identity_of(pairs):
    """The username a set of field pairs belongs to, if one is present.

    Last one wins: a form that carries both `user` and `email` is
    describing one person, and the later field is the more specific in
    every layout that does this.
    """
    user = None
    for name, value in pairs:
        if str(name).lower() in IDENTITY_FIELDS and value:
            user = _text(value)
    return user


def secrets_in(pairs):
    """The (field, value) pairs that are secrets. Order is preserved so a
    caller reporting them keeps the order they appeared on the wire."""
    found = []
    for name, value in pairs:
        lowered = str(name).lower()
        if not value:
            continue
        if lowered in SECRET_FIELDS or lowered == "authorization":
            found.append((lowered, _text(value)))
    return found


def _basic_auth_identity(value):
    """The username inside an HTTP Basic credential.

    Worth decoding because base64 is an encoding, not a protection - the
    header is as readable as a form field to anyone on the path, and
    naming the account is what makes the finding actionable.
    """
    text = _text(value).strip()
    if not text.lower().startswith("basic "):
        return None
    try:
        decoded = base64.b64decode(text[6:].strip() + "==", validate=False)
    except Exception:
        return None
    decoded = decoded.decode("utf-8", errors="replace")
    return decoded.split(":", 1)[0] or None if ":" in decoded else None


def pairs_from_http_request(payload):
    """Field pairs from one HTTP request: query string, urlencoded body,
    and the Authorization header.

    Requests only, never responses. A response body can contain a login
    FORM - field names, no values - and reporting the page that asks for a
    password as a password crossing the network would be a false positive
    of exactly the kind that teaches people to ignore a rule.
    """
    payload = payload[:MAX_SCAN_BYTES]
    head, _, body = payload.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    pairs = []

    request_line = lines[0].decode("utf-8", errors="replace") if lines else ""
    parts = request_line.split(" ")
    if len(parts) >= 2:
        query = urlsplit(parts[1]).query
        if query:
            pairs.extend(parse_qsl(query, keep_blank_values=False))

    content_type = ""
    authorization = None
    for line in lines[1:]:
        lowered = line.lower()
        if lowered.startswith(b"content-type:"):
            content_type = line[13:].strip().decode("utf-8", errors="replace").lower()
        elif lowered.startswith(b"authorization:"):
            authorization = line[14:].strip().decode("utf-8", errors="replace")

    if body and "x-www-form-urlencoded" in content_type:
        pairs.extend(parse_qsl(body.decode("utf-8", errors="replace"), keep_blank_values=False))

    if authorization:
        identity = _basic_auth_identity(authorization)
        if identity:
            pairs.append(("username", identity))
        pairs.append(("authorization", authorization))

    return pairs


def pairs_from_line_protocol(payload):
    """Field pairs from the line-oriented cleartext logins: FTP, POP3,
    IMAP, and SMTP's self-contained AUTH PLAIN.

    Only ever called on client-to-server payloads - a server's `331
    Password required` is a prompt, not a credential.
    """
    payload = payload[:MAX_SCAN_BYTES]
    pairs = []

    for command, argument in _FTP_POP_LINE.findall(payload):
        name = "password" if command.upper() == b"PASS" else "username"
        pairs.append((name, _text(argument)))

    for user, secret in _IMAP_LOGIN.findall(payload):
        pairs.append(("username", _text(user).strip('"')))
        pairs.append(("password", _text(secret).strip('"')))

    for blob in _SMTP_AUTH_PLAIN.findall(payload):
        # SASL PLAIN is authzid\0authcid\0password, base64-wrapped.
        try:
            decoded = base64.b64decode(blob + b"==", validate=False).split(b"\x00")
        except Exception:
            continue
        if len(decoded) == 3:
            if decoded[1]:
                pairs.append(("username", _text(decoded[1])))
            if decoded[2]:
                pairs.append(("password", _text(decoded[2])))

    return pairs


def scan_payload(payload, dst_port=None, is_http_request=False):
    """Every credential in one client-to-server TCP payload.

    Returns a list of (field, value) pairs plus the identity they belong
    to, as (secrets, user). Callers turn those into events; this decides
    only what counts as a credential.
    """
    if not payload:
        return [], None

    if is_http_request:
        pairs = pairs_from_http_request(payload)
    elif dst_port in CLEARTEXT_PROTOCOLS and dst_port != 80:
        pairs = pairs_from_line_protocol(payload)
    else:
        # Anything else is either encrypted, or a protocol whose framing
        # this module cannot read without guessing. Guessing here produces
        # confident nonsense, so it does not guess.
        return [], None

    return secrets_in(pairs), identity_of(pairs)


def message_for(field, protocol, user):
    """The one sentence that goes on the event, worded identically by both
    engines so a report does not read differently depending on which
    dissector happened to run."""
    return (
        f"A {field} field was transmitted over {protocol} without encryption"
        + (f" for user '{user}'" if user else "")
    )


def reference_for(packet_number, field, protocol, value, engine):
    return {
        "packet_number": packet_number,
        "field": field,
        "protocol": protocol,
        # Identifies the secret across events without being the secret.
        "secret_sha256": digest(value),
        "engine": engine,
    }
