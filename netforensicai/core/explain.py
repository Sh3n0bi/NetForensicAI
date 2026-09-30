"""Plain language for people new to network forensics.

Wireshark's vocabulary - "TCP stream 5, FTP-DATA, 9 packets", "tls",
"network_connection" - is exact and, to someone new, opaque. This module is
the one place that turns it into words: a glossary of protocols (what each one
is, whether its content can be read on the wire), plain names for the event
types the tool produces, and describe_stream(), which says what a conversation
was in a sentence.

Deterministic and offline: no model writes these words, so they can be trusted
the same way the detections are. The optional AI explanation is a separate,
cited path (core/chat.py).
"""

import ipaddress
import re

# name -> (display name, what it is, encrypted?)  encrypted: True / False /
# None (depends, or not applicable). Keys are lower-case Wireshark protocol
# names; versions are stripped before lookup (see _canonical).
PROTOCOLS = {
    "eth": ("Ethernet", "The local network link a packet travelled on.", None),
    "arp": ("ARP", "How devices on a local network find each other's hardware addresses.", False),
    "ip": ("IPv4", "The addressing that gets packets from one computer to another.", None),
    "ipv6": ("IPv6", "The newer form of internet addressing.", None),
    "icmp": ("ICMP", "Network control messages such as ping. Can hide data in its payload.", False),
    "tcp": ("TCP", "A reliable two-way connection that most applications run on.", None),
    "udp": ("UDP", "Quick one-shot messages, used by DNS, streaming and games.", None),
    "dns": ("DNS", "Looking up a website's name to find its address - the internet's phone book.", False),
    "mdns": ("Multicast DNS", "Devices announcing their names on the local network.", False),
    "llmnr": ("LLMNR", "Windows asking the local network for a name; attackers can answer it to steal passwords.", False),
    "nbns": ("NetBIOS name service", "Old Windows name lookups on the local network; leaks computer names.", False),
    "dhcp": ("DHCP", "A device getting its network address when it joins a network.", False),
    "http": ("HTTP", "Web traffic without encryption - pages, forms and passwords are readable.", False),
    "http2": ("HTTP/2", "A faster form of web traffic, usually inside TLS.", None),
    "tls": ("TLS", "Encrypted traffic (the padlock in a browser). The content cannot be read, only who talked and how much.", True),
    "ssl": ("SSL", "An old form of TLS encryption.", True),
    "quic": ("QUIC", "Encrypted web traffic over UDP, used by many modern sites.", True),
    "ftp": ("FTP", "An old way to move files. Logins and commands are sent unencrypted.", False),
    "ftp-data": ("FTP-DATA", "The channel FTP uses to actually move a file. Unencrypted - the file can be recovered.", False),
    "tftp": ("TFTP", "A very simple file transfer with no login at all.", False),
    "ssh": ("SSH", "An encrypted remote login or file copy.", True),
    "telnet": ("Telnet", "An unencrypted remote login - everything typed, including passwords, is readable.", False),
    "rdp": ("RDP", "Windows Remote Desktop - someone controlling a computer remotely.", True),
    "smtp": ("SMTP", "Sending email. Often unencrypted, so messages and attachments can be recovered.", False),
    "imf": ("Email message", "The content of an email carried over SMTP.", False),
    "pop": ("POP3", "Downloading email; the login can be unencrypted.", False),
    "imap": ("IMAP", "Reading email on a server; the login can be unencrypted.", False),
    "smb": ("SMB", "Windows file sharing - opening and copying files on another computer.", None),
    "smb2": ("SMB2", "Windows file sharing - opening and copying files on another computer.", None),
    "nbss": ("NetBIOS session", "The older wrapper Windows file sharing runs inside.", None),
    "kerberos": ("Kerberos", "Windows domain logins. Attackers abuse it to crack service passwords.", None),
    "ntlmssp": ("NTLM", "An older Windows login method; its exchanges can be relayed or cracked.", None),
    "ldap": ("LDAP", "Looking up users and computers in a directory such as Active Directory.", False),
    "snmp": ("SNMP", "Managing network devices; its 'community string' works like a password sent in the clear.", False),
    "ntp": ("NTP", "Setting a computer's clock.", False),
    "ssdp": ("SSDP", "Devices advertising themselves on the local network (UPnP).", False),
    "sip": ("SIP", "Setting up internet phone calls.", False),
    "rtp": ("RTP", "Audio or video of a call or stream.", False),
    "mysql": ("MySQL", "Talking to a MySQL database.", None),
    "pgsql": ("PostgreSQL", "Talking to a PostgreSQL database.", None),
    "tds": ("SQL Server", "Talking to a Microsoft SQL Server database.", None),
    "websocket": ("WebSocket", "A long-lived two-way web connection.", None),
    "data": ("Raw data", "Bytes Wireshark could not identify as any protocol.", None),
    "data-text-lines": ("Text lines", "Plain text carried inside another protocol.", None),
    "urlencoded-form": ("Web form", "Values typed into a web form and submitted.", False),
    "media": ("File content", "A file's bytes carried inside another protocol.", None),
    "json": ("JSON", "Structured data exchanged by apps and websites.", None),
    "xml": ("XML", "Structured data, often from older web services.", None),
}

# event_type -> plain label
EVENT_TYPES = {
    "network_connection": "Network connection",
    "dns_query": "Website name lookup",
    "dns_response": "Name lookup answer",
    "http_request": "Web request",
    "http_response": "Web response",
    "tls_handshake": "Start of an encrypted connection",
    "file_transfer": "File recovered from traffic",
    "file_access": "File opened on a share",
    "credential_exposure": "Password sent without encryption",
    "authentication": "Login attempt",
    "anomaly": "Unusual packet (statistical outlier)",
    "process_start": "Program started",
    "process_stop": "Program stopped",
    "file_created": "File created",
    "logon_success": "Successful login",
    "logon_failure": "Failed login",
    "logoff": "Logoff",
    "explicit_credential_logon": "Login with someone else's credentials",
    "special_privileges_logon": "Administrator-level login",
    "service_installed": "Service installed",
    "scheduled_task_created": "Scheduled task created",
    "scheduled_task_updated": "Scheduled task changed",
    "user_account_created": "User account created",
    "user_account_enabled": "User account enabled",
    "user_account_deleted": "User account deleted",
    "password_reset": "Password reset",
    "group_member_added": "Added to a group",
    "account_locked_out": "Account locked out",
    "kerberos_tgt_request": "Domain login ticket requested",
    "kerberos_service_ticket": "Service ticket requested",
    "kerberos_preauth_failure": "Domain login failed",
    "ntlm_authentication": "NTLM login check",
    "audit_log_cleared": "Security log cleared",
    "event_log_cleared": "Event log cleared",
    "powershell_script_block": "PowerShell code ran",
}

# The protocols Wireshark reports that say least; skipped when choosing the
# one word that best names what a conversation was.
_TRANSPORT = {"tcp", "udp", "ip", "ipv6", "eth", "data"}
_VERSION = re.compile(r"(v?\d+(\.\d+)*)$")


def _canonical(name):
    """'TLSv1.2' -> 'tls', 'HTTP/JSON' -> 'http', 'SSLv3' -> 'ssl'."""
    name = (name or "").strip().lower().split("/")[0]
    if name in PROTOCOLS:
        return name
    stripped = _VERSION.sub("", name).rstrip("v")
    return stripped if stripped in PROTOCOLS else name


def protocol_info(name):
    """{name, what, encrypted} for a Wireshark protocol name, or None."""
    entry = PROTOCOLS.get(_canonical(name))
    if entry is None:
        return None
    display, what, encrypted = entry
    return {"name": display, "what": what, "encrypted": encrypted}


def glossary():
    """Everything the UI needs to explain terms, keyed as the tool emits them."""
    return {
        "protocols": {key: {"name": v[0], "what": v[1], "encrypted": v[2]} for key, v in PROTOCOLS.items()},
        "event_types": dict(EVENT_TYPES),
    }


def event_label(event_type):
    if event_type in EVENT_TYPES:
        return EVENT_TYPES[event_type]
    if event_type and event_type.startswith("windows_event:"):
        return "Windows event (" + event_type.split(":", 1)[1] + ")"
    return (event_type or "event").replace("_", " ").capitalize()


# The ranges that really are someone's own network (RFC 1918, carrier-grade
# NAT, IPv6 unique-local). Not ipaddress.is_private, which also counts
# documentation and benchmarking ranges.
_LOCAL_NETWORKS = tuple(
    ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "fc00::/7")
)


def _host(endpoint):
    """(address, where) - where is a phrase a newcomer understands."""
    address = (endpoint or "").rsplit(":", 1)[0].strip("[]") if endpoint and endpoint.count(":") <= 1 else (endpoint or "")
    if endpoint and endpoint.count(":") > 1 and "]" in endpoint:
        address = endpoint.split("]")[0].strip("[")
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return address or "an unknown host", "unknown"
    if ip.is_loopback:
        return address, "this same computer"
    if ip.is_link_local or any(ip in net for net in _LOCAL_NETWORKS if net.version == ip.version):
        return address, "on your network"
    if ip.is_multicast:
        return address, "a group address"
    if ip.is_global:
        return address, "on the internet"
    # Documentation, benchmarking and other reserved ranges: Python calls
    # these "private", but they are not anyone's local network.
    return address, "a reserved address"


def _size(n):
    for unit in ("bytes", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:,} {unit}" if unit == "bytes" else f"{n:,.1f} {unit}"
        n /= 1024
    return f"{n} bytes"


def main_protocol(applications):
    """The single most telling protocol in a conversation's list."""
    names = [a for a in applications or [] if _canonical(a) not in _TRANSPORT]
    return names[-1] if names else (applications[0] if applications else None)


def describe_stream(summary):
    """What one conversation was, in a sentence plus supporting points.

    `summary` is a StreamSummary or its dict. Says who talked to whom (and
    whether each side is on this network or the internet), which way the
    data mostly went, what the protocol is for, and whether the content can
    be read.
    """
    data = summary.to_dict() if hasattr(summary, "to_dict") else dict(summary)
    a, where_a = _host(data.get("endpoint_a"))
    b, where_b = _host(data.get("endpoint_b"))
    sent, received = data.get("bytes_a_to_b") or 0, data.get("bytes_b_to_a") or 0
    total = data.get("bytes") or (sent + received)
    proto = main_protocol(data.get("applications"))
    info = protocol_info(proto) if proto else None
    proto_name = info["name"] if info else (proto or data.get("protocol", "").upper())

    who_a = f"{a} ({where_a})"
    who_b = f"{b} ({where_b})"
    if sent and received and min(sent, received) / max(sent, received) >= 0.2:
        headline = f"{who_a} and {who_b} exchanged {_size(total)} using {proto_name}."
    elif sent >= received:
        headline = f"{who_a} sent {_size(sent or total)} to {who_b} using {proto_name}."
    else:
        headline = f"{who_b} sent {_size(received)} to {who_a} using {proto_name}."

    points = []
    if info:
        points.append(f"{info['name']}: {info['what']}")
    encrypted = info["encrypted"] if info else None
    if encrypted is False:
        points.append("Not encrypted - anyone on the path could read this conversation, and so can you.")
    elif encrypted is True:
        points.append("Encrypted - only who talked, when and how much is visible, not what was said.")
    if where_a == "on your network" and where_b == "on the internet" and sent > 4 * max(received, 1) and sent > 1024:
        points.append("Mostly outgoing: data left your network - check what it was.")
    return {"headline": headline, "points": points, "protocol": proto_name, "encrypted": encrypted}
