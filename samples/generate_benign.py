"""Generate benign office traffic, for false-positive auditing and for
measuring throughput.

WHY THIS EXISTS. A detection rule tested only against the incident it was
written for will always look perfect. What decides whether anyone keeps
the tool switched on is what it does on the other 99.9% of traffic - and
the traffic that matters is not "obviously fine", it is the traffic that
LOOKS LIKE the incident and is not one:

  - a monitoring agent checking in on a fixed interval        (vs a beacon)
  - a nightly backup pushing gigabytes off-site               (vs exfiltration)
  - a signed installer downloaded from a vendor               (vs a dropper)
  - a login, on a page served over TLS                        (vs a cleartext credential)
  - a corporate domain that happens to sit on a new gTLD      (vs a cheap-TLD C2)

Each of those is generated here on purpose. Some of them SHOULD still
produce a finding - a rule that never fires on legitimate-looking traffic
is usually a rule that never fires - so the audit reports what fired and
the reasoning is judged against it, rather than the generator being tuned
until the number reaches zero.

  python samples/generate_benign.py -o benign.pcap --scale 20

--scale multiplies the volume; scale 1 is roughly a minute of one busy
workstation. The traffic is fabricated end to end and contacts nothing.
"""

import argparse
import random
from pathlib import Path

try:
    from scapy.all import IP, TCP, UDP, DNS, DNSQR, DNSRR, Raw, wrpcap
except ImportError:  # pragma: no cover
    raise SystemExit("This script needs scapy: pip install -e '.[pcap]'")

import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from generate_incident import Clock, Flow, dns  # noqa: E402

SUBNET = "10.20.30."
RESOLVER = "10.20.30.1"
FILE_SERVER = "10.20.30.9"
MONITORING = "10.20.30.11"

# Ordinary destinations. Real registered ranges are avoided in favour of
# addresses chosen for the story; nothing here is contacted.
CDN = "151.101.1.140"
SAAS = "104.18.32.7"
VENDOR = "23.55.61.12"
BACKUP = "52.94.236.248"

SITES = [
    "www.example.com", "docs.example.org", "mail.corp.example", "cdn.example.net",
    "api.saas.example", "status.saas.example", "packages.vendor.example",
    "intranet.corp.example", "search.example.com", "chat.corp.example",
]

# A corporate domain on a new gTLD. Cheap TLDs are used in bulk by
# malware infrastructure AND by ordinary businesses, which is precisely
# why SUSPICIOUS-TLD is rated low rather than high.
GTLD_SITE = "helpdesk.acme.app"


# A TLS 1.2 application-data record header: content type 23, version
# 3.3, then the length. Enough for a dissector to label the flow TLS
# without any of the handshake, which these flows do not need.
TLS_APPLICATION_DATA = bytes([0x17, 0x03, 0x03])


def _record(size, marker):
    return TLS_APPLICATION_DATA + bytes([(size >> 8) & 0xFF, size & 0xFF]) + bytes([marker]) * size


def _https(clock, client, server, sport, records=3, size=1200, gap=0.05, upload=None):
    """An encrypted exchange. Opaque by construction - which is the point:
    most real traffic tells a payload-reading rule nothing at all.

    ASYMMETRIC ON PURPOSE. Browsing sends small requests and receives
    large responses, and getting that backwards is not a cosmetic detail.
    A symmetric generator makes every page load look like a multi-kilobyte
    upload, and OUTBOUND-BULK-TRANSFER then fires on all of it: the first
    run of this audit reported 48 false positives that were entirely an
    artifact of this function, against a rule that was behaving correctly.
    An unrealistic generator does not measure a detector, it measures
    itself.

    `upload` overrides the client-side size, for the cases that genuinely
    do send data outward - a backup, a file share, an attachment.
    """
    flow = Flow(clock, client, server, sport, 443)
    out = upload if upload is not None else 180
    for i in range(records):
        flow.c2s(_record(out, i), gap)
        flow.s2c(_record(size, i), gap)
    return flow.packets


def build(scale=1, seed=7):
    rng = random.Random(seed)
    clock = Clock()
    packets = []
    sport = 40000

    def next_port():
        nonlocal sport
        sport += 1
        return sport

    for round_number in range(scale):
        client = f"{SUBNET}{20 + (round_number % 12)}"

        # --- ordinary web browsing over TLS ---------------------------
        for site in rng.sample(SITES, 5):
            packets += dns(clock, site, CDN, src=client, resolver=RESOLVER)
            packets += _https(clock, client, CDN, next_port(), records=rng.randint(2, 5))

        # --- a corporate domain on a new gTLD -------------------------
        # Expected to trip SUSPICIOUS-TLD. It is rated low for this reason.
        packets += dns(clock, GTLD_SITE, SAAS, src=client, resolver=RESOLVER)
        packets += _https(clock, client, SAAS, next_port())

        # --- a login, over TLS ----------------------------------------
        # The credential is real and completely invisible, which is the
        # correct outcome and the reason CLEARTEXT-CREDENTIALS is worth
        # having: it fires on the absence of encryption, not on the login.
        packets += _https(clock, client, SAAS, next_port(), records=2)

        # --- internal HTTP: an intranet page, no credential -----------
        page = Flow(clock, client, FILE_SERVER, next_port(), 80)
        page.c2s(b"GET /intranet/news HTTP/1.1\r\nHost: intranet.corp.example\r\n"
                 b"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n\r\n")
        page.s2c(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"
                 b"<html><body>Company news</body></html>")
        packets += page.packets

        # --- a signed installer, over TLS -----------------------------
        # An .exe is not a finding; an .exe over cleartext is. This is the
        # case that separates the two.
        packets += dns(clock, "packages.vendor.example", VENDOR, src=client, resolver=RESOLVER)
        packets += _https(clock, client, VENDOR, next_port(), records=8, size=1400)

        # --- a monitoring agent, on a fixed interval ------------------
        # Machine-regular by design. Internal, so PERIODIC-BEACON should
        # not fire: an agent talking to its own server is not an implant
        # talking to the internet.
        for _ in range(6):
            heartbeat = Flow(clock, client, MONITORING, next_port(), 80)
            heartbeat.c2s(b"POST /agent/checkin HTTP/1.1\r\nHost: monitoring.corp.example\r\n"
                          b"Content-Type: application/json\r\n\r\n{\"status\":\"ok\"}")
            heartbeat.s2c(b"HTTP/1.1 204 No Content\r\n\r\n")
            packets += heartbeat.packets
            clock.tick(60.0)

        # --- a large internal file copy -------------------------------
        # Volume, but inside the network. A file copy is not exfiltration.
        copy = Flow(clock, client, FILE_SERVER, next_port(), 445)
        for _ in range(12):
            copy.c2s(b"\xfeSMB" + b"\x00" * 1400, 0.02)
        packets += copy.packets

        # --- the nightly backup, off-site over TLS --------------------
        # Genuinely large and genuinely outbound. Expected to trip
        # OUTBOUND-BULK-TRANSFER, which is correct behaviour: the rule
        # says volume left the network, and its own description says
        # volume alone is not exfiltration.
        packets += _https(clock, client, BACKUP, next_port(), records=10, size=200, upload=1400)

        clock.tick(rng.uniform(5, 20))

    return packets


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("-o", "--output", default="benign.pcap")
    parser.add_argument("--scale", type=int, default=1, help="volume multiplier")
    parser.add_argument("--seed", type=int, default=7)
    args = parser.parse_args()

    packets = build(scale=args.scale, seed=args.seed)
    out = Path(args.output)
    wrpcap(str(out), packets)
    print(f"{len(packets):,} packets -> {out} ({out.stat().st_size:,} bytes)")


if __name__ == "__main__":
    main()
