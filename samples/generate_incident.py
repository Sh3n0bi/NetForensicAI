"""Generate a synthetic incident capture for demos, tests and evaluation.

A GENERATOR RATHER THAN A CHECKED-IN .PCAP, deliberately. A binary in the
repository is something you take on trust: nobody reviews it, nobody can
tell what it contains without opening it, and it grows the clone for
everyone forever. This script is the same capture expressed as something
you can read, diff and argue with - and running it takes a second.

The traffic is fabricated end to end. Every address is chosen for the
story, no real host is contacted, and nothing here is captured from a real
network - so it can live in a public repository without any of the
questions a real capture would raise.

The incident, in seven acts:

  1. Ordinary browsing, so the capture is not made entirely of findings.
     A tool that only ever sees the incident is not being tested.
  2. A DNS lookup of a domain on a cheap TLD.
  3. An executable pulled from it over cleartext HTTP.
  4. A credential posted in the clear to the same host.
  5. A private key served back over the same channel.
  6. An FTP login reusing that password, then a customer CSV uploaded in
     chunks.
  7. Eight beacons at a machine-regular interval.

Run it, then:

    python samples/generate_incident.py -o incident.pcap
    netforensic case create --name "Demo incident" --investigator you
    netforensic evidence add incident.pcap --case INC-0001
    netforensic analyze --case INC-0001
    netforensic story --case INC-0001
"""

import argparse
from pathlib import Path

try:
    from scapy.all import IP, TCP, UDP, DNS, DNSQR, DNSRR, Raw, wrpcap
except ImportError:  # pragma: no cover - the message is the whole point
    raise SystemExit("This script needs scapy: pip install -e '.[pcap]'")

# The story's cast. 10.10.4.17 is the workstation the incident happens to;
# 10.10.4.1 is the resolver. The external addresses are ordinary public
# ranges - RFC5737 documentation ranges look right but Python's ipaddress
# module reports them as private, so rules that distinguish inside from
# outside would never fire on them.
VICTIM = "10.10.4.17"
RESOLVER = "10.10.4.1"
STAGER = "45.33.32.156"
DROP = "104.21.7.19"
BENIGN = "93.184.216.34"

BAD_DOMAIN = "update-service.badcdn.top"
PASSWORD = "W1nter2023!"

START = 1699999999.0  # a fixed base so two runs produce identical captures


class Clock:
    """Monotonic, explicit time. Packets carry the time the story says
    they happened, not the time the script ran."""

    def __init__(self, start=START):
        self.t = start

    def tick(self, seconds=0.05):
        self.t += seconds
        return self.t


class Flow:
    """One TCP conversation, with sequence numbers that advance.

    THE SEQUENCE NUMBERS ARE NOT COSMETIC. Left at scapy's default of 0,
    every packet after the first in a direction looks to tshark like a
    retransmission of the first - and tshark does not hand a
    retransmission's payload to the subdissector. The visible symptom is
    subtle and badly misleading: an FTP login dissects as raw TCP, the
    PASS line is never seen as a credential, and a rule that works
    perfectly well reports nothing. A capture that is wrong in a way only
    the dissector notices is worse than no capture, because it looks like
    a bug in the tool.

    The handshake is here for the same reason - it costs three packets and
    makes this a conversation a dissector can follow rather than a pile of
    payloads on the right ports.
    """

    def __init__(self, clock, client, server, sport, dport):
        self.clock = clock
        self.client, self.server = client, server
        self.sport, self.dport = sport, dport
        self.cseq, self.sseq = 1000, 5000
        self.packets = []
        self._handshake()

    def _emit(self, packet, gap):
        packet.time = self.clock.tick(gap)
        self.packets.append(packet)
        return packet

    def _handshake(self):
        self._emit(
            IP(src=self.client, dst=self.server)
            / TCP(sport=self.sport, dport=self.dport, flags="S", seq=self.cseq - 1),
            0.01,
        )
        self._emit(
            IP(src=self.server, dst=self.client)
            / TCP(sport=self.dport, dport=self.sport, flags="SA", seq=self.sseq - 1, ack=self.cseq),
            0.01,
        )
        self._emit(
            IP(src=self.client, dst=self.server)
            / TCP(sport=self.sport, dport=self.dport, flags="A", seq=self.cseq, ack=self.sseq),
            0.01,
        )

    def c2s(self, payload, gap=0.05):
        """Client to server."""
        self._emit(
            IP(src=self.client, dst=self.server)
            / TCP(sport=self.sport, dport=self.dport, flags="PA", seq=self.cseq, ack=self.sseq)
            / Raw(load=payload),
            gap,
        )
        self.cseq += len(payload)
        return self

    def s2c(self, payload, gap=0.05):
        """Server to client."""
        self._emit(
            IP(src=self.server, dst=self.client)
            / TCP(sport=self.dport, dport=self.sport, flags="PA", seq=self.sseq, ack=self.cseq)
            / Raw(load=payload),
            gap,
        )
        self.sseq += len(payload)
        return self


def dns(clock, domain, answer, src=VICTIM, resolver=RESOLVER):
    """A query and its answer, as two packets rather than one."""
    query = (
        IP(src=src, dst=resolver)
        / UDP(sport=51000, dport=53)
        / DNS(rd=1, id=0x1234, qd=DNSQR(qname=domain))
    )
    reply = (
        IP(src=resolver, dst=src)
        / UDP(sport=53, dport=51000)
        / DNS(
            id=0x1234,
            qr=1,
            aa=1,
            qd=DNSQR(qname=domain),
            an=DNSRR(rrname=domain, ttl=300, rdata=answer),
        )
    )
    for packet in (query, reply):
        packet.time = clock.tick()
    return [query, reply]


def http(clock, request, response, dst, sport):
    """One request and one response on a fresh connection."""
    flow = Flow(clock, VICTIM, dst, sport, 80)
    flow.c2s(request).s2c(response)
    return flow.packets


def build():
    clock = Clock()
    packets = []

    # --- 1. background browsing ---------------------------------------
    packets += dns(clock, "www.example.com", BENIGN)
    packets += http(
        clock,
        b"GET /index.html HTTP/1.1\r\nHost: www.example.com\r\n"
        b"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 42\r\n\r\n"
        b"<html><body>Example Domain</body></html>",
        BENIGN,
        49200,
    )

    # --- 2. the lookup ------------------------------------------------
    clock.tick(20)
    packets += dns(clock, BAD_DOMAIN, STAGER)

    # --- 3. the download ----------------------------------------------
    packets += http(
        clock,
        b"GET /update/svc-installer.exe HTTP/1.1\r\nHost: " + BAD_DOMAIN.encode() + b"\r\n"
        b"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n"
        b"Content-Length: 64\r\n\r\nMZ\x90\x00\x03" + b"\x00" * 59,
        STAGER,
        49210,
    )

    # --- 4. the credential, in the clear ------------------------------
    clock.tick(40)
    body = b"username=svc_backup&password=" + PASSWORD.encode()
    packets += http(
        clock,
        b"POST /portal/login HTTP/1.1\r\nHost: " + BAD_DOMAIN.encode() + b"\r\n"
        b"Content-Type: application/x-www-form-urlencoded\r\n"
        b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body,
        b"HTTP/1.1 302 Found\r\nLocation: /portal/home\r\n\r\n",
        STAGER,
        49220,
    )

    # --- 5. key material ----------------------------------------------
    packets += http(
        clock,
        b"GET /files/id_rsa HTTP/1.1\r\nHost: " + BAD_DOMAIN.encode() + b"\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n\r\n"
        b"-----BEGIN OPENSSH PRIVATE KEY-----\n"
        b"b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAB\n"
        b"-----END OPENSSH PRIVATE KEY-----\n",
        STAGER,
        49230,
    )

    # --- 6. FTP with the same password, then the upload ---------------
    clock.tick(60)
    control = Flow(clock, VICTIM, DROP, 49240, 21)
    control.s2c(b"220 ProFTPD Server ready\r\n", 0.3)
    control.c2s(b"USER svc_backup\r\n", 0.3)
    control.s2c(b"331 Password required\r\n", 0.3)
    control.c2s(b"PASS " + PASSWORD.encode() + b"\r\n", 0.3)
    control.s2c(b"230 User logged in\r\n", 0.3)
    control.c2s(b"STOR customers-export.csv\r\n", 0.3)
    packets += control.packets

    # Six chunks on the data channel. Chunked because that is what an
    # upload looks like, and because it is the case a beacon rule must
    # not misread as an implant checking in.
    chunk = b"id,name,email,card_last4\n" + b"".join(
        f"{i},Customer {i},user{i}@corp.example,{1000 + i}\n".encode() for i in range(20)
    )
    data = Flow(clock, VICTIM, DROP, 49241, 20)
    for _ in range(6):
        data.c2s(chunk, 2.0)
    packets += data.packets

    # --- 7. the beacons -----------------------------------------------
    # A fresh connection each time, which is what an implant that does not
    # hold a socket open looks like.
    clock.tick(30)
    for i in range(8):
        beacon = Flow(clock, VICTIM, STAGER, 49300 + i, 443)
        beacon.c2s(b"\x17\x03\x03\x00\x20" + bytes([i]) * 32, 0.1)
        beacon.s2c(b"\x17\x03\x03\x00\x10" + bytes([i]) * 16, 0.1)
        packets += beacon.packets
        clock.tick(29.6)  # a machine-regular ~30s, which is the whole point

    return packets


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("-o", "--output", default="incident.pcap", help="where to write the capture")
    args = parser.parse_args()

    packets = build()
    out = Path(args.output)
    wrpcap(str(out), packets)
    print(f"{len(packets)} packets -> {out} ({out.stat().st_size:,} bytes)")


if __name__ == "__main__":
    main()
