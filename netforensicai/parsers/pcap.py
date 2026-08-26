"""PCAP -> normalized Event parsing.

Uses scapy (pure Python) to read .pcap files instead of pyshark/tshark.
Reading and writing pcap *files* with scapy needs no external binary or
capture driver (only live sniffing does), which is what makes it possible
to build synthetic pcap fixtures for tests in this repo.

Three analyses, carried over from the original single-file script, each
producing a distinct event_type:
  - network_connection: one event per TCP packet carrying a payload
    (raw payload preview kept in `message`, same as the original DPI output)
  - file_transfer: one event per TCP stream whose reassembled data matches
    a known file signature (magic bytes), optionally saved to disk
  - anomaly: one event per packet flagged as a statistical outlier by
    IsolationForest over [size, inter_arrival, src_port, dst_port]
"""

import hashlib
import logging
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd
from scapy.all import IP, TCP, Raw, rdpcap
from sklearn.ensemble import IsolationForest

from netforensicai.core.event import Event, EventSequence, generate_event_id
from netforensicai.parsers import base

logger = logging.getLogger(__name__)

FILE_SIGNATURES = {
    "pdf": b"%PDF-",
    "png": b"\x89PNG",
    "jpg": b"\xFF\xD8\xFF",
    "zip": b"PK\x03\x04",
    "exe": b"MZ",
    "gif": b"GIF89a",
}

SIGNATURE_SCAN_WINDOW = 1024
DPI_PREVIEW_BYTES = 50
DEFAULT_ANOMALY_CONTAMINATION = 0.05


class PcapParseError(Exception):
    """Raised when a pcap file cannot be read."""


def _load_packets(pcap_path):
    try:
        return rdpcap(str(pcap_path))
    except Exception as e:
        raise PcapParseError(f"Failed to read pcap file '{pcap_path}': {e}") from e


def _tcp_payload_packets(packets):
    """Yield (packet_number, packet) for packets with an IP+TCP layer and a payload."""
    for i, packet in enumerate(packets, start=1):
        if packet.haslayer(IP) and packet.haslayer(TCP) and packet.haslayer(Raw):
            yield i, packet


def _packet_timestamp(packet):
    return datetime.fromtimestamp(float(packet.time), tz=timezone.utc)


def _network_connection_events(packets, evidence_id, sequence):
    events = []
    for packet_number, packet in _tcp_payload_packets(packets):
        payload = bytes(packet[Raw].load)
        events.append(
            Event(
                event_id=generate_event_id(evidence_id, sequence.next()),
                evidence_id=evidence_id,
                source="pcap",
                event_type="network_connection",
                timestamp=_packet_timestamp(packet),
                src_ip=packet[IP].src,
                src_port=int(packet[TCP].sport),
                dst_ip=packet[IP].dst,
                dst_port=int(packet[TCP].dport),
                protocol="tcp",
                message=payload[:DPI_PREVIEW_BYTES].decode("utf-8", errors="ignore"),
                raw_event_reference={"packet_number": packet_number},
            )
        )
    return events


def _file_transfer_events(packets, evidence_id, sequence, output_dir=None):
    streams = {}
    for packet_number, packet in _tcp_payload_packets(packets):
        stream_key = (
            f"{packet[IP].src}:{packet[TCP].sport}->{packet[IP].dst}:{packet[TCP].dport}"
        )
        stream = streams.setdefault(
            stream_key, {"data": [], "packet_numbers": [], "first_timestamp": None}
        )
        stream["data"].append(bytes(packet[Raw].load))
        stream["packet_numbers"].append(packet_number)
        if stream["first_timestamp"] is None:
            stream["first_timestamp"] = float(packet.time)

    if output_dir is not None:
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

    events = []
    for stream_key, info in streams.items():
        full_data = b"".join(info["data"])
        file_type = next(
            (ext for ext, sig in FILE_SIGNATURES.items() if sig in full_data[:SIGNATURE_SCAN_WINDOW]),
            None,
        )
        if not file_type:
            continue

        src, dst = stream_key.split("->")
        src_ip, src_port = src.split(":")
        dst_ip, dst_port = dst.split(":")
        file_name = f"{stream_key.replace(':', '_').replace('->', '_to_')}.{file_type}"

        stored_path = None
        if output_dir is not None:
            stored_path = output_dir / file_name
            stored_path.write_bytes(full_data)
            logger.info(f"Saved extracted file: {stored_path} ({len(full_data)} bytes)")

        events.append(
            Event(
                event_id=generate_event_id(evidence_id, sequence.next()),
                evidence_id=evidence_id,
                source="pcap",
                event_type="file_transfer",
                timestamp=datetime.fromtimestamp(info["first_timestamp"], tz=timezone.utc),
                src_ip=src_ip,
                src_port=int(src_port),
                dst_ip=dst_ip,
                dst_port=int(dst_port),
                protocol="tcp",
                file_name=file_name,
                file_path=str(stored_path) if stored_path else None,
                file_hash=hashlib.sha256(full_data).hexdigest(),
                message=f"Detected embedded {file_type} file ({len(full_data)} bytes) in TCP stream {stream_key}",
                raw_event_reference={"packet_numbers": info["packet_numbers"], "stream": stream_key},
            )
        )
    return events


def _packet_features(packets):
    """Return (feature_rows, meta) for every packet, in packet order."""
    features = []
    meta = []
    prev_time = None
    for i, packet in enumerate(packets, start=1):
        timestamp = float(packet.time)
        size = len(packet)
        src_port = int(packet[TCP].sport) if packet.haslayer(TCP) else 0
        dst_port = int(packet[TCP].dport) if packet.haslayer(TCP) else 0
        inter_arrival = timestamp - prev_time if prev_time is not None else 0.0
        prev_time = timestamp
        features.append([size, inter_arrival, src_port, dst_port])
        meta.append(
            {
                "packet_number": i,
                "timestamp": timestamp,
                "size": size,
                "inter_arrival": inter_arrival,
                "src_ip": packet[IP].src if packet.haslayer(IP) else None,
                "dst_ip": packet[IP].dst if packet.haslayer(IP) else None,
                "src_port": src_port or None,
                "dst_port": dst_port or None,
            }
        )
    return features, meta


def _anomaly_events(packets, evidence_id, sequence, contamination=DEFAULT_ANOMALY_CONTAMINATION):
    if len(packets) < 2:
        return []

    features, meta = _packet_features(packets)
    df = pd.DataFrame(features, columns=["size", "inter_arrival", "src_port", "dst_port"])
    model = IsolationForest(contamination=contamination, random_state=42)
    predictions = model.fit_predict(df)

    events = []
    for is_anomalous, info in zip(predictions == -1, meta):
        if not is_anomalous:
            continue
        events.append(
            Event(
                event_id=generate_event_id(evidence_id, sequence.next()),
                evidence_id=evidence_id,
                source="pcap",
                event_type="anomaly",
                timestamp=datetime.fromtimestamp(info["timestamp"], tz=timezone.utc),
                src_ip=info["src_ip"],
                dst_ip=info["dst_ip"],
                src_port=info["src_port"],
                dst_port=info["dst_port"],
                severity="medium",
                message="Packet flagged as a statistical outlier (size/timing/port profile) by IsolationForest.",
                raw_event_reference={
                    "packet_number": info["packet_number"],
                    "size": info["size"],
                    "inter_arrival": info["inter_arrival"],
                },
            )
        )
    return events


class PcapParser(base.BaseParser):
    evidence_types = ("pcap",)

    def parse(
        self,
        file_path,
        evidence_id,
        output_dir=None,
        anomaly_contamination=DEFAULT_ANOMALY_CONTAMINATION,
        **_ignored,
    ):
        """Parse a pcap file into normalized Events. Raises PcapParseError if unreadable.

        output_dir: if given, extracted embedded files are saved there and
        file_transfer events get a populated file_path.
        """
        packets = _load_packets(file_path)
        sequence = EventSequence()

        events = []
        events.extend(_network_connection_events(packets, evidence_id, sequence))
        events.extend(_file_transfer_events(packets, evidence_id, sequence, output_dir))
        events.extend(_anomaly_events(packets, evidence_id, sequence, anomaly_contamination))
        return events


base.register(PcapParser())
