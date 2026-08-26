"""PCAP deep packet inspection, embedded-file extraction, and anomaly detection.

Relocated from the original top-level netforensicai.py script. Logic is
unchanged from the original; only the module layout and class name changed
(NetForensicAI -> PcapAnalyzer, since it now sits under parsers/) and unused
imports (scapy.rdpcap, multiprocessing.Pool, binascii) were dropped.
"""

import logging
import os
import shutil
import sys

import pandas as pd
import pyshark
from sklearn.ensemble import IsolationForest

logger = logging.getLogger(__name__)

FILE_SIGNATURES = {
    "pdf": b"%PDF-",
    "png": b"\x89PNG",
    "jpg": b"\xFF\xD8\xFF",
    "zip": b"PK\x03\x04",
    "exe": b"MZ",
    "gif": b"GIF89a",
}


class PcapAnalyzer:
    def __init__(self, pcap_file, output_dir="extracted_files"):
        self.pcap_file = pcap_file
        self.output_dir = output_dir
        self.validate_pcap()

    def validate_pcap(self):
        """Check if the PCAP file exists and is readable."""
        if not os.path.exists(self.pcap_file):
            logger.error(f"PCAP file '{self.pcap_file}' not found. Please provide a valid file.")
            sys.exit(1)
        if not shutil.which("tshark"):
            logger.error("tshark not found. Install it with 'sudo apt install tshark' on Linux.")
            sys.exit(1)

    def deep_packet_inspection(self):
        """Perform deep packet inspection on the PCAP file."""
        logger.info(f"Analyzing packets in {self.pcap_file}")
        try:
            capture = pyshark.FileCapture(self.pcap_file, display_filter="tcp")
            findings = []
            for packet in capture:
                try:
                    if "TCP" in packet and hasattr(packet.tcp, "payload"):
                        payload = packet.tcp.payload.replace(":", "")
                        payload_bytes = bytes.fromhex(payload)
                        findings.append({
                            "src_ip": packet.ip.src,
                            "dst_ip": packet.ip.dst,
                            "src_port": packet.tcp.srcport,
                            "dst_port": packet.tcp.dstport,
                            "payload": payload_bytes.decode("utf-8", errors="ignore")[:50]
                        })
                except AttributeError:
                    continue
            capture.close()
            return findings
        except Exception as e:
            logger.error(f"Error during DPI: {e}")
            return []

    def extract_files(self, save_files=False):
        """Extract files from the PCAP file."""
        logger.info(f"Extracting files from {self.pcap_file}")
        try:
            capture = pyshark.FileCapture(self.pcap_file, display_filter="tcp")
            streams = {}
            packet_num = 0

            if save_files and not os.path.exists(self.output_dir):
                os.makedirs(self.output_dir)

            for packet in capture:
                packet_num += 1
                try:
                    if "TCP" in packet and hasattr(packet.tcp, "payload"):
                        payload = packet.tcp.payload.replace(":", "")
                        payload_bytes = bytes.fromhex(payload)
                        stream_key = f"{packet.ip.src}:{packet.tcp.srcport}->{packet.ip.dst}:{packet.tcp.dstport}"
                        if stream_key not in streams:
                            streams[stream_key] = {"data": [], "packets": []}
                        streams[stream_key]["data"].append(payload_bytes)
                        streams[stream_key]["packets"].append(packet_num)
                except AttributeError:
                    continue
            capture.close()

            files_found = []
            for stream_key, stream_info in streams.items():
                full_data = b"".join(stream_info["data"])
                file_type = None
                for ext, signature in FILE_SIGNATURES.items():
                    if signature in full_data[:1024]:
                        file_type = ext
                        break
                if file_type:
                    total_size = len(full_data)
                    files_found.append({
                        "stream": stream_key,
                        "file_type": file_type,
                        "size_bytes": total_size,
                        "packet_numbers": stream_info["packets"]
                    })
                    if save_files:
                        filename = f"{self.output_dir}/{stream_key.replace(':', '_')}.{file_type}"
                        with open(filename, "wb") as f:
                            f.write(full_data)
                        logger.info(f"Saved file: {filename} ({total_size} bytes)")
            return files_found
        except Exception as e:
            logger.error(f"Error extracting files: {e}")
            return []

    def anomaly_detection(self):
        """Detect anomalies in packet traffic."""
        logger.info("Running anomaly detection")
        try:
            capture = pyshark.FileCapture(self.pcap_file)
            features = []
            prev_time = None
            for packet in capture:
                try:
                    size = int(packet.length)
                    timestamp = float(packet.sniff_time.timestamp())
                    src_port = int(packet.tcp.srcport) if "TCP" in packet else 0
                    dst_port = int(packet.tcp.dstport) if "TCP" in packet else 0
                    inter_arrival = timestamp - prev_time if prev_time else 0
                    prev_time = timestamp
                    features.append([size, inter_arrival, src_port, dst_port])
                except AttributeError:
                    continue
            capture.close()
            df = pd.DataFrame(features, columns=["size", "inter_arrival", "src_port", "dst_port"])
            model = IsolationForest(contamination=0.05, random_state=42)
            predictions = model.fit_predict(df)
            anomalies = df[predictions == -1]
            logger.info(f"Found {len(anomalies)} anomalous packets")
            return anomalies
        except Exception as e:
            logger.error(f"Error during anomaly detection: {e}")
            return pd.DataFrame()
