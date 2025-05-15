#!/usr/bin/env python3

import pyshark
import pandas as pd
from sklearn.ensemble import IsolationForest
import requests
import dash
from dash import html, dcc
import plotly.express as px
from scapy.all import rdpcap
from multiprocessing import Pool
import argparse
import sys
import binascii
import os
import logging
import shutil

# --- Setup Logging ---
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# --- File Signatures ---
FILE_SIGNATURES = {
    "pdf": b"%PDF-",
    "png": b"\x89PNG",
    "jpg": b"\xFF\xD8\xFF",
    "zip": b"PK\x03\x04",
    "exe": b"MZ",
    "gif": b"GIF89a",
}

class NetForensicAI:
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

    def check_threat_intel(self, ip, api_key):
        """Check IP against VirusTotal."""
        if not api_key:
            logger.warning("VirusTotal API key not provided. Skipping threat intel.")
            return False
        logger.info(f"Checking threat intel for IP: {ip}")
        try:
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
            headers = {"x-apikey": api_key}
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                data = response.json()
                malicious = data["data"]["attributes"]["last_analysis_stats"]["malicious"]
                return malicious > 0
            return False
        except Exception as e:
            logger.error(f"Error checking threat intel: {e}")
            return False

    def launch_dashboard(self, anomalies):
        """Launch an interactive dashboard for anomalies."""
        logger.info("Starting dashboard. Open http://127.0.0.1:8050 in your browser.")
        try:
            app = dash.Dash(__name__)
            fig = px.scatter(anomalies, x="inter_arrival", y="size", title="Anomalous Packets")
            app.layout = html.Div([
                html.H1("NetForensicAI Dashboard"),
                dcc.Graph(figure=fig)
            ])
            app.run(debug=False)
        except Exception as e:
            logger.error(f"Error launching dashboard: {e}")

def main():
    parser = argparse.ArgumentParser(
        description="NetForensicAI - AI-Powered Network Forensics Tool",
        epilog="Example: python netforensicai.py sample.pcap --save-files"
    )
    parser.add_argument("pcap_file", help="Path to the .pcap file")
    parser.add_argument("--vt-api", help="VirusTotal API key for threat intelligence", default=None)
    parser.add_argument("--save-files", action="store_true", help="Save extracted files to disk")
    parser.add_argument("--no-dashboard", action="store_true", help="Skip launching the dashboard")
    args = parser.parse_args()

    # Initialize the tool
    tool = NetForensicAI(args.pcap_file)

    # Run Deep Packet Inspection
    dpi_results = tool.deep_packet_inspection()
    if dpi_results:
        logger.info("Top 5 DPI Results:")
        for result in dpi_results[:5]:
            logger.info(f"Source: {result['src_ip']}:{result['src_port']} -> Destination: {result['dst_ip']}:{result['dst_port']}")
            logger.info(f"Payload Preview: {result['payload']}...")
    else:
        logger.warning("No TCP packets found for DPI.")

    # Extract Files
    files_found = tool.extract_files(save_files=args.save_files)
    logger.info(f"Total Files Found: {len(files_found)}")
    if files_found:
        logger.info("Detected Files:")
        for file in files_found:
            logger.info(f"Stream: {file['stream']} | Type: {file['file_type']} | Size: {file['size_bytes']} bytes")

    # Run Anomaly Detection
    anomalies = tool.anomaly_detection()
    if not anomalies.empty:
        logger.info("Anomalies Detected:")
        logger.info(anomalies.head().to_string())
    else:
        logger.warning("No anomalies detected.")

    # Threat Intelligence
    if args.vt_api and dpi_results:
        logger.info("Checking threat intelligence for top IPs...")
        for result in dpi_results[:5]:
            if tool.check_threat_intel(result["src_ip"], args.vt_api):
                logger.warning(f"Malicious IP detected: {result['src_ip']}")

    # Launch Dashboard (unless skipped)
    if not args.no_dashboard and not anomalies.empty:
        tool.launch_dashboard(anomalies)
    else:
        logger.info("Dashboard skipped. Use --no-dashboard to disable or ensure anomalies are detected.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logger.info("Analysis interrupted by user.")
        sys.exit(0)
    except Exception as e:
        logger.error(f"An unexpected error occurred: {e}")
        sys.exit(1)
