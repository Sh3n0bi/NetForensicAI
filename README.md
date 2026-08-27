# NetForensicAI
**AI-Powered Network Forensics Made Simple**


NetForensicAI is a user-friendly tool for analyzing network traffic (PCAP files). It extracts files (like PDFs or images), detects suspicious activity using AI, and checks for malicious IPs. Whether you're a cybersecurity beginner or a seasoned analyst, NetForensicAI simplifies network forensics with clear outputs and an interactive dashboard.

## ✨ Features
- **File Extraction**: Recover files (PDFs, PNGs, etc.) from network traffic.
- **Anomaly Detection**: Spot unusual packets with machine learning.
- **Threat Intelligence**: Check IPs against VirusTotal (optional).
- **Deep Packet Inspection**: Analyze TCP payloads in detail.
- **Interactive Dashboard**: Visualize results with a web-based interface.

## 🚀 Quick Start for Non-Technical Users

## Prerequisites
- A computer with Python 3.9+ installed ([Download Python](https://www.python.org/downloads/)).
- A PCAP file to analyze (use `demo/sample.pcap` to test).

### Step-by-Step Setup
1. **Clone the Repository**:
```
git clone https://github.com/Sh3n0bi/NetForensicAI.git
cd NetForensicAI 
```   
2. Set Up the Development Environment:
Steps:
Install Python 3.9+ (Linux):
```
sudo apt update
sudo apt install python3 python3-pip python3-venv
```
On Windows, install Python from python.org.

No Wireshark/tshark install needed - pcap parsing uses scapy (pure Python).

Create a virtual environment:
```
python3 -m venv netforensicai_env
source netforensicai_env/bin/activate  # On Windows: netforensicai_env\Scripts\activate
```
Install the package with the extras you need:
```
pip install -e ".[pcap,intel,dashboard]"
```
3. Run the Tool:
Analyze a PCAP:
```
netforensic scan your_capture.pcap
```
To save extracted files:
```
netforensic scan your_capture.pcap --save-files
```
To skip the dashboard (terminal output only):
```
netforensic scan your_capture.pcap --no-dashboard
```
4. View Results:
Check the terminal for files found, anomalies, and IP checks.
If the dashboard opens, visit http://127.0.0.1:8050 in your browser.
Extracted files are saved in extracted_files/.

## For Advanced Users
VirusTotal Integration: Get a free API key from virustotal.com and run:
```
netforensic scan your_capture.pcap --vt-api your_api_key
# or export VT_API_KEY=your_api_key and omit --vt-api
```

AI Investigation Assistant (optional, `[ai]` extra): `netforensic investigate --case <ID> --ip <ip> --ai`
asks Claude for one hedged hypothesis about that entity's events (observed evidence / claim / confidence
/ alternative explanation), never a bare conclusion. Requires `pip install -e ".[ai]"` and Anthropic
credentials (`--api-key`, `ANTHROPIC_API_KEY`, or `ant auth login`). The assistant only ever sees the
normalized events already in the case - never raw evidence files - and any response citing evidence not
actually present in those events is rejected outright rather than shown. It never creates a Finding on
its own; that's always an explicit `netforensic finding create` by the investigator.

Development: Add tests in tests/ or extend file signatures in netforensicai/parsers/pcap.py

## Example Output
```
2025-05-15 11:27:00,123 - INFO - Analyzing packets in demo/sample.pcap
2025-05-15 11:27:01,456 - INFO - Total Files Found: 2
2025-05-15 11:27:01,457 - INFO - Detected Files:
2025-05-15 11:27:01,458 - INFO - Stream: 192.168.1.1:12345->8.8.8.8:80 | Type: pdf | Size: 10240 bytes
2025-05-15 11:27:01,459 - INFO - Found 5 anomalous packets
```
## 🛠️Troubleshooting
"Module not found": Ensure you're in the virtual environment and reinstall with `pip install -e ".[pcap,intel,dashboard]"`.
No dashboard?: Ensure your pcap contains TCP packets, or use --no-dashboard.
Still stuck? Open an issue at https://github.com/Sh3n0bi/NetForensicAI/issues.

## 🤝 Contributing
Want to improve NetForensicAI? Fork the repo, make changes, and submit a pull request. See CONTRIBUTING.md for details.

## 📜 License
This project is licensed under the MIT License - see LICENSE for details



