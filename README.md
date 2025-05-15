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
Why: Avoid errors like missing dependencies (e.g., pyshark not found).
Steps:
Install Python 3.9+ and required tools (Linux):
```
sudo apt update
sudo apt install python3 python3-pip python3-venv tshark
```
On Windows, install Python from python.org and Wireshark (includes tshark) from wireshark.org.

Create a virtual environment:
```
python3 -m venv netforensicai_env
source netforensicai_env/bin/activate  # On Windows: netforensicai_env\Scripts\activate
```
Install required libraries:
```
pip install pyshark pandas scikit-learn requests dash plotly scapy
```
Verify tshark is installed:
```
tshark -v
```
Tip: Manage dependencies with requirements.txt:
```
pip freeze > requirements.txt
pip install -r requirements.txt
```
3.Run the Tool:
Analyze the sample PCAP
```
python3 netforensicai.py sample.pcap
```
To save extracted files.
```
python3 snetforensicai.py demo/sample.pcap --save-files
```
To skip the dashboard (terminal output only):
```
python3 netforensicai.py sample.pcap --no-dashboard
```
4. View Results:
Check the terminal for files found, anomalies, and IP checks.
If the dashboard opens, visit http://127.0.0.1:8050 in your browser.
Extracted files are saved in extracted_files/.

## For Advanced Users
VirusTotal Integration: Get a free API key from virustotal.com and run:
```
python src/netforensicai.py demo/sample.pcap --vt-api your_api_key
```
Custom PCAPs: Replace demo/sample.pcap with your own PCAP file.
Development: Add tests in tests/ or extend file signatures in src/netforensicai.py

## Example Output
```
2025-05-15 11:27:00,123 - INFO - Analyzing packets in demo/sample.pcap
2025-05-15 11:27:01,456 - INFO - Total Files Found: 2
2025-05-15 11:27:01,457 - INFO - Detected Files:
2025-05-15 11:27:01,458 - INFO - Stream: 192.168.1.1:12345->8.8.8.8:80 | Type: pdf | Size: 10240 bytes
2025-05-15 11:27:01,459 - INFO - Found 5 anomalous packets
```
## 🛠️Troubleshooting
"tshark not found": Install Wireshark or tshark (see Setup).
"Module not found": Ensure you're in the virtual environment and run pip install -r requirements.txt.
No dashboard?: Ensure demo/sample.pcap contains TCP packets, or use --no-dashboard.
Still stuck? Open an issue at https://github.com/Sh3n0bi/NetForensicAI/issues.

## 🤝 Contributing
Want to improve NetForensicAI? Fork the repo, make changes, and submit a pull request. See CONTRIBUTING.md for details.

## 📜 License
This project is licensed under the MIT License - see LICENSE for details



