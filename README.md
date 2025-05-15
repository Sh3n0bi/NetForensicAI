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
   ```bash
   git clone https://github.com/Sh3n0bi/NetForensicAI.git
   cd NetForensicAI
## 2. Install Dependencies:
On Windows, Linux, or macOS, run:
 ```
pip install -r requirements.txt
```

On Linux, install tshark:
```
sudo apt update
sudo apt install tshark
```
On Windows, install Wireshark (includes tshark) from wireshark.org.

## 3. Run the Tool:
Analyze the sample PCAP:
```
python src/netforensicai.py demo/sample.pcap
```
To save extracted files:
```
python src/netforensicai.py demo/sample.pcap --save-files
```
To skip the dashboard (terminal output only):
```
python src/netforensicai.py demo/sample.pcap --no-dashboard
```
###4.View Results:
Check the terminal for files found, anomalies, and IP checks.
If the dashboard opens, visit http://127.0.0.1:8050 in your browser.
Extracted files are saved in extracted_files/.

### 🛠️ For Advanced Users
VirusTotal Integration: Get a free API key from virustotal.com and run:
```
python src/netforensicai.py demo/sample.pcap --vt-api your_api_key
```
Custom PCAPs: Replace demo/sample.pcap with your own PCAP file.
Development: Add tests in tests/ or extend file signatures in src/netforensicai.py.

## Example Output
```
2025-05-15 11:27:00,123 - INFO - Analyzing packets in demo/sample.pcap
2025-05-15 11:27:01,456 - INFO - Total Files Found: 2
2025-05-15 11:27:01,457 - INFO - Detected Files:
2025-05-15 11:27:01,458 - INFO - Stream: 192.168.1.1:12345->8.8.8.8:80 | Type: pdf | Size: 10240 bytes
2025-05-15 11:27:01,459 - INFO - Found 5 anomalous packets
```
## 🤝 Contributing
Want to improve NetForensicAI? Fork the repo, make changes, and submit a pull request. See CONTRIBUTING.md for details.

## 📜 License
This project is licensed under the MIT License - see LICENSE for details.





