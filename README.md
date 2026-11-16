# NetSentry — Network Traffic Anomaly Detection

A beginner-friendly defensive network-monitoring project built with **Python, Scapy, Flask and Wireshark**. It analyzes saved PCAP/PCAPNG captures and flags traffic patterns that may deserve investigation.

## Features
- Upload and analyze `.pcap` / `.pcapng` files in a local web dashboard.
- Packet and protocol counts, top source/destination IPs, and destination ports.
- Heuristic alerts for possible TCP SYN floods, port scans, ICMP bursts and unusually high packet volume.
- Optional authorized live packet capture using Scapy.
- Synthetic PCAP generator for a safe demo (does not transmit packets).
- Wireshark workflow for inspecting the same capture in detail.

> **Important:** This is an educational prototype, not a production IDS. Threshold-based alerts can produce false positives and do not prove malicious activity. Analyze only networks and devices you own or have explicit permission to monitor. Packet captures may contain sensitive information; store and share them carefully.

## 1. Requirements
- Windows 10/11, Linux or macOS
- Python 3.10–3.12 recommended
- Wireshark (optional, for visual packet inspection)
- On Windows, install **Npcap** if you want live packet capture. Use the official Npcap installer and enable WinPcap API-compatible mode if prompted.

## 2. Install

### Windows PowerShell
```powershell
cd NetSentry_Network_Anomaly_Detection
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```
If PowerShell blocks activation:
```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
```

### Linux/macOS
```bash
cd NetSentry_Network_Anomaly_Detection
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
```

## 3. Run the dashboard
```bash
python app.py
```
Open `http://127.0.0.1:5000` in your browser. Select a PCAP/PCAPNG file and click **Analyze Capture**. Use **Load Demo Results** to explore the interface without a capture.

## 4. Generate and analyze a safe sample
```bash
python -m netsentry.generate_sample
```
This creates `sample_traffic.pcap` with synthetic packet records; it does not send traffic. Upload that file to the dashboard. It should demonstrate the port-scan and ICMP-burst rules.

## 5. Capture your own authorized traffic (optional)
Run PowerShell or terminal as Administrator/root:
```bash
python -m netsentry.live_capture --count 200 --output my_capture.pcap
```
To select a specific interface:
```bash
python -m netsentry.live_capture --interface "Wi-Fi" --count 200 --output my_capture.pcap
```
Interface names differ by operating system. On Windows, list available adapters with:
```powershell
python -c "from scapy.all import show_interfaces; show_interfaces()"
```
If capture fails, first confirm Npcap is installed, then run the terminal as Administrator and verify the interface name. You can also use Wireshark to capture traffic and save it as a PCAP file, then upload that file to NetSentry.

## 6. Wireshark integration
1. Open Wireshark and select the authorized network interface.
2. Start a capture, generate ordinary traffic, then stop the capture.
3. Save it as `capture.pcapng` (or `.pcap`).
4. Upload the saved file to NetSentry.
5. In Wireshark, useful display filters include:
   - `tcp.flags.syn == 1 && tcp.flags.ack == 0` — initial TCP SYN packets
   - `icmp` — ICMP packets
   - `tcp` / `udp` — protocol-specific traffic
   - `ip.addr == 192.168.1.10` — traffic involving an IP (replace with your address)

Wireshark is used for packet capture and manual inspection; Scapy parses packets and NetSentry applies detection logic.

## 7. Detection logic
| Detection | Current prototype rule | Interpretation |
|---|---|---|
| Possible port scan | One source contacts at least 12 distinct destination ports | Could be service discovery, inventory or scanning |
| High SYN volume | At least 40 initial SYN packets from one source in the capture | Could be a connection burst or SYN flood |
| ICMP burst | At least 35 ICMP packets from one source | Could be diagnostics or unusual ICMP activity |
| High packet volume | At least 500 packets from one source | Could be a busy legitimate endpoint |

These are capture-wide thresholds, not time-window/rate-based production detections. Tune `netsentry/config.py` for your lab environment.

## 8. Project structure
```text
NetSentry_Network_Anomaly_Detection/
├── app.py
├── requirements.txt
├── README.md
├── netsentry/
│   ├── __init__.py
│   ├── analyzer.py
│   ├── config.py
│   ├── live_capture.py
│   └── generate_sample.py
├── templates/
│   └── index.html
├── static/
│   └── style.css
├── tests/
│   └── test_analyzer.py
└── uploads/                 # created automatically
```

## 9. Run tests
```bash
python -m unittest discover -s tests -v
```

## 10. Limitations and next improvements
- Heuristics do not use machine learning and may generate false positives.
- Detection currently evaluates one capture as a whole rather than a rolling time window.
- Non-IP frames are counted but not deeply inspected.
- For a stronger next version: add rolling flow windows, baseline learning, Isolation Forest, alert export, authentication, and a database with retention controls.

## Interview explanation
**Problem:** Network administrators need visibility into traffic patterns that may indicate scanning, flooding or abnormal protocol usage.

**Solution:** NetSentry reads packet captures with Scapy, extracts source/destination addresses, protocols, ports and TCP flags, then applies transparent heuristic rules. A Flask dashboard summarizes traffic and presents alerts. Wireshark provides independent packet-level validation.

**Why Scapy?** It is a Python packet-manipulation and packet-analysis library. It lets the project inspect packet layers and fields programmatically, which makes custom analysis rules possible.

**Why Wireshark?** It is a mature packet analyzer useful for capturing, filtering and manually validating suspicious packets. It complements rather than replaces the Python detection engine.

**Is this AI/ML?** No. The delivered version is rule-based, not an AI model. Do not describe it as machine learning in an interview. An ML model can be added later after collecting representative labelled traffic and evaluating precision/recall.


## Render deployment
See `README_RENDER.md` for the Render deployment steps and the important cloud-vs-local packet capture limitation.
