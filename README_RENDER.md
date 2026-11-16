# NetSentry — Render-ready Network Traffic Anomaly Detection

## What happens when a visitor clicks Scan & Detect?
1. The visitor selects a `.pcap` or `.pcapng` capture file.
2. The browser uploads it to the Flask service.
3. Flask passes the capture to Scapy immediately.
4. NetSentry counts protocols, source/destination IPs and destination ports.
5. It raises heuristic alerts for possible port scans, high TCP SYN volume, ICMP bursts and high packet volume.
6. The results are displayed on the dashboard. The temporary uploaded file is deleted after analysis.

Maximum upload size: 25 MB.

## Important hosting limitation
Render runs your Flask application on a remote cloud server. It cannot access the Wi-Fi adapter, Npcap device, or local network interface of the person visiting the website. Therefore, a button on the Render website cannot directly sniff the visitor's laptop Wi-Fi traffic.

For an actual laptop capture:
1. Open Wireshark on your laptop.
2. Capture traffic on your own Wi-Fi adapter/network, with permission.
3. Stop the capture and save as `.pcapng` or `.pcap`.
4. Open the deployed NetSentry website, select that file, and click **Scan & Detect**.
5. The website automatically analyzes that uploaded capture.

The project intentionally does not claim that cloud-hosted scanning is live local Wi-Fi monitoring.

## Deploy on Render
1. Extract this ZIP.
2. Create a GitHub repository and upload the contents of this folder to the repository root (not inside an extra nested folder).
3. Open Render and choose **New + → Blueprint** or **New + → Web Service**.
4. For a Web Service, connect the GitHub repository and set:
   - Runtime: Python 3
   - Build command: `pip install -r requirements.txt`
   - Start command: `gunicorn app:app`
   - Health check path: `/health`
5. Deploy. Render provides an `onrender.com` URL.
6. Open the URL, select a PCAP/PCAPNG file and click **Scan & Detect**.

The included `render.yaml` contains the service configuration for Blueprint deployment.

## Run locally
```powershell
py -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python app.py
```
Open `http://127.0.0.1:5000`.

## Safe test capture
```powershell
python -m netsentry.generate_sample
```
Upload the generated `sample_traffic.pcap` to the website. It is synthetic test data; it sends no packets.

## Detection notes
This is a rule-based educational prototype, not a production IDS or machine-learning model. Alerts are heuristic indicators and may be false positives. Thresholds are in `netsentry/config.py`. Analyze only captures you are authorized to inspect.
