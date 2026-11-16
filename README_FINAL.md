# NetSentry final architecture: Render website + local capture agent

## How the Scan button works
1. Deploy the Flask website to Render.
2. Install and run `agent.py` on your Windows laptop, with Scapy/Npcap and the Wi-Fi interface.
3. The agent maintains an outbound HTTPS polling connection to Render.
4. Click **Scan my network** on the website.
5. Render queues a scan job.
6. The local agent receives the job and captures packets from the selected local interface for the chosen duration.
7. The agent applies the same Scapy detection rules and posts results to Render.
8. The website automatically displays packet totals, protocols, IP summaries and alerts.

This is a local endpoint sensor controlled by the website. Render itself does not sniff the laptop's Wi-Fi adapter.

## Deploy the website
1. Push all files in this folder to the root of a GitHub repository.
2. In Render, create a Web Service from that repository (or use the included Blueprint `render.yaml`).
3. Build command: `pip install -r requirements.txt`
4. Start command: `gunicorn --workers 1 --threads 8 app:app`
5. Add environment variable `AGENT_SHARED_SECRET` with a long random secret string. Example generate one in PowerShell:
   `python -c "import secrets; print(secrets.token_urlsafe(32))"`
6. Deploy and copy the Render URL.

**Important:** Set `AGENT_SHARED_SECRET` in Render and use exactly the same value for the local agent. Do not publish the secret in GitHub or share it with anyone.

## Set up your Windows laptop agent
In a separate copy of this project (or same project folder):
```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```
Install Npcap if not already installed. Run PowerShell as Administrator if capture permissions require it.

Set the secret for this terminal session:
```powershell
$env:NETSENTRY_AGENT_TOKEN="PASTE_THE_SAME_SECRET_AS_RENDER"
```
Start the agent (replace URL if yours differs):
```powershell
python agent.py --server https://YOUR-SERVICE.onrender.com --interface "Intel(R) Wi-Fi 6 AX203"
```
Keep this terminal open. It must show `NetSentry Agent online`.

## Use it
1. Open your Render website.
2. Ensure the local agent terminal is still running.
3. Click **Scan my network** and select 10/20/30/60 seconds.
4. The agent captures packets locally and sends analysis results to the site.
5. Keep the laptop online until scan completes.

## Manual PCAP scan
The dashboard also retains PCAP/PCAPNG upload and scan. This works without the local agent.

## Limitations
- The agent monitors packets exposed by the laptop's selected interface. Normal Wi-Fi client mode generally sees the laptop's own traffic, not every other device's unicast traffic.
- The laptop must be powered on, connected to the internet and running the agent for website-triggered local scans.
- Render free instances may sleep; the first request can take time to wake.
- This simple prototype stores scan jobs/results in process memory. It is intended for a student demonstration, not multi-user production SOC deployment.
- Rule-based detections are heuristics and can produce false positives. The project is not an ML model.
- Only monitor devices/networks you own or are explicitly authorized to monitor.
