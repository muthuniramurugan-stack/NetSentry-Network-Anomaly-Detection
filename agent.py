import os, time, argparse, requests
from scapy.all import sniff
from netsentry.analyzer import analyze_packets

def main():
    parser = argparse.ArgumentParser(description="NetSentry local authorized network capture agent")
    parser.add_argument("--server", required=True, help="Your deployed Render URL, e.g. https://netsentry-example.onrender.com")
    parser.add_argument("--interface", required=True, help="Scapy interface name, e.g. Intel(R) Wi-Fi 6 AX203")
    parser.add_argument("--token", default=os.environ.get("NETSENTRY_AGENT_TOKEN", ""), help="Same secret as Render AGENT_SHARED_SECRET")
    args = parser.parse_args()
    if not args.token:
        raise SystemExit("Missing token. Set NETSENTRY_AGENT_TOKEN or pass --token.")
    base = args.server.rstrip("/")
    headers = {"X-Agent-Token": args.token}
    print("NetSentry Agent online. Keep this terminal open. Press Ctrl+C to stop.")
    print(f"Server: {base} | Interface: {args.interface}")
    session = requests.Session()
    while True:
        try:
            response = session.get(base + "/api/agent/next", headers=headers, timeout=25)
            response.raise_for_status()
            job = response.json().get("job")
            if not job:
                time.sleep(3)
                continue
            job_id, duration = job["id"], int(job["duration"])
            print(f"Scan requested: capturing for {duration} seconds...")
            try:
                packets = sniff(iface=args.interface, timeout=duration, store=True)
                result = analyze_packets(packets)
                payload = {"id": job_id, "result": result}
                print(f"Captured {len(packets)} packets; {result['alert_count']} alert(s).")
            except Exception as exc:
                payload = {"id": job_id, "error": str(exc)}
                print("Capture error:", exc)
            posted = session.post(base + "/api/agent/result", json=payload, headers=headers, timeout=30)
            posted.raise_for_status()
            print("Scan result sent to Render.")
        except requests.RequestException as exc:
            print("Cloud connection problem:", exc)
            time.sleep(5)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nNetSentry Agent stopped.")
