from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
UPLOAD_DIR = ROOT / "uploads"
ALLOWED_EXTENSIONS = {"pcap", "pcapng"}
# Detection thresholds are intentionally configurable and suitable for lab/demo captures.
SYN_FLOOD_THRESHOLD = 40       # SYN packets from one source in the observation window
PORT_SCAN_THRESHOLD = 12      # distinct destination ports from one source
ICMP_BURST_THRESHOLD = 35     # ICMP packets from one source
HIGH_PACKET_THRESHOLD = 500   # packets from one source
