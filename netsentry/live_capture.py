"""Optional authorized live capture utility. Run with administrator/root privileges."""
import argparse
from scapy.all import sniff, wrpcap

def main():
    parser = argparse.ArgumentParser(description="Capture packets to a PCAP file for NetSentry analysis.")
    parser.add_argument("-i", "--interface", help="Capture interface name (optional)")
    parser.add_argument("-c", "--count", type=int, default=200, help="Number of packets to capture (default: 200)")
    parser.add_argument("-o", "--output", default="capture.pcap", help="Output PCAP filename")
    args = parser.parse_args()
    print("Capture only on networks/devices you own or are explicitly authorized to monitor.")
    packets = sniff(iface=args.interface, count=args.count)
    wrpcap(args.output, packets)
    print(f"Saved {len(packets)} packets to {args.output}")

if __name__ == "__main__":
    main()
