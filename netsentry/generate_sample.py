"""Create a small synthetic PCAP for testing; it does not send network traffic."""
from scapy.all import Ether, IP, TCP, UDP, ICMP, wrpcap

def main():
    packets = []
    # Ordinary illustrative web/DNS traffic
    for i in range(8):
        packets.append(Ether()/IP(src="192.168.1.10", dst="93.184.216.34")/
                       TCP(sport=50000+i, dport=443, flags="S"))
    for i in range(5):
        packets.append(Ether()/IP(src="192.168.1.11", dst="192.168.1.1")/
                       UDP(sport=53000+i, dport=53))
    # Simulated port-scan pattern for detector demonstration
    for port in range(20, 38):
        packets.append(Ether()/IP(src="10.0.0.99", dst="192.168.1.20")/
                       TCP(sport=40000+port, dport=port, flags="S"))
    # ICMP burst example
    for _ in range(40):
        packets.append(Ether()/IP(src="10.0.0.55", dst="192.168.1.1")/ICMP())
    wrpcap("sample_traffic.pcap", packets)
    print("Created sample_traffic.pcap (synthetic packets; nothing was transmitted).")

if __name__ == "__main__":
    main()
