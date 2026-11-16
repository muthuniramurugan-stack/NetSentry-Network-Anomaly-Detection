import unittest
from scapy.all import Ether, IP, TCP, ICMP
from netsentry.analyzer import analyze_packets

class AnalyzerTests(unittest.TestCase):
    def test_port_scan_alert(self):
        packets = [Ether()/IP(src="10.0.0.2", dst="10.0.0.3")/TCP(dport=p, flags="S")
                   for p in range(1, 16)]
        result = analyze_packets(packets)
        self.assertTrue(any(a["title"] == "Possible port scan" for a in result["alerts"]))

    def test_icmp_burst_alert(self):
        packets = [Ether()/IP(src="10.0.0.4", dst="10.0.0.1")/ICMP() for _ in range(40)]
        result = analyze_packets(packets)
        self.assertTrue(any(a["title"] == "ICMP burst" for a in result["alerts"]))

    def test_packet_count(self):
        packets = [Ether()/IP(src="1.1.1.1", dst="2.2.2.2")/TCP(dport=80)]
        self.assertEqual(analyze_packets(packets)["total_packets"], 1)

if __name__ == "__main__":
    unittest.main()
