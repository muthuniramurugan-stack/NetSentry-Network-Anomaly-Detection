from collections import Counter, defaultdict
from pathlib import Path
from datetime import datetime
from scapy.all import rdpcap, IP, TCP, UDP, ICMP
from .config import (SYN_FLOOD_THRESHOLD, PORT_SCAN_THRESHOLD,
                     ICMP_BURST_THRESHOLD, HIGH_PACKET_THRESHOLD)

def _new_stats():
    return {
        "total_packets": 0, "protocols": Counter(), "src_ips": Counter(),
        "dst_ips": Counter(), "dst_ports": Counter(), "syn_by_src": Counter(),
        "ports_by_src": defaultdict(set), "icmp_by_src": Counter(),
        "bytes_by_src": Counter(), "alerts": []
    }

def analyze_packets(packets):
    s = _new_stats()
    for pkt in packets:
        s["total_packets"] += 1
        length = len(pkt)
        if IP not in pkt:
            s["protocols"]["Non-IP"] += 1
            continue
        ip = pkt[IP]
        src, dst = ip.src, ip.dst
        s["src_ips"][src] += 1
        s["dst_ips"][dst] += 1
        s["bytes_by_src"][src] += length

        if TCP in pkt:
            s["protocols"]["TCP"] += 1
            tcp = pkt[TCP]
            s["dst_ports"][str(tcp.dport)] += 1
            s["ports_by_src"][src].add(int(tcp.dport))
            # SYN set and ACK not set: initial TCP connection attempt
            if int(tcp.flags) & 0x02 and not (int(tcp.flags) & 0x10):
                s["syn_by_src"][src] += 1
        elif UDP in pkt:
            s["protocols"]["UDP"] += 1
            udp = pkt[UDP]
            s["dst_ports"][str(udp.dport)] += 1
            s["ports_by_src"][src].add(int(udp.dport))
        elif ICMP in pkt:
            s["protocols"]["ICMP"] += 1
            s["icmp_by_src"][src] += 1
        else:
            s["protocols"][f"IP protocol {ip.proto}"] += 1

    alerts = []
    for src, count in s["syn_by_src"].most_common():
        if count >= SYN_FLOOD_THRESHOLD:
            alerts.append(_alert("High SYN volume", "High", src,
                f"{count} initial TCP SYN packets observed. This may indicate a SYN flood or aggressive connection activity."))
    for src, ports in s["ports_by_src"].items():
        if len(ports) >= PORT_SCAN_THRESHOLD:
            alerts.append(_alert("Possible port scan", "High", src,
                f"Traffic contacted {len(ports)} distinct destination ports."))
    for src, count in s["icmp_by_src"].most_common():
        if count >= ICMP_BURST_THRESHOLD:
            alerts.append(_alert("ICMP burst", "Medium", src,
                f"{count} ICMP packets observed from this source."))
    for src, count in s["src_ips"].most_common():
        if count >= HIGH_PACKET_THRESHOLD:
            alerts.append(_alert("High packet volume", "Medium", src,
                f"{count} packets observed from this source in this capture."))

    return {
        "total_packets": s["total_packets"],
        "unique_sources": len(s["src_ips"]),
        "unique_destinations": len(s["dst_ips"]),
        "protocols": dict(s["protocols"].most_common()),
        "top_sources": s["src_ips"].most_common(8),
        "top_destinations": s["dst_ips"].most_common(8),
        "top_ports": s["dst_ports"].most_common(8),
        "alerts": alerts,
        "alert_count": len(alerts),
        "source_bytes": s["bytes_by_src"].most_common(8),
    }

def _alert(title, severity, source, details):
    return {"title": title, "severity": severity, "source": source, "details": details}

def analyze_pcap(path):
    packets = rdpcap(str(path))
    return analyze_packets(packets)

def demo_analysis():
    # Deterministic, clearly labelled illustrative results; no real traffic is captured.
    return {
        "demo": True, "total_packets": 1240, "unique_sources": 7,
        "unique_destinations": 19,
        "protocols": {"TCP": 810, "UDP": 310, "ICMP": 120},
        "top_sources": [("192.168.1.20", 610), ("192.168.1.15", 280), ("10.0.0.8", 160)],
        "top_destinations": [("192.168.1.1", 520), ("93.184.216.34", 220), ("10.0.0.12", 140)],
        "top_ports": [("443", 420), ("80", 190), ("53", 150), ("22", 70)],
        "source_bytes": [("192.168.1.20", 810000), ("192.168.1.15", 420000)],
        "alert_count": 3,
        "alerts": [
            _alert("Possible port scan", "High", "192.168.1.20", "Traffic contacted 24 distinct destination ports."),
            _alert("High SYN volume", "High", "192.168.1.15", "67 initial TCP SYN packets observed."),
            _alert("ICMP burst", "Medium", "10.0.0.8", "48 ICMP packets observed from this source.")
        ]
    }
