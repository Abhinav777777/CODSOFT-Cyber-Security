#!/usr/bin/env python3
"""
Network Packet Analyzer
CODSOFT Cyber Security Internship - Task 1

Captures live packets with Scapy, extracts source/destination IP, protocol,
ports, flags and a payload preview, and prints them as an organised table.
Optionally saves results to CSV and the raw packets to a .pcap file.

Run with admin/root rights, and only on networks you own or have permission to monitor.
"""
import argparse
import csv
from collections import Counter
from datetime import datetime

from scapy.all import (ARP, DNS, DNSQR, ICMP, IP, TCP, UDP, IPv6, Raw,
                       sniff, wrpcap)

PROTOCOLS = {1: "ICMP", 6: "TCP", 17: "UDP"}
HEADER = f"{'No':<5}{'Time':<10}{'Source':<22}{'Destination':<22}{'Proto':<7}{'Sport':<7}{'Dport':<7}{'Len':<6}Info"

stats = Counter()
rows = []
packets = []


def payload_preview(pkt, limit=40):
    """Return the first bytes of the payload as printable text."""
    if Raw in pkt:
        data = bytes(pkt[Raw].load)[:limit]
        return "".join(chr(b) if 32 <= b < 127 else "." for b in data)
    return ""


def analyze(pkt, show_payload):
    """Extract the key fields from one packet and print a table row."""
    if IP in pkt:
        src, dst = pkt[IP].src, pkt[IP].dst
        proto = PROTOCOLS.get(pkt[IP].proto, f"OTHER({pkt[IP].proto})")
    elif IPv6 in pkt:
        src, dst, proto = pkt[IPv6].src, pkt[IPv6].dst, "IPv6"
    elif ARP in pkt:
        src, dst, proto = pkt[ARP].psrc, pkt[ARP].pdst, "ARP"
    else:
        return  # ignore non-IP traffic

    sport = dport = ""
    info = ""
    if TCP in pkt:
        sport, dport = pkt[TCP].sport, pkt[TCP].dport
        info = f"flags={pkt[TCP].flags}"
    elif UDP in pkt:
        sport, dport = pkt[UDP].sport, pkt[UDP].dport
    elif ICMP in pkt:
        info = f"type={pkt[ICMP].type} code={pkt[ICMP].code}"
    elif ARP in pkt:
        info = "who-has" if pkt[ARP].op == 1 else "is-at"

    if DNS in pkt and pkt.haslayer(DNSQR):
        info = "DNS query: " + pkt[DNSQR].qname.decode(errors="ignore")

    data = payload_preview(pkt)
    stats[proto] += 1
    packets.append(pkt)
    row = {
        "no": len(packets), "time": datetime.now().strftime("%H:%M:%S"),
        "src": src, "dst": dst, "protocol": proto, "sport": sport,
        "dport": dport, "length": len(pkt), "info": info, "payload": data,
    }
    rows.append(row)
    print(f"{row['no']:<5}{row['time']:<10}{src:<22}{dst:<22}{proto:<7}"
          f"{str(sport):<7}{str(dport):<7}{row['length']:<6}{info}")
    if show_payload and data:
        print(f"      payload: {data}")


def summary():
    print("\n" + "=" * 40 + "\nCAPTURE SUMMARY\n" + "=" * 40)
    print(f"Total packets analysed: {len(packets)}")
    for proto, count in stats.most_common():
        print(f"  {proto:<10}{count}")
    talkers = Counter(r["src"] for r in rows).most_common(3)
    if talkers:
        print("Top talkers:")
        for ip, count in talkers:
            print(f"  {ip:<22}{count} packets")


def main():
    p = argparse.ArgumentParser(description="Simple network packet analyzer (Scapy)")
    p.add_argument("-i", "--iface", help="network interface (default: Scapy's default)")
    p.add_argument("-c", "--count", type=int, default=50, help="packets to capture (0 = until Ctrl+C)")
    p.add_argument("-f", "--filter", default="", help="BPF filter, e.g. 'tcp port 80' or 'icmp'")
    p.add_argument("--payload", action="store_true", help="show a payload preview")
    p.add_argument("--csv", help="save analysed packets to this CSV file")
    p.add_argument("--pcap", help="save raw packets to this .pcap file (open in Wireshark)")
    args = p.parse_args()

    print(f"Sniffing on {args.iface or 'default interface'} | filter: '{args.filter or 'none'}' | Ctrl+C to stop\n")
    print(HEADER)
    print("-" * 110)
    try:
        sniff(iface=args.iface, filter=args.filter, count=args.count,
              prn=lambda pkt: analyze(pkt, args.payload), store=False)
    except KeyboardInterrupt:
        pass
    except PermissionError:
        raise SystemExit("Permission denied: run with sudo (Linux/macOS) or as Administrator (Windows).")

    summary()
    if args.csv and rows:
        with open(args.csv, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=rows[0].keys())
            writer.writeheader()
            writer.writerows(rows)
        print(f"Saved CSV  -> {args.csv}")
    if args.pcap and packets:
        wrpcap(args.pcap, packets)
        print(f"Saved PCAP -> {args.pcap}")


if __name__ == "__main__":
    main()
