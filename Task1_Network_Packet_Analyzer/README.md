# Task 1 - Network Packet Analyzer
CODSOFT Cyber Security Internship

A Python tool built on **Scapy** that captures live network packets and shows
source IP, destination IP, protocol, ports, TCP flags, DNS queries and a payload preview
in an organised table, followed by a summary of protocol counts and top talkers.

## Setup
```bash
pip install -r requirements.txt
# Windows only: install Npcap from https://npcap.com
```

## Usage
```bash
sudo python3 packet_analyzer.py                       # capture 50 packets
sudo python3 packet_analyzer.py -c 100 -f "tcp port 80" --payload
sudo python3 packet_analyzer.py -f icmp -c 10         # then ping something in another terminal
sudo python3 packet_analyzer.py --csv out.csv --pcap out.pcap
```
| Option | Meaning |
|---|---|
| `-i` | network interface |
| `-c` | number of packets (0 = until Ctrl+C) |
| `-f` | BPF capture filter |
| `--payload` | print payload preview |
| `--csv` / `--pcap` | save results |

## What I learned
- How Ethernet / IP / TCP / UDP / ICMP layers are nested in a packet
- How TCP flags (SYN, ACK, FIN) show connection setup and teardown
- Why unencrypted protocols (HTTP, FTP, Telnet) expose data and HTTPS does not

## Ethical use
Capture traffic only on networks you own or have written permission to monitor.
