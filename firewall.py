from scapy.all import sniff, IP, TCP, UDP
import json
import time
import os

RULES_FILE = 'rules.json'
last_modified = 0
blocked_ips = []
blocked_ports = []

# Load blocked IPs and Ports from rules.json
def load_rules():
    global last_modified, blocked_ips, blocked_ports

    # Get the last modified time of the file
    modified_time = os.path.getmtime(RULES_FILE)

    # Reload only if the file is updated
    if modified_time != last_modified:
        print("[INFO] Reloading rules.json...")
        try:
            with open(RULES_FILE, 'r') as f:
                rules = json.load(f)
            blocked_ips = rules.get("blocked_ips", [])
            blocked_ports = rules.get("blocked_ports", [])
            last_modified = modified_time
            print(f"[INFO] Blocked IPs: {blocked_ips}, Blocked Ports: {blocked_ports}")
        except (FileNotFoundError, json.JSONDecodeError):
            print("[WARNING] rules.json missing or corrupted. Using empty block list.")
            blocked_ips = []
            blocked_ports = []

# Callback to process each packet
def packet_callback(packet):
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst

        # Dynamically reload rules every 5 seconds
        load_rules()

        # Check for blocked IPs
        if ip_src in blocked_ips:
            print(f"[BLOCKED] Packet from {ip_src} to {ip_dst}")
            return
        
        # Check for blocked Ports (TCP/UDP)
        if packet.haslayer(TCP) or packet.haslayer(UDP):
            port = packet[TCP].dport if packet.haslayer(TCP) else packet[UDP].dport
            if port in blocked_ports:
                print(f"[BLOCKED] Packet to {ip_dst}:{port}")
                return

        # Allow the packet if it passes both IP and port filters
        print(f"[ALLOWED] Packet: {ip_src} -> {ip_dst}")

# Start sniffing packets
load_rules()
print("Starting packet capture with IP and Port filtering...")
sniff(prn=packet_callback, store=0)
