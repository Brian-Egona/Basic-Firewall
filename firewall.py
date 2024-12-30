from scapy.all import sniff, IP
import json
import time
import os

RULES_FILE = 'rules.json'
last_modified = 0
blocked_ips = []

# Load blocked IPs from rules.json
def load_rules():
    global last_modified, blocked_ips

    # Get the last modified time of the file
    modified_time = os.path.getmtime(RULES_FILE)

    # Reload only if the file is updated
    if modified_time != last_modified:
        print("[INFO] Reloading rules.json...")
        try:
            with open(RULES_FILE, 'r') as f:
                rules = json.load(f)
            blocked_ips = rules.get("blocked_ips", [])
            last_modified = modified_time
        except (FileNotFoundError, json.JSONDecodeError):
            print("[WARNING] rules.json missing or corrupted. Using empty block list.")
            blocked_ips = []

# Callback to process each packet
def packet_callback(packet):
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst

        # Dynamically reload rules every 5 seconds
        load_rules()

        if ip_src in blocked_ips:
            print(f"[BLOCKED] Packet from {ip_src} to {ip_dst}")
        else:
            print(f"[ALLOWED] Packet: {ip_src} -> {ip_dst}")

# Start sniffing packets
print("Starting packet capture with IP filtering...")
sniff(prn=packet_callback, store=0)
