from scapy.all import sniff, IP
import json

# Load blocked IPs from rules.json
def load_rules():
    try:
        with open('rules.json', 'r') as f:
            rules = json.load(f)
        return rules.get("blocked_ips", [])
    except FileNotFoundError:
        return []

blocked_ips = load_rules()

def packet_callback(packet):
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        
        # Block packet if source IP is in blocked list
        if ip_src in blocked_ips:
            print(f"[BLOCKED] Packet from {ip_src} to {ip_dst}")
        else:
            print(f"[ALLOWED] Packet: {ip_src} -> {ip_dst}")

# Sniff packets and apply filter
print("Starting packet capture with IP filtering...")
sniff(prn=packet_callback, store=0)
