from scapy.all import sniff, IP, TCP, UDP
import json
import os
import sys
import time

RULES_FILE = 'rules.json'
last_modified = 0
blocked_ips = []
blocked_ports = []


# =============================
#  Load/Save Rule Functions
# =============================

def load_rules():
    """Load rules from rules.json."""
    global last_modified, blocked_ips, blocked_ports

    # Get the last modified time of the rules file
    if os.path.exists(RULES_FILE):
        modified_time = os.path.getmtime(RULES_FILE)
    else:
        save_rules({"blocked_ips": [], "blocked_ports": []})
        return

    # Reload rules if the file is updated
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
            print("[WARNING] rules.json is missing or corrupted. Resetting...")
            save_rules({"blocked_ips": [], "blocked_ports": []})


def save_rules(rules):
    """Save rules to rules.json."""
    with open(RULES_FILE, 'w') as f:
        json.dump(rules, f, indent=4)
    print("[INFO] Rules updated.")


# =============================
#  Modify IP/Port Rules
# =============================

def modify_rules(action, value, key):
    """Add or remove IPs and ports dynamically."""
    rules = load_rules() or {"blocked_ips": [], "blocked_ports": []}

    if action == "block":
        if value not in rules[key]:
            rules[key].append(value)
            print(f"[INFO] {key[:-1]} {value} blocked.")
        else:
            print(f"[INFO] {key[:-1]} {value} is already blocked.")
    elif action == "unblock":
        if value in rules[key]:
            rules[key].remove(value)
            print(f"[INFO] {key[:-1]} {value} unblocked.")
        else:
            print(f"[INFO] {key[:-1]} {value} not found in block list.")

    save_rules(rules)


def list_rules():
    """List all current blocked IPs and ports."""
    rules = load_rules() or {"blocked_ips": [], "blocked_ports": []}
    print("[INFO] Current Rules:")
    print("Blocked IPs:", rules.get("blocked_ips", []))
    print("Blocked Ports:", rules.get("blocked_ports", []))


# =============================
#  Packet Filtering Callback
# =============================

def packet_callback(packet):
    """Filter packets dynamically based on IP and Port."""
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst

        # Reload rules dynamically on each packet
        load_rules()

        # Check for blocked IP
        if ip_src in blocked_ips:
            print(f"[BLOCKED] Packet from {ip_src} to {ip_dst}")
            return
        
        # Check for blocked Ports (TCP/UDP)
        if packet.haslayer(TCP) or packet.haslayer(UDP):
            port = packet[TCP].dport if packet.haslayer(TCP) else packet[UDP].dport
            if port in blocked_ports:
                print(f"[BLOCKED] Packet to {ip_dst}:{port}")
                return

        # Allow the packet if no block condition is met
        print(f"[ALLOWED] Packet: {ip_src} -> {ip_dst}")


# =============================
#  CLI Management for Rules
# =============================

if __name__ == "__main__":
    if len(sys.argv) > 2:
        cmd, value = sys.argv[1], sys.argv[2]

        # IP Management
        if cmd == "--block-ip":
            modify_rules("block", value, "blocked_ips")
        elif cmd == "--unblock-ip":
            modify_rules("unblock", value, "blocked_ips")

        # Port Management
        elif cmd == "--block-port":
            modify_rules("block", int(value), "blocked_ports")
        elif cmd == "--unblock-port":
            modify_rules("unblock", int(value), "blocked_ports")
    
    # List Rules
    elif len(sys.argv) == 2 and sys.argv[1] == "--list":
        list_rules()
    
    # Start Packet Sniffing (Default)
    else:
        load_rules()
        print("Starting packet capture with IP and Port filtering...")
        sniff(prn=packet_callback, store=0)

        print("Usage:")
        print("  python firewall.py --block-ip <IP>")
        print("  python firewall.py --unblock-ip <IP>")
        print("  python firewall.py --block-port <port>")
        print("  python firewall.py --unblock-port <port>")
        print("  python firewall.py --list")
