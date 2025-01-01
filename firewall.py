from scapy.all import sniff, IP, TCP, UDP
import json
import os
import sys
from datetime import datetime

RULES_FILE = 'rules.json'
LOG_FILE = 'firewall.log'
acl_rules = []


# =============================
#  Load/Save ACL Rules
# =============================
def load_rules():
    """Load ACL rules from rules.json."""
    global acl_rules

    if os.path.exists(RULES_FILE):
        with open(RULES_FILE, 'r') as f:
            rules = json.load(f)
            acl_rules = rules.get("acl_rules", [])
    else:
        save_rules({"acl_rules": []})


def save_rules(rules):
    """Save rules to rules.json."""
    with open(RULES_FILE, 'w') as f:
        json.dump(rules, f, indent=4)
    print("[INFO] Rules updated.")


# =============================
#  Logging Blocked Packets
# =============================
def log_blocked_packet(ip_src, ip_dst, protocol, port):
    """Log blocked packets to firewall.log."""
    with open(LOG_FILE, 'a') as f:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        f.write(f"{timestamp} - BLOCKED: {ip_src} -> {ip_dst} (Port: {port}, Protocol: {protocol})\n")
    print(f"[LOGGED] {ip_src} -> {ip_dst} (Port: {port}, Protocol: {protocol})")


# =============================
#  ACL Packet Filtering
# =============================
def packet_callback(packet):
    """Apply ACL filtering to incoming packets."""
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = "tcp" if packet.haslayer(TCP) else "udp" if packet.haslayer(UDP) else "any"
        port = packet[TCP].dport if packet.haslayer(TCP) else packet[UDP].dport if packet.haslayer(UDP) else "any"

        # Dynamically reload rules before applying ACL
        load_rules()

        # Apply ACL Rules (Top-Down)
        for rule in acl_rules:
            if (
                (rule["src_ip"] == "any" or rule["src_ip"] == ip_src) and
                (rule["dst_ip"] == "any" or rule["dst_ip"] == ip_dst) and
                (rule["protocol"] == "any" or rule["protocol"] == protocol) and
                (rule["port"] == "any" or str(rule["port"]) == str(port))
            ):
                if rule["action"] == "deny":
                    print(f"[BLOCKED] {ip_src} -> {ip_dst} (Port: {port}, Protocol: {protocol})")
                    log_blocked_packet(ip_src, ip_dst, protocol, port)
                    return  # Stop processing if deny rule is matched
                else:
                    print(f"[ALLOWED] {ip_src} -> {ip_dst} (Port: {port}, Protocol: {protocol})")
                    return  # Allow packet if match is found

        # Default Allow (if no rules matched)
        print(f"[ALLOWED] {ip_src} -> {ip_dst} (Default Allow)")


# =============================
#  CLI Rule Management
# =============================
def add_acl_rule(action, src_ip, dst_ip, protocol, port):
    """Add a new ACL rule dynamically."""
    acl_rules.append({
        "action": action,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "protocol": protocol,
        "port": port
    })
    save_rules({"acl_rules": acl_rules})
    print(f"[INFO] Added ACL: {action} {src_ip} -> {dst_ip} (Port: {port}, Protocol: {protocol})")


if __name__ == "__main__":
    load_rules()

    # CLI Commands for Dynamic ACLs
    if len(sys.argv) > 5:
        cmd, action, src_ip, dst_ip, protocol, port = sys.argv[1:]
        if cmd == "--add-acl":
            add_acl_rule(action, src_ip, dst_ip, protocol, port)
    elif len(sys.argv) == 2 and sys.argv[1] == "--list":
        print(json.dumps(acl_rules, indent=4))
    else:
        print("Starting firewall with ACL filtering...")
        sniff(prn=packet_callback, store=0)
