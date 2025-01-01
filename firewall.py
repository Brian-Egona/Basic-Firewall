from scapy.all import sniff, IP, TCP, UDP
import json
import os
import sys
import time

RULES_FILE = 'rules.json'
acl_rules = []
last_modified = 0


# =============================
#  Load/Save ACL Rules
# =============================
def load_rules():
    """Load ACL rules from rules.json if updated."""
    global acl_rules, last_modified

    if os.path.exists(RULES_FILE):
        modified_time = os.path.getmtime(RULES_FILE)
        if modified_time != last_modified:
            print("[INFO] Reloading ACL rules...")
            with open(RULES_FILE, 'r') as f:
                rules = json.load(f)
                acl_rules = rules.get("acl_rules", [])
            last_modified = modified_time
    else:
        save_rules({"acl_rules": []})


def save_rules(rules):
    """Save rules to rules.json."""
    with open(RULES_FILE, 'w') as f:
        json.dump(rules, f, indent=4)
    print("[INFO] Rules updated.")


# =============================
#  ACL Rule Management
# =============================
def add_or_update_acl_rule(action, src_ip, dst_ip, protocol, port):
    """Add a new ACL rule or update an existing one dynamically."""
    load_rules()  # Ensure rules are up to date

    # Check if rule already exists
    for rule in acl_rules:
        if rule["src_ip"] == src_ip and rule["dst_ip"] == dst_ip and \
           rule["protocol"] == protocol and rule["port"] == port:
            rule["action"] = action  # Update existing rule
            print(f"[INFO] Updated ACL: {action} {src_ip} -> {dst_ip} (Port: {port}, Protocol: {protocol})")
            save_rules({"acl_rules": acl_rules})
            return

    # Add new rule if not found
    acl_rules.append({
        "action": action,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "protocol": protocol,
        "port": port
    })
    save_rules({"acl_rules": acl_rules})
    print(f"[INFO] Added ACL: {action} {src_ip} -> {dst_ip} (Port: {port}, Protocol: {protocol})")


def list_rules():
    """List current ACL rules."""
    load_rules()  # Ensure rules are up to date
    print(json.dumps(acl_rules, indent=4))


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
                    return  # Stop processing if deny rule is matched
                else:
                    print(f"[ALLOWED] {ip_src} -> {ip_dst} (Port: {port}, Protocol: {protocol})")
                    return  # Allow packet if match is found

        # Default Allow (if no rules matched)
        print(f"[ALLOWED] {ip_src} -> {ip_dst} (Default Allow)")


# =============================
#  CLI Rule Management
# =============================
if __name__ == "__main__":
    load_rules()

    # CLI Commands for Dynamic ACLs
    if len(sys.argv) > 5:
        cmd, action, src_ip, dst_ip, protocol, port = sys.argv[1:]
        if cmd == "--add-acl":
            add_or_update_acl_rule(action, src_ip, dst_ip, protocol, port)
    elif len(sys.argv) == 2 and sys.argv[1] == "--list":
        list_rules()
    else:
        print("Starting firewall with ACL filtering...")
        sniff(prn=packet_callback, store=0)
