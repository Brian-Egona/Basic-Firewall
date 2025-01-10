# Basic-Firewall

## Overview
This is a basic Python-based firewall built using Scapy that filters incoming and outgoing packets based on user-defined rules. It implements a mock Access Control Lists (ACLs) to dynamically allow or deny packets based on IP addresses, ports, and protocols.

## Features
- **Dynamic Rule Management**: Add or remove ACL rules using CLI commands without restarting the firewall.
- **Port and IP Filtering**: Block or allow traffic based on IP addresses, ports, and protocols.
- **Logging**: Logs blocked packets with timestamps for later review.
- **Real-time Packet Filtering**: Captures and filters packets in real-time using Scapy.
- **Persistent Rules**: Firewall rules are stored in `rules.json` and persist across sessions.

## Installation
### Prerequisites
- Python 3.x
- Scapy (`pip install scapy`)
- Npcap (for Windows) or libpcap (for Linux/MacOS)

### Setup
1. Clone the repository:
   `
   git clone https://github.com/Brian-Egona/Basic-Firewall.git
   cd Basic-Firewall
   `
2. Install required dependencies:
    `
    pip install -r requirements.txt
    `
3. Run the firewall:
   `
    python firewall.py
   `

### Usage
After the firewall is launched and live packet capture begins, the firewall will monitor and filter traffic based on the rules defined in rules.json(the mock ACL). 
On a different terminal, you can perform the follwing:
1. List Current Rules
   `
   python firewall.py --list
   `
2. Add ACL Rule (Deny or Allow an IP or Port)
    `
    python firewall.py --add-acl <action> <src_ip> <dst_ip> <protocol> <port>
    `
    - Example to block SSH (port 22) from a specific IP:
      `python firewall.py --add-acl deny 192.168.1.100 any tcp 22`
    - Example to allow HTTPS (port 443) traffic:
      `python firewall.py --add-acl allow any any tcp 443`
    - Example to block multicast traffic:
    - `python firewall.py --add-acl deny any 224.0.0.251 udp 5353`

### Testing the Firewall
A simple way to test the firewall is by taking the following steps:
1. Launch the Firewall:
- Start the firewall to begin live packet capture and filtering.
2. Block/Deny a Target IP:
- Use the CLI to block the IP address of a virtual machine (VM) on your device or another remote system.
3. Initiate a Ping Test:
- From the blocked VM or remote device, attempt to ping your local machine's IP address.
4. Monitor Live Captures:
- Observe the live packet captures displayed by the firewall in real-time.
5. Verify Blocked Traffic:
- Look for log entries or console output indicating that the ping packets from the blocked IP were intercepted and denied by the firewall.

By following this process, you can confirm that the firewall correctly identifies and blocks unauthorized traffic, ensuring enhanced security for your network.





