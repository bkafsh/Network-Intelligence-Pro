Network Intelligence Pro v1.0
Network Intelligence Pro is a comprehensive, Python-based desktop utility designed for network discovery, security auditing, and diagnostics. It provides a graphical user interface (GUI) to simplify complex networking tasks such as subnet calculation, SSL certificate verification, and advanced port scanning.

🚀 Features
1. Local Discovery
Adapter Detection: Automatically maps active network interfaces using PowerShell.

Network Mapping: Scans local IP ranges to identify online hosts.

Vendor Identification: Resolves MAC addresses to known hardware vendors (e.g., Apple, Cisco, VMware).

Hostname Resolution: Automatically attempts to resolve hostnames for discovered devices.

2. Advanced Port Scanner
Multi-Protocol Support: Scans both TCP and UDP ports.

BACnet Mode: Specialized preset for Industrial Control Systems (ICS) scanning on port 47808.

Service Mapping: Automatically identifies common services associated with open ports.

Multi-threaded: Fast execution using non-blocking socket operations.

3. Networking Toolset
Subnet Calculator: Quickly determine network/broadcast addresses and usable IP ranges.

SSL Verifier: Check the expiration date and validity of SSL certificates for any domain.

IP Lookup: Integrated Geolocation and Organization (ISP) lookup via ipapi.co.

Traceroute: Visual hop-by-hop diagnostic tool to identify routing paths and latency.

🛠️ Requirements
Operating System: Windows (Required for tracert, arp -a, and PowerShell adapter discovery).

Python: 3.x

Standard Libraries: tkinter, socket, threading, subprocess, ssl, json.

🛡️ Disclaimer
This tool is intended for educational and professional network administration purposes only. Always ensure you have explicit permission before scanning networks or devices you do not own.

✍️ Author
Version: 1.0

Built for: Babak Afshari
