# Network Analyzer
A program that analyzes and categorizes network traffic based on the protocol used and turns it into a neat pie chart.

# Get Started
1. Clone this repo
2. Install dependencies `python3 -m pip install -r requirements.txt` and Npcap: https://npcap.com/#download
3. Run the program `python3 Analyzer.py`
4. Select a network interface
5. (optional) Select where to output a pcap file

# Supported Protocols
1. HTTP
2. HTTPS
3. ARP
4. DNS
5. FTP
6. SMB
7. SSH
8. Telnet
9. BitTorrent
10. ICMP
11. TCP
12. UDP
<br>
Any unrecognized traffic will be labeled as "Other".
