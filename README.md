# Java Network Intrusion Detection System (IDS)

## Overview
This project is a simple Intrusion Detection System (IDS) built in Java using the Pcap4J library. It captures live network traffic and detects suspicious activity such as port scanning and ICMP (ping) activity.

## Features
Captures live packets from a selected network interface
Detects TCP port scans based on multiple destination ports
Monitors ICMP traffic and summarizes activity
Works with VirtualBox VM to simulate attacker traffic
Change the filter to whichever device if you want to test locally, on the internet, or over a VM

## How to Run
Install Npcap
Run the program in Eclipse
Run with a terminal or over the VM terminal
Run "ipconfig" on your Command prompt to figure out your IP address to use for testing
Run "ip a" on your VM terminal to figure out the machines IP for testing
Select the correct network interface
Run ping corresponding with your IP on your local machine.

## Expected Output 
Expected output:
```
[ICMP] Packet received from ...

```
```
[TCP SYN] ...
[ALERT] Possible port scan detected
```

## Notes
- Windows Firewall may block some scan results  
- SYN scan (`-sS`) is required for detection  
- Host-only networking provides cleaner results than bridged mode  

## Author
Alex Stanford  
University of North Florida  
