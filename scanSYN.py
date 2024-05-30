from scapy.all import *

# Target IP address
target_ip = "20.20.20.5"

# Port range to scan
port_range = [1, 65535]

# SYN scan
def syn_scan(target_ip, port_range):
    open_ports = []
    for port in range(port_range[0], port_range[1]+1):
        # Create packets
        ip = IP(dst=target_ip)
        syn = TCP(dport=port, flags="S")
        
        # Send the packet
        packet = ip/syn
        response = sr1(packet, timeout=1, verbose=False)
        
        # Check for SYN-ACK response
        if response:
            if response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:
                open_ports.append(port)
    return open_ports

# Perform the scan and print open ports
open_ports = syn_scan(target_ip, port_range)
print("Open ports:", open_ports)
