from scapy.all import IP, ICMP, TCP, sr1
import sys

# Function to check if a port is open on a host
def scan_ports(ip, ports):
    open_ports = []
    for port in ports:
        packet = IP(dst=ip) / TCP(dport=port, flags="S")  # SYN packet to check if port is open
        response = sr1(packet, timeout=1, verbose=0)  # Send the packet and wait for a response
        
        if response:
            if response.haslayer(TCP) and response.getlayer(TCP).flags == 18:  # SYN+ACK -> Port is open
                open_ports.append(port)
                print(f"Port {port} is OPEN.")
            else:
                print(f"Port {port} is CLOSED.")
        else:
            print(f"Port {port} is FILTERED (no response).")
    
    return open_ports

# Function to detect live hosts and scan ports
def detect_live_hosts_and_scan_ports(network_prefix, ports):
    print(f"Scanning network: {network_prefix}...\n")

    for i in range(1, 255):
        ip = f"{network_prefix}.{i}"
        # Send an ICMP ping request to the IP address to check if it's live
        packet = IP(dst=ip)/ICMP()
        reply = sr1(packet, timeout=1, verbose=False)

        if reply:
            print(f"Host {ip} is live.")
            # Scan ports for the live host
            open_ports = scan_ports(ip, ports)
            if open_ports:
                print(f"Open ports for {ip}: {open_ports}")
            else:
                print(f"No open ports found for {ip}.")
        else:
            print(f"Host {ip} is down.")

# Example usage: change network prefix to your local network range
if __name__ == "__main__":
    network_prefix = input("Enter the network prefix (e.g., 192.168.1): ")
    ports = [22, 80, 443, 8080]  # Ports to scan, you can add more ports as needed
    detect_live_hosts_and_scan_ports(network_prefix, ports)

