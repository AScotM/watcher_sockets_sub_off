import time
from datetime import datetime
import socket
import struct

# ANSI escape codes for coloring
GREEN = "\033[32m"
RED = "\033[31m"
YELLOW = "\033[33m"
BLUE = "\033[34m"
RESET = "\033[0m"

TCP_STATES = {
    "01": "ESTABLISHED",
    "02": "SYN_SENT",
    "03": "SYN_RECV",
    "04": "FIN_WAIT1",
    "05": "FIN_WAIT2",
    "06": "TIME_WAIT",
    "07": "CLOSE",
    "08": "CLOSE_WAIT",
    "09": "LAST_ACK",
    "0A": "LISTEN",
    "0B": "CLOSING",
}

def hex_to_ip(hex_ip):
    """
    Convert hex IP address from /proc/net/tcp to dotted decimal format.
    Handles both IPv4 and IPv6.
    """
    try:
        # IPv4 (8 hex digits)
        if len(hex_ip) == 8:
            # Convert from little-endian hex to bytes and unpack as IPv4
            ip_int = int(hex_ip, 16)
            ip_bytes = ip_int.to_bytes(4, byteorder='little')
            return socket.inet_ntoa(ip_bytes)
        # IPv6 (32 hex digits)
        elif len(hex_ip) == 32:
            # Group into 4-byte chunks and reverse for little-endian
            chunks = [hex_ip[i:i+8] for i in range(0, 32, 8)]
            ip_int = 0
            for i, chunk in enumerate(reversed(chunks)):
                ip_int |= int(chunk, 16) << (32 * i)
            ip_bytes = ip_int.to_bytes(16, byteorder='big')
            return socket.inet_ntop(socket.AF_INET6, ip_bytes)
        else:
            return "INVALID"
    except Exception:
        return "0.0.0.0"

def read_tcp_connections(use_ipv6=False):
    """
    Reads and displays active TCP connections from /proc/net/tcp or /proc/net/tcp6.
    """
    tcp_file = '/proc/net/tcp6' if use_ipv6 else '/proc/net/tcp'
    ip_version = "IPv6" if use_ipv6 else "IPv4"
    
    try:
        with open(tcp_file, 'r') as file:
            lines = file.readlines()

        # Clear screen for better monitoring (optional)
        print("\033c", end="")
        
        # Display headers
        print(f"{GREEN}Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ({ip_version}){RESET}")
        print(f"{YELLOW}Netid  State          Local Address:Port         Peer Address:Port          UID{RESET}")
        print("=" * 90)

        for line in lines[1:]:  # Skip the header
            line_data = line.split()
            
            if len(line_data) < 10:  # Ensure we have enough fields
                continue

            # Extract relevant data
            netid = line_data[0]
            local_address, local_port = line_data[1].split(':')
            peer_address, peer_port = line_data[2].split(':')
            state = line_data[3]
            uid = line_data[7]

            # Decode state
            state_name = TCP_STATES.get(state, "UNKNOWN")

            # Convert addresses from hex to IP
            local_ip = hex_to_ip(local_address)
            peer_ip = hex_to_ip(peer_address)

            # Convert ports from hex to decimal
            local_port_dec = int(local_port, 16)
            peer_port_dec = int(peer_port, 16)

            # Color coding based on connection state
            if state == "01":  # ESTABLISHED
                state_color = GREEN
            elif state in {"02", "03", "04", "05"}:  # Connection setup/teardown
                state_color = YELLOW
            elif state == "0A":  # LISTEN
                state_color = BLUE
            else:  # Other states
                state_color = RED

            # Format and print the output with colors
            print(f"{netid:<5}  {state_color}{state_name:<14}{RESET} "
                  f"{local_ip}:{local_port_dec:<21} "
                  f"{peer_ip}:{peer_port_dec:<21} "
                  f"{uid}")

        print("=" * 90)

    except FileNotFoundError:
        print(f"{RED}Error: {tcp_file} not found. Are you running on a Linux system?{RESET}")
    except PermissionError:
        print(f"{RED}Error: Permission denied. Please run as root or with sufficient privileges.{RESET}")

def watch_tcp_connections(interval=2):
    """
    Continuously monitors TCP connections at the specified interval.
    Monitors both IPv4 and IPv6 connections.
    """
    try:
        while True:
            read_tcp_connections(use_ipv6=False)  # IPv4
            print()  # Add blank line between IPv4 and IPv6 output
            read_tcp_connections(use_ipv6=True)   # IPv6
            time.sleep(interval)
    except KeyboardInterrupt:
        print(f"\n{YELLOW}Exiting TCP connection watcher.{RESET}")

if __name__ == "__main__":
    # Specify the interval in seconds
    interval = 2  # Change this to your desired interval
    watch_tcp_connections(interval)
