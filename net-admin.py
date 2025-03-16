import os
import time
import json
import signal
from datetime import datetime

# ANSI escape codes for coloring
COLORS = {
    "ESTABLISHED": "\033[32m",  # Green
    "SYN_SENT": "\033[31m",     # Red
    "SYN_RECV": "\033[31m",     # Red
    "LISTEN": "\033[33m",       # Yellow
    "CLOSE": "\033[31m",        # Red
    "DEFAULT": "\033[0m",       # Reset
    "HEADER": "\033[1;34m",     # Bold Blue for header
    "TIMESTAMP": "\033[1;36m",  # Bold Cyan for timestamp
    "SEPARATOR": "\033[1;30m",  # Light Grey for separator
}

# TCP state mappings
TCP_STATES = {
    "01": "ESTABLISHED", "02": "SYN_SENT", "03": "SYN_RECV", "04": "FIN_WAIT1",
    "05": "FIN_WAIT2", "06": "TIME_WAIT", "07": "CLOSE", "08": "CLOSE_WAIT",
    "09": "LAST_ACK", "0A": "LISTEN", "0B": "CLOSING"
}

# Convert hex IP to dotted decimal

def parse_ipv4(hex_ip):
    return ".".join(str(int(hex_ip[i:i+2], 16)) for i in range(6, -1, -2))

def parse_ipv6(hex_ip):
    return ":".join(hex_ip[i:i+4] for i in range(0, 32, 4))

def read_tcp_connections(protocol="tcp", filter_state=None, filter_ip=None, filter_port=None, output_format="text"):
    proc_file = f"/proc/net/{protocol}"
    if not os.path.exists(proc_file):
        print(f"\033[31mError: {proc_file} not found. Are you on a Linux system?\033[0m")
        return []
    
    connections = []
    with open(proc_file, "r") as file:
        next(file)  # Skip header
        for line in file:
            fields = line.split()
            local_hex, local_port_hex = fields[1].split(":")
            peer_hex, peer_port_hex = fields[2].split(":")
            state_hex = fields[3]
            state = TCP_STATES.get(state_hex, "UNKNOWN")
            
            local_ip = parse_ipv6(local_hex) if "6" in protocol else parse_ipv4(local_hex)
            peer_ip = parse_ipv6(peer_hex) if "6" in protocol else parse_ipv4(peer_hex)
            local_port = int(local_port_hex, 16)
            peer_port = int(peer_port_hex, 16)
            
            # Apply filters
            if filter_state and state != filter_state:
                continue
            if filter_ip and filter_ip not in (local_ip, peer_ip):
                continue
            if filter_port and filter_port not in (local_port, peer_port):
                continue
            
            connections.append({
                "protocol": protocol,
                "state": state,
                "local_address": local_ip,
                "local_port": local_port,
                "peer_address": peer_ip,
                "peer_port": peer_port,
            })
    
    return connections

def display_connections(connections, output_format):
    if output_format == "json":
        print(json.dumps(connections, indent=2))
    else:
        print(f"{COLORS['TIMESTAMP']}Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\033[0m")
        print(f"{COLORS['HEADER']}Netid  State          Local Address:Port     Peer Address:Port\033[0m")
        print("=" * 70)
        for conn in connections:
            color = COLORS.get(conn["state"], COLORS["DEFAULT"])
            print(f"tcp    {color}{conn['state']:<14}\033[0m {conn['local_address']}:{conn['local_port']:<5}   {conn['peer_address']}:{conn['peer_port']:<5}")
            print(f"{COLORS['SEPARATOR']}--------------------------------------------\033[0m")
        print("=" * 70)

def watch_tcp_connections(interval=2, filter_state=None, filter_ip=None, filter_port=None, output_format="text"):
    def signal_handler(sig, frame):
        print("\n\033[33mExiting TCP connection watcher.\033[0m")
        exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    
    while True:
        connections = read_tcp_connections("tcp", filter_state, filter_ip, filter_port, output_format)
        connections += read_tcp_connections("tcp6", filter_state, filter_ip, filter_port, output_format)
        display_connections(connections, output_format)
        time.sleep(interval)

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Monitor TCP connections (IPv4 & IPv6)")
    parser.add_argument("--interval", type=int, default=2, help="Update interval in seconds")
    parser.add_argument("--filter-state", type=str, help="Filter by TCP state")
    parser.add_argument("--filter-ip", type=str, help="Filter by IP address")
    parser.add_argument("--filter-port", type=int, help="Filter by port")
    parser.add_argument("--output-format", choices=["text", "json"], default="text", help="Output format")
    args = parser.parse_args()
    
    if args.interval <= 0:
        print("\033[31mError: Interval should be a positive integer.\033[0m")
        exit(1)
    
    watch_tcp_connections(args.interval, args.filter_state, args.filter_ip, args.filter_port, args.output_format)
