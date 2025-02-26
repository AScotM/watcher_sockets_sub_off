import time
from datetime import datetime
import argparse
import json

# ANSI escape codes for coloring
COLORS = {
    "ESTABLISHED": "\033[32m",  # Green
    "SYN_SENT": "\033[31m",      # Red
    "SYN_RECV": "\033[31m",      # Red
    "LISTEN": "\033[33m",        # Yellow
    "CLOSE": "\033[31m",         # Red
    "DEFAULT": "\033[0m",        # Reset
    "HEADER": "\033[1;34m",       # Bold Blue for header
    "TIMESTAMP": "\033[1;36m",    # Bold Cyan for timestamp
    "SEPARATOR": "\033[1;30m",    # Light Grey for separator
}

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

def parse_ip(hex_ip):
    """Convert hex IP address to dotted decimal."""
    return ".".join(str(int(hex_ip[i:i + 2], 16)) for i in range(0, 8, 2))

def read_tcp_connections(filter_state=None, filter_ip=None, filter_port=None, output_format="text"):
    """Reads and displays active TCP connections."""
    try:
        with open('/proc/net/tcp', 'r') as file:
            lines = file.readlines()

        connections = []
        for line in lines[1:]:  # Skip header
            line_data = line.split()

            local_address, local_port = line_data[1].split(':')
            peer_address, peer_port = line_data[2].split(':')
            state = line_data[3]

            state_name = TCP_STATES.get(state, "UNKNOWN")
            local_ip = parse_ip(local_address)
            peer_ip = parse_ip(peer_address)
            local_port = int(local_port, 16)
            peer_port = int(peer_port, 16)

            # Apply filters
            if filter_state and state_name != filter_state:
                continue
            if filter_ip and local_ip != filter_ip and peer_ip != filter_ip:
                continue
            if filter_port and local_port != filter_port and peer_port != filter_port:
                continue

            connections.append({
                "local_address": local_ip,
                "local_port": local_port,
                "peer_address": peer_ip,
                "peer_port": peer_port,
                "state": state_name
            })

        if output_format == "json":
            print(json.dumps(connections, indent=2))
        else:
            print(f"{COLORS['TIMESTAMP']}Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\033[0m")
            print(f"{COLORS['HEADER']}Netid  State          Local Address:Port     Peer Address:Port\033[0m")
            print("=" * 70)
            for conn in connections:
                color = COLORS.get(conn["state"], COLORS["DEFAULT"])
                print(f"tcp    {color}{conn['state']:<14}\033[0m {conn['local_address']}:{conn['local_port']:>5}   {conn['peer_address']}:{conn['peer_port']:>5}")
                print(f"{COLORS['SEPARATOR']}--------------------------------------------\033[0m")
            print("=" * 70)

    except FileNotFoundError:
        print("\033[31mError: /proc/net/tcp not found. Are you running on a Linux system?\033[0m")
    except PermissionError:
        print("\033[31mError: Permission denied. Please run as root.\033[0m")

def watch_tcp_connections(interval, filter_state=None, filter_ip=None, filter_port=None, output_format="text"):
    """Continuously monitors TCP connections."""
    try:
        while True:
            read_tcp_connections(filter_state, filter_ip, filter_port, output_format)
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\n\033[33mExiting TCP connection watcher.\033[0m")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Monitor TCP connections.")
    parser.add_argument("--interval", type=int, default=2, help="Update interval in seconds")
    parser.add_argument("--filter-state", type=str, help="Filter by connection state")
    parser.add_argument("--filter-ip", type=str, help="Filter by IP address")
    parser.add_argument("--filter-port", type=int, help="Filter by port number")
    parser.add_argument("--output-format", type=str, choices=["text", "json"], default="text", help="Output format (text or json)")
    args = parser.parse_args()

    watch_tcp_connections(args.interval, args.filter_state, args.filter_ip, args.filter_port, args.output_format)
