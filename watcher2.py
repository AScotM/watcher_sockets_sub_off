import time
from datetime import datetime

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

def read_tcp_connections():
    """Reads and displays active TCP connections."""
    try:
        with open('/proc/net/tcp', 'r') as file:
            lines = file.readlines()

        print(f"{COLORS['TIMESTAMP']}Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\033[0m")
        print(f"{COLORS['HEADER']}Netid  State          Local Address:Port     Peer Address:Port\033[0m")
        print("=" * 70)

        for line in lines[1:]:  # Skip header
            line_data = line.split()

            local_address, local_port = line_data[1].split(':')
            peer_address, peer_port = line_data[2].split(':')
            state = line_data[3]

            state_name = TCP_STATES.get(state, "UNKNOWN")
            color = COLORS.get(state_name, COLORS["DEFAULT"])

            local_ip = parse_ip(local_address)
            peer_ip = parse_ip(peer_address)

            print(f"tcp    {color}{state_name:<14}\033[0m {local_ip}:{int(local_port, 16):>5}   {peer_ip}:{int(peer_port, 16):>5}")

            # Adding a subtle separator between entries for readability
            print(f"{COLORS['SEPARATOR']}--------------------------------------------\033[0m")

        print("=" * 70)

    except FileNotFoundError:
        print("\033[31mError: /proc/net/tcp not found. Are you running on a Linux system?\033[0m")
    except PermissionError:
        print("\033[31mError: Permission denied. Please run as root.\033[0m")

def watch_tcp_connections(interval):
    """Continuously monitors TCP connections."""
    try:
        while True:
            read_tcp_connections()
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\n\033[33mExiting TCP connection watcher.\033[0m")

if __name__ == "__main__":
    watch_tcp_connections(2)
