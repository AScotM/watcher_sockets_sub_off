import time
from datetime import datetime

# ANSI escape codes for coloring
GREEN = "\033[32m"
RED = "\033[31m"
YELLOW = "\033[33m"
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

def read_tcp_connections():
    """
    Reads and displays active TCP connections from /proc/net/tcp.
    """
    try:
        with open('/proc/net/tcp', 'r') as file:
            # Read and parse the lines
            lines = file.readlines()

        # Display headers
        print(f"{GREEN}Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{RESET}")
        print(f"{YELLOW}Netid  State          Local Address:Port         Peer Address:Port{RESET}")
        print("=" * 70)

        for line in lines[1:]:  # Skip the header
            line_data = line.split()

            # Extract relevant data
            netid = line_data[0]
            local_address, local_port = line_data[1].split(':')
            peer_address, peer_port = line_data[2].split(':')
            state = line_data[3]

            # Decode state
            state_name = TCP_STATES.get(state, "UNKNOWN")

            # Convert addresses from hex to IP
            local_address = '.'.join(str(int(local_address[i:i + 2], 16)) for i in range(0, 8, 2))
            peer_address = '.'.join(str(int(peer_address[i:i + 2], 16)) for i in range(0, 8, 2))

            # Format and print the output with colors
            state_color = GREEN if state == "01" else RED if state in {"02", "03"} else RESET
            print(f"{netid:<5}  {state_color}{state_name:<14}{RESET} {local_address}:{int(local_port, 16):<15} {peer_address}:{int(peer_port, 16)}")

        print("=" * 70)

    except FileNotFoundError:
        print(f"{RED}Error: /proc/net/tcp not found. Are you running on a Linux system?{RESET}")
    except PermissionError:
        print(f"{RED}Error: Permission denied. Please run as root or with sufficient privileges.{RESET}")

def watch_tcp_connections(interval):
    """
    Continuously monitors TCP connections at the specified interval.
    """
    try:
        while True:
            read_tcp_connections()
            time.sleep(interval)
    except KeyboardInterrupt:
        print(f"\n{YELLOW}Exiting TCP connection watcher.{RESET}")

if __name__ == "__main__":
    # Specify the interval in seconds
    interval = 2  # Change this to your desired interval
    watch_tcp_connections(interval)
