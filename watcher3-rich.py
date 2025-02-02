import time
from datetime import datetime
from rich.console import Console
from rich.table import Table

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

STATE_COLORS = {
    "ESTABLISHED": "green",
    "LISTEN": "yellow",
    "SYN_SENT": "red",
    "SYN_RECV": "red",
    "CLOSE": "red",
    "CLOSE_WAIT": "red",
    "FIN_WAIT1": "magenta",
    "FIN_WAIT2": "magenta",
    "TIME_WAIT": "blue",
    "LAST_ACK": "blue",
    "CLOSING": "blue",
    "UNKNOWN": "white",
}

console = Console()

def parse_ip(hex_ip):
    """Converts a hex-encoded IP address to a human-readable format (IPv4 or IPv6)."""
    if len(hex_ip) == 8:  # IPv4
        return ".".join(str(int(hex_ip[i:i + 2], 16)) for i in range(0, 8, 2))
    elif len(hex_ip) == 32:  # IPv6
        return ":".join(hex_ip[i:i + 4] for i in range(0, 32, 4))
    return "UNKNOWN"

def read_tcp_connections(filename, protocol):
    """Reads active TCP connections from /proc/net/tcp or /proc/net/tcp6."""
    try:
        with open(filename, 'r') as file:
            lines = file.readlines()
    except FileNotFoundError:
        return []
    except PermissionError:
        console.print(f"[bold red]Error: Permission denied for {filename}. Run as root.[/]")
        return []

    connections = []
    for line in lines[1:]:  # Skip header
        line_data = line.split()
        local_address, local_port = line_data[1].split(':')
        peer_address, peer_port = line_data[2].split(':')
        state_code = line_data[3]

        state_name = TCP_STATES.get(state_code, "UNKNOWN")
        color = STATE_COLORS.get(state_name, "white")

        local_ip = parse_ip(local_address)
        peer_ip = parse_ip(peer_address)

        connections.append((protocol, state_name, color, f"{local_ip}:{int(local_port, 16)}", f"{peer_ip}:{int(peer_port, 16)}"))

    return connections

def display_tcp_connections():
    """Fetches and displays active TCP connections from both IPv4 and IPv6 tables."""
    console.clear()
    
    connections = read_tcp_connections("/proc/net/tcp", "TCP") + read_tcp_connections("/proc/net/tcp6", "TCP6")

    if not connections:
        console.print("[bold red]No active TCP connections found.[/]")
        return

    table = Table(title=f"TCP Connections - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", expand=True)
    
    table.add_column("Protocol", style="cyan", justify="left")
    table.add_column("State", style="bold", justify="left")
    table.add_column("Local Address", style="white", justify="left")
    table.add_column("Peer Address", style="white", justify="left")

    for protocol, state, color, local, peer in connections:
        table.add_row(protocol, f"[{color}]{state}[/{color}]", local, peer)

    console.print(table)

def watch_tcp_connections(interval):
    """Continuously monitors TCP connections at the specified interval."""
    try:
        while True:
            display_tcp_connections()
            time.sleep(interval)
    except KeyboardInterrupt:
        console.print("\n[bold yellow]Exiting TCP connection watcher.[/]")

if __name__ == "__main__":
    watch_tcp_connections(2)

