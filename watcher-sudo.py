#!/usr/bin/env python3
import argparse
import time
import os
import ipaddress
from rich.console import Console
from rich.table import Table
from rich.style import Style

# Initialize Rich console
console = Console()

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

def parse_ip_address(hex_ip: str, ipv6: bool = False) -> str:
    """Converts a hexadecimal IP address to a human-readable format."""
    try:
        if ipv6:
            # Reverse byte order for IPv6
            hex_ip_reversed = "".join(reversed([hex_ip[i:i+2] for i in range(0, len(hex_ip), 2)]))
            ip_int = int(hex_ip_reversed, 16)
            return str(ipaddress.IPv6Address(ip_int))
        else:
            octets = [str(int(hex_ip[i:i+2], 16)) for i in reversed(range(0, 8, 2))]
            return ".".join(octets)
    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] IP parsing error: {e}")
        return "INVALID_IP"

def parse_port(hex_port: str) -> int:
    """Converts a hexadecimal port to an integer."""
    try:
        return int(hex_port, 16)
    except ValueError:
        console.print(f"[bold red]Error:[/bold red] Invalid port: {hex_port}")
        return 0

def get_tcp_state(hex_state: str) -> str:
    """Returns the TCP state name based on the hexadecimal code."""
    return TCP_STATES.get(hex_state, "UNKNOWN")

def read_tcp_connections(ipv6: bool = False) -> list:
    """Reads TCP connections from /proc/net/tcp or /proc/net/tcp6."""
    filepath = "/proc/net/tcp6" if ipv6 else "/proc/net/tcp"
    try:
        with open(filepath, "r") as f:
            lines = f.readlines()
        return lines[1:]  # Skip header line
    except FileNotFoundError:
        console.print(f"[bold red]Error:[/bold red] {filepath} not found.  Are you on Linux?")
        return []
    except PermissionError:
        console.print("[bold red]Error:[/bold red] Permission denied. Run as root.")
        return []
    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] Unexpected error: {e}")
        return []

def parse_connection_line(line: str, ipv6: bool = False) -> dict:
    """Parses a line from /proc/net/tcp and returns a dictionary."""
    parts = line.split()
    if len(parts) < 4:
        console.print(f"[bold yellow]Warning:[/bold yellow] Skipping malformed line: {line.strip()}")
        return None

    local_address_hex, local_port_hex = parts[1].split(":")
    remote_address_hex, remote_port_hex = parts[2].split(":")
    state_hex = parts[3]

    local_address = parse_ip_address(local_address_hex, ipv6)
    local_port = parse_port(local_port_hex)
    remote_address = parse_ip_address(remote_address_hex, ipv6)
    remote_port = parse_port(remote_port_hex)
    state = get_tcp_state(state_hex)

    return {
        "local_address": local_address,
        "local_port": local_port,
        "remote_address": remote_address,
        "remote_port": remote_port,
        "state": state,
    }

def display_connections(connections: list):
    """Displays TCP connections in a Rich table."""
    if not connections:
        console.print("[bold yellow]No connections found.[/bold yellow]")
        return

    table = Table(title="TCP Connections", show_lines=True)
    table.add_column("State", style=Style(bold=True), justify="left")
    table.add_column("Local Address", justify="right")
    table.add_column("Remote Address", justify="right")

    for conn in connections:
        table.add_row(
            conn["state"],
            f"{conn['local_address']}:{conn['local_port']}",
            f"{conn['remote_address']}:{conn['remote_port']}",
        )

    console.print(table)

def main():
    """Main function to parse arguments and start the monitoring."""
    parser = argparse.ArgumentParser(description="Monitor TCP connections.")
    parser.add_argument("--interval", type=int, default=2, help="Update interval in seconds.")
    parser.add_argument("--ipv6", action="store_true", help="Enable IPv6 monitoring.")
    args = parser.parse_args()

    # Check if running as root
    if os.geteuid() != 0:
        console.print("[bold red]Error:[/bold red] This script requires root privileges. Please run with sudo.")
        return

    try:
        while True:
            # Read TCP connections
            connection_lines = read_tcp_connections(ipv6=args.ipv6)

            # Parse connection lines
            connections = []
            for line in connection_lines:
                connection = parse_connection_line(line, ipv6=args.ipv6)
                if connection:  # Skip None values (malformed lines)
                    connections.append(connection)

            # Display connections
            display_connections(connections)
            time.sleep(args.interval)
            # Clear the console for the next iteration
            os.system('cls' if os.name == 'nt' else 'clear') # Clear screen

    except KeyboardInterrupt:
        console.print("[bold yellow]Exiting.[/bold yellow]")

if __name__ == "__main__":
    main()

