import time

def read_tcp_connections():
    with open('/proc/net/tcp', 'r') as file:
        # Read the lines and process the data
        lines = file.readlines()
        # Display headers
        print("Netid  State      Local Address:Port       Peer Address:Port")
        for line in lines[1:]:  # Skip the first line (headers)
            line_data = line.split()
            # Extract relevant information
            netid = line_data[0]
            local_address, local_port = line_data[1].split(':')
            peer_address, peer_port = line_data[2].split(':')
            state = line_data[3]
            # Convert addresses from hex to IP format
            local_address = '.'.join(str(int(local_address[i:i + 2], 16)) for i in range(0, 8, 2))
            peer_address = '.'.join(str(int(peer_address[i:i + 2], 16)) for i in range(0, 8, 2))
            # Display formatted output
            print(f"{netid}    {state:<10} {local_address}:{int(local_port, 16)}       {peer_address}:{int(peer_port, 16)}")

def watch_tcp_connections(interval):
    while True:
        read_tcp_connections()
        time.sleep(interval)

if __name__ == "__main__":
    # Specify the interval in seconds
    interval = 2  # Change this to your desired interval
    watch_tcp_connections(interval)

