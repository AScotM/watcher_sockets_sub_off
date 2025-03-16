#!/usr/bin/perl
use strict;
use warnings;
use Time::HiRes qw(sleep);
use POSIX qw(strftime);
use Getopt::Long;
use JSON;

# ANSI escape codes for coloring
my %COLORS = (
    "ESTABLISHED" => "\033[32m",  # Green
    "SYN_SENT"    => "\033[31m",  # Red
    "SYN_RECV"    => "\033[31m",  # Red
    "LISTEN"      => "\033[33m",  # Yellow
    "CLOSE"       => "\033[31m",  # Red
    "DEFAULT"     => "\033[0m",   # Reset
    "HEADER"      => "\033[1;34m", # Bold Blue for header
    "TIMESTAMP"   => "\033[1;36m", # Bold Cyan for timestamp
    "SEPARATOR"   => "\033[1;30m", # Light Grey for separator
);

# TCP state mappings
my %TCP_STATES = (
    "01" => "ESTABLISHED",
    "02" => "SYN_SENT",
    "03" => "SYN_RECV",
    "04" => "FIN_WAIT1",
    "05" => "FIN_WAIT2",
    "06" => "TIME_WAIT",
    "07" => "CLOSE",
    "08" => "CLOSE_WAIT",
    "09" => "LAST_ACK",
    "0A" => "LISTEN",
    "0B" => "CLOSING",
);

# Convert hex IP to dotted decimal notation
sub parse_ip {
    my ($hex_ip) = @_;
    return join(".", map { hex($_) } unpack("A2 A2 A2 A2", $hex_ip));
}

# Read active TCP connections
sub read_tcp_connections {
    my ($filter_state, $filter_ip, $filter_port, $output_format) = @_;
    
    open my $fh, '<', '/proc/net/tcp' or do {
        print "\033[31mError: /proc/net/tcp not found. Are you running on a Linux system?\033[0m\n";
        return;
    };
    
    my @connections;
    while (<$fh>) {
        next if $. == 1; # Skip header line

        my @fields = split;
        my ($local_hex, $local_port_hex) = split(':', $fields[1]);
        my ($peer_hex, $peer_port_hex) = split(':', $fields[2]);
        my $state_hex = $fields[3];

        my $state = $TCP_STATES{$state_hex} // "UNKNOWN";
        my $local_ip = parse_ip($local_hex);
        my $peer_ip  = parse_ip($peer_hex);
        my $local_port = hex($local_port_hex);
        my $peer_port  = hex($peer_port_hex);

        # Apply filters
        next if $filter_state && $state ne $filter_state;
        next if $filter_ip && $local_ip ne $filter_ip && $peer_ip ne $filter_ip;
        next if $filter_port && $local_port != $filter_port && $peer_port != $filter_port;

        push @connections, {
            local_address => $local_ip,
            local_port    => $local_port,
            peer_address  => $peer_ip,
            peer_port     => $peer_port,
            state         => $state
        };
    }
    close $fh;

    if ($output_format eq "json") {
        print encode_json(\@connections), "\n";
    } else {
        print "$COLORS{TIMESTAMP}Timestamp: " . strftime("%Y-%m-%d %H:%M:%S", localtime) . "\033[0m\n";
        print "$COLORS{HEADER}Netid  State          Local Address:Port     Peer Address:Port\033[0m\n";
        print "=" x 70, "\n";

        foreach my $conn (@connections) {
            my $color = $COLORS{$conn->{state}} // $COLORS{"DEFAULT"};
            printf "tcp    %s%-14s\033[0m %s:%-5d   %s:%-5d\n", 
                $color, $conn->{state}, 
                $conn->{local_address}, $conn->{local_port}, 
                $conn->{peer_address}, $conn->{peer_port};
            print "$COLORS{SEPARATOR}--------------------------------------------\033[0m\n";
        }
        print "=" x 70, "\n";
    }
}

# Continuously monitor TCP connections
sub watch_tcp_connections {
    my ($interval, $filter_state, $filter_ip, $filter_port, $output_format) = @_;
    
    eval {
        while (1) {
            read_tcp_connections($filter_state, $filter_ip, $filter_port, $output_format);
            sleep($interval);
        }
    };
    
    if ($@) {
        print "\n\033[33mExiting TCP connection watcher.\033[0m\n";
    }
}

# Command-line argument parsing
my ($interval, $filter_state, $filter_ip, $filter_port, $output_format) = (2, undef, undef, undef, "text");
GetOptions(
    "interval=i"      => \$interval,
    "filter-state=s"  => \$filter_state,
    "filter-ip=s"     => \$filter_ip,
    "filter-port=i"   => \$filter_port,
    "output-format=s" => \$output_format,
);

# Validate command-line arguments
if ($interval <= 0) {
    die "\033[31mError: Interval should be a positive integer.\033[0m\n";
}
if ($filter_state && !exists $TCP_STATES{lc $filter_state}) {
    die "\033[31mError: Invalid filter state '$filter_state'.\033[0m\n";
}
if ($output_format !~ /^(text|json)$/) {
    die "\033[31mError: Output format should be either 'text' or 'json'.\033[0m\n";
}

watch_tcp_connections($interval, $filter_state, $filter_ip, $filter_port, $output_format);
