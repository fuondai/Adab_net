import pyshark
import sys
from colorama import Fore, Style

def capture_packets(interface, packet_count=10, display_filter="ip"):
    """
    Capture packets from the given interface and print the packet details.

    :param interface: The network interface to listen on (e.g., 'eth0', 'wlan0').
    :param packet_count: Number of packets to capture (default: 10).
    :param display_filter: Display filter for packet capture (default: 'ip').
    """
    try:
        print(f'[{Fore.YELLOW}?{Style.RESET_ALL}] Capturing packets on {Fore.YELLOW}{interface}{Style.RESET_ALL}...')
        print(f'[{Fore.YELLOW}?{Style.RESET_ALL}] Display filter: {display_filter}')
        
        # Start capturing packets
        capture = pyshark.LiveCapture(interface=interface, display_filter=display_filter)
        
        # Capture packets and display info
        packet_count = 0
        for packet in capture.sniff_continuously(packet_count=packet_count):
            print_packet_info(packet)
    
    except KeyboardInterrupt:
        print(f'\n[{Fore.RED}!{Style.RESET_ALL}] Capture interrupted by user.')
        sys.exit(0)
    except Exception as e:
        print(f'[{Fore.RED}!{Style.RESET_ALL}] Error: {Fore.RED}{e}{Style.RESET_ALL}')

def print_packet_info(packet):
    """Print the details of a captured packet."""
    try:
        if hasattr(packet, 'ip'):
            print(f'[{Fore.GREEN}+{Style.RESET_ALL}] Packet Info:')
            print(f'  {Fore.YELLOW}Source IP:{Style.RESET_ALL} {packet.ip.src}')
            print(f'  {Fore.YELLOW}Destination IP:{Style.RESET_ALL} {packet.ip.dst}')
            print(f'  {Fore.YELLOW}Protocol:{Style.RESET_ALL} {packet.highest_layer}')
            print(f'  {Fore.YELLOW}Packet Length:{Style.RESET_ALL} {packet.length} bytes')
            print('-' * 50)
        else:
            print(f'[{Fore.RED}!{Style.RESET_ALL}] Non-IP packet detected, skipping...')
    except AttributeError as e:
        print(f'[{Fore.RED}!{Style.RESET_ALL}] Error parsing packet: {e}')

def start_packet_capture(interface='eth0', packet_count=10, display_filter="ip"):
    """Start capturing packets on the specified interface."""
    print(f'[{Fore.YELLOW}?{Style.RESET_ALL}] Starting packet capture on {Fore.YELLOW}{interface}{Style.RESET_ALL}...')
    capture_packets(interface, packet_count, display_filter)
