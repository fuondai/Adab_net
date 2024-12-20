import sys
from colorama import Fore, Style
from typing import List, Dict, Any, Optional
from .base import BaseScanner

# Thử import pyshark, nếu không có thì bỏ qua
try:
    import pyshark
    PYSHARK_AVAILABLE = True
except ImportError:
    PYSHARK_AVAILABLE = False

class PacketScanner(BaseScanner):
    """Scanner để bắt và phân tích gói tin mạng"""
    
    def __init__(self, targets: List[str], **kwargs):
        super().__init__(targets, **kwargs)
        self.interface = kwargs.get('interface', 'eth0')
        self.packet_count = kwargs.get('packet_count', 10)
        self.display_filter = kwargs.get('display_filter', 'ip')
        self.results = {}

    def scan(self) -> Dict[str, Any]:
        """Thực hiện bắt gói tin trên interface."""
        if not PYSHARK_AVAILABLE:
            print(f"{Fore.YELLOW}[!] pyshark not found. This scanner requires pyshark.{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[!] Install it with: pip install pyshark{Style.RESET_ALL}")
            return self.results

        try:
            print(f'[{Fore.YELLOW}?{Style.RESET_ALL}] Capturing packets on {Fore.YELLOW}{self.interface}{Style.RESET_ALL}...')
            print(f'[{Fore.YELLOW}?{Style.RESET_ALL}] Display filter: {self.display_filter}')
            
            # Khởi tạo capture
            capture = pyshark.LiveCapture(
                interface=self.interface,
                display_filter=self.display_filter
            )
            
            # Bắt gói tin
            packets = []
            packet_count = 0
            
            for packet in capture.sniff_continuously(packet_count=self.packet_count):
                info = self._print_packet_info(packet)
                if info:
                    packets.append(info)
                packet_count += 1
                if packet_count >= self.packet_count:
                    break
                    
            self.results = {
                'interface': self.interface,
                'packet_count': len(packets),
                'packets': packets
            }

        except KeyboardInterrupt:
            print(f'\n[{Fore.RED}!{Style.RESET_ALL}] Capture interrupted by user.')
        except Exception as e:
            print(f'[{Fore.RED}!{Style.RESET_ALL}] Error: {Fore.RED}{e}{Style.RESET_ALL}')

        return self.results

    def print_results(self) -> None:
        """In kết quả bắt gói tin."""
        if not self.results:
            print(f"{Fore.YELLOW}[!] No packet capture results to display{Style.RESET_ALL}")
            return

        print("\nPacket Capture Results:")
        print("-" * 60)
        
        print(f"Interface: {Fore.CYAN}{self.results['interface']}{Style.RESET_ALL}")
        print(f"Total Packets: {Fore.GREEN}{self.results['packet_count']}{Style.RESET_ALL}\n")
        
        for i, packet in enumerate(self.results['packets'], 1):
            print(f"Packet #{i}:")
            print(f"  Source IP: {Fore.GREEN}{packet['source_ip']}{Style.RESET_ALL}")
            print(f"  Destination IP: {Fore.GREEN}{packet['dest_ip']}{Style.RESET_ALL}")
            print(f"  Protocol: {Fore.YELLOW}{packet['protocol']}{Style.RESET_ALL}")
            print(f"  Length: {packet['length']} bytes")
            print("-" * 40)
