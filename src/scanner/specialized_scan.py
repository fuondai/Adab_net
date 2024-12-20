import socket
import ipaddress
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from scapy.all import IP, TCP, UDP, ICMP, sr1, send, conf
import time
import os
import ctypes
from typing import List, Dict, Any
from .base import BaseScanner

class SpecializedScanner(BaseScanner):
    def __init__(self, targets: List[str], **kwargs):
        super().__init__(targets, **kwargs)
        self.scan_type = kwargs.get('scan_type', 'sn')
        # Parse ports nếu là string
        ports = kwargs.get('ports', [])
        if isinstance(ports, str):
            self.ports = self._parse_ports(ports)
        else:
            self.ports = ports
        self.protocol = kwargs.get('protocol', 'TCP')
        self.version = kwargs.get('version', False)
        self.threads = kwargs.get('threads', 10)
        self.timeout = kwargs.get('timeout', 5)
        conf.verb = 0
        self.results = {}

    def _parse_ports(self, ports_str: str) -> List[int]:
        """
        Parse chuỗi ports thành list các port
        
        Args:
            ports_str: Chuỗi ports (vd: "80,443" hoặc "1-1000")
            
        Returns:
            List[int]: Danh sách các port
        """
        ports = []
        for part in ports_str.split(','):
            if '-' in part:
                start, end = map(int, part.split('-'))
                ports.extend(range(start, end + 1))
            else:
                ports.append(int(part))
        return ports

    def scan(self) -> Dict[str, Any]:
        """Thực hiện quét dựa trên scan_type đã chọn"""
        if self.scan_type == 'sn':
            return self.ping_scan()
        elif self.scan_type == 'sS':
            return self.syn_stealth_scan()
        elif self.scan_type == 'sT':
            return self.tcp_connect_scan()
        elif self.scan_type == 'sU':
            return self.udp_scan()
        else:
            raise ValueError(f"Unsupported scan type: {self.scan_type}")

    def ping_scan(self) -> Dict[str, str]:
        """Thực hiện ping scan"""
        results = {}
        for target in self.targets:
            try:
                packet = IP(dst=target)/ICMP()
                reply = sr1(packet, timeout=self.timeout, verbose=0)
                
                if reply is not None:
                    results[target] = "Host is up"
                else:
                    results[target] = "Host is down"
            except Exception as e:
                results[target] = f"Error: {str(e)}"
        
        self.results = results
        return results

    def syn_stealth_scan(self) -> Dict[str, List[int]]:
        """Thực hiện SYN stealth scan"""
        results = {}
        for target in self.targets:
            open_ports = []
            for port in self.ports:
                try:
                    packet = IP(dst=target)/TCP(dport=int(port), flags="S")
                    response = sr1(packet, timeout=self.timeout, verbose=0)
                    
                    if response and response.haslayer(TCP):
                        if response[TCP].flags == 0x12:  # SYN-ACK
                            # Gửi RST để đóng kết nối
                            rst = IP(dst=target)/TCP(dport=int(port), flags="R")
                            send(rst, verbose=0)
                            open_ports.append(port)
                except Exception as e:
                    print(f"Error scanning port {port}: {e}")
                    
            if open_ports:
                results[target] = open_ports
                
        self.results = results
        return results

    def tcp_connect_scan(self) -> Dict[str, List[int]]:
        """Thực hiện TCP connect scan"""
        results = {}
        for target in self.targets:
            open_ports = []
            for port in self.ports:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(self.timeout)
                    result = sock.connect_ex((target, int(port)))
                    if result == 0:
                        open_ports.append(port)
                    sock.close()
                except Exception as e:
                    print(f"Error scanning port {port}: {e}")
                    
            if open_ports:
                results[target] = open_ports
                
        self.results = results
        return results

    def udp_scan(self) -> Dict[str, List[int]]:
        """Thực hiện UDP scan"""
        results = {}
        for target in self.targets:
            open_ports = []
            for port in self.ports:
                try:
                    packet = IP(dst=target)/UDP(dport=int(port))
                    response = sr1(packet, timeout=self.timeout, verbose=0)
                    
                    if response is None:
                        # Không có phản hồi có thể là port mở
                        open_ports.append(port)
                    elif response.haslayer(ICMP):
                        # ICMP port unreachable = port đóng
                        continue
                    else:
                        open_ports.append(port)
                except Exception as e:
                    print(f"Error scanning port {port}: {e}")
                    
            if open_ports:
                results[target] = open_ports
                
        self.results = results
        return results

    def print_results(self) -> None:
        """In kết quả quét"""
        if not self.results:
            print("No results found")
            return

        print("\nScan Results:")
        print("-" * 60)
        
        if isinstance(self.results, dict):
            for target, data in self.results.items():
                print(f"\nTarget: {target}")
                if isinstance(data, list):
                    for port in data:
                        print(f"Port {port}: OPEN")
                else:
                    print(data)
        else:
            print(self.results)

    # ... giữ nguyên các phương thức khác ...