from typing import List, Dict, Any
from .base import BaseScanner
import socket

class DnsScanner(BaseScanner):
    def __init__(self, targets: List[str], **kwargs):
        super().__init__(targets, **kwargs)
        self.results = {}

    def scan(self) -> Dict[str, Any]:
        """Thực hiện DNS scan"""
        for domain in self.targets:
            try:
                ip = socket.gethostbyname(domain)
                self.results[domain] = {'ip': ip}
            except socket.gaierror:
                self.results[domain] = {'ip': None}
        return self.results

    def print_results(self) -> None:
        """In kết quả DNS scan"""
        print("\nDNS Scan Results:")
        print("-" * 50)
        for domain, result in self.results.items():
            ip = result['ip'] or 'Not found'
            print(f"Domain: {domain:<30} IP: {ip}")