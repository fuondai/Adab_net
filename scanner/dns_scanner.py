# scanner/dns_scanner.py
import socket

class DnsScanner:
    def __init__(self, domain_list):
        self.domain_list = domain_list

    def scan(self):
        results = []
        for domain in self.domain_list:
            try:
                ip = socket.gethostbyname(domain)
                results.append({'domain': domain, 'ip': ip})
            except socket.gaierror:
                results.append({'domain': domain, 'ip': None})
        return results
