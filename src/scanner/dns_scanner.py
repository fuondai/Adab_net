from typing import List, Dict, Any
from .base import BaseScanner
import socket
import logging
from ..exceptions import ScannerError

logger = logging.getLogger(__name__)

class DnsScanner(BaseScanner):
    """Scanner cho DNS records"""
    
    def __init__(self, targets: List[str], **kwargs):
        super().__init__(targets, **kwargs)
        self.record_types = kwargs.get('record_types', ['A', 'AAAA', 'MX', 'NS', 'TXT'])
        
    def scan(self) -> Dict[str, Any]:
        try:
            for target in self.targets:
                self.results[target] = self._scan_domain(target)
            return self.results
        except Exception as e:
            logger.error(f"DNS scan error: {e}")
            raise ScannerError(f"DNS scan failed: {e}")
            
    def _scan_domain(self, domain: str) -> Dict[str, List[str]]:
        domain_results = {}
        for record_type in self.record_types:
            try:
                answers = socket.gethostbyname_ex(domain)
                domain_results[record_type] = answers[2]
            except Exception as e:
                logger.error(f"Error resolving {record_type} records for {domain}: {e}")
                domain_results[record_type] = [f"Error: {str(e)}"]
        return domain_results
        
    def print_results(self) -> None:
        """In kết quả DNS scan"""
        for domain, records in self.results.items():
            print(f"\nDNS Records for {domain}:")
            for record_type, values in records.items():
                print(f"{record_type} Records:")
                for value in values:
                    print(f"  {value}")