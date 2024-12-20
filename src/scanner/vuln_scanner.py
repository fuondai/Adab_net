# shodan_scan.py

import sys
from colorama import Fore, Style
from typing import List, Dict, Any
from .base import BaseScanner

# Thử import shodan, nếu không có thì bỏ qua
try:
    import shodan
    SHODAN_AVAILABLE = True
except ImportError:
    SHODAN_AVAILABLE = False

class VulnScanner(BaseScanner):
    """Scanner để quét lỗ hổng bảo mật"""
    
    def __init__(self, targets: List[str], **kwargs):
        super().__init__(targets, **kwargs)
        self.api_key = kwargs.get('api_key')
        self.results = {}

    def scan(self) -> Dict[str, Any]:
        """Thực hiện quét lỗ hổng."""
        if not SHODAN_AVAILABLE:
            print(f"{Fore.YELLOW}[!] shodan not found. This scanner requires shodan.{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[!] Install it with: pip install shodan{Style.RESET_ALL}")
            return self.results

        if not self.api_key:
            print(f"{Fore.RED}[!] Shodan API key is required{Style.RESET_ALL}")
            return self.results

        try:
            api = shodan.Shodan(self.api_key)
            
            for target in self.targets:
                print(f"[{Fore.YELLOW}*{Style.RESET_ALL}] Scanning {target} for vulnerabilities...")
                try:
                    # Quét thông tin host
                    host = api.host(target)
                    
                    self.results[target] = {
                        'ip': host.get('ip_str'),
                        'os': host.get('os', 'Unknown'),
                        'ports': host.get('ports', []),
                        'vulns': host.get('vulns', []),
                        'hostnames': host.get('hostnames', []),
                        'domains': host.get('domains', [])
                    }
                    
                except shodan.APIError as e:
                    print(f"[{Fore.RED}!{Style.RESET_ALL}] Error scanning {target}: {e}")
                    self.results[target] = None

        except Exception as e:
            print(f"[{Fore.RED}!{Style.RESET_ALL}] Error during vulnerability scan: {e}")

        return self.results

    def print_results(self) -> None:
        """In kết quả quét lỗ hổng."""
        if not self.results:
            print(f"{Fore.YELLOW}[!] No vulnerability scan results to display{Style.RESET_ALL}")
            return

        print("\nVulnerability Scan Results:")
        print("-" * 60)
        
        for target, info in self.results.items():
            print(f"\nTarget: {Fore.CYAN}{target}{Style.RESET_ALL}")
            
            if not info:
                print(f"{Fore.RED}[!] Scan failed for this target{Style.RESET_ALL}")
                continue
                
            print(f"IP: {Fore.GREEN}{info['ip']}{Style.RESET_ALL}")
            print(f"OS: {Fore.GREEN}{info['os']}{Style.RESET_ALL}")
            
            if info['ports']:
                print(f"\nOpen Ports:")
                for port in info['ports']:
                    print(f"  {Fore.GREEN}{port}{Style.RESET_ALL}")
                    
            if info['vulns']:
                print(f"\nVulnerabilities:")
                for vuln in info['vulns']:
                    print(f"  {Fore.RED}{vuln}{Style.RESET_ALL}")
                    
            if info['hostnames']:
                print(f"\nHostnames:")
                for hostname in info['hostnames']:
                    print(f"  {Fore.YELLOW}{hostname}{Style.RESET_ALL}")
