import os
from scapy.all import Ether, ARP, srp
from colorama import Fore, Style
from typing import List, Dict, Any, Optional
from .base import BaseScanner

class MacScanner(BaseScanner):
    """Scanner để lấy địa chỉ MAC của các thiết bị"""
    
    def __init__(self, targets: List[str], **kwargs):
        super().__init__(targets, **kwargs)
        self.timeout = kwargs.get('timeout', 2)
        self.retries = kwargs.get('retries', 5)
        self.results = {}

    def _get_mac_address(self, host_ip: str) -> Optional[str]:
        """Lấy địa chỉ MAC của một địa chỉ IP.
        
        Args:
            host_ip: Địa chỉ IP cần tìm MAC
            
        Returns:
            str: Địa chỉ MAC nếu tìm thấy, None nếu không tìm thấy
        """
        if os.geteuid() != 0:
            print(f"{Fore.RED}[!] Permission error: You need root privileges for this feature.{Style.RESET_ALL}")
            return None

        print(f"\n{Fore.YELLOW}[?] Trying to get MAC address of {host_ip}...{Style.RESET_ALL}")

        # Tạo gói tin ARP request
        packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op="who-has", pdst=host_ip)

        try:
            # Gửi gói tin và chờ phản hồi
            responses, _ = srp(packet, timeout=self.timeout, retry=self.retries, verbose=False)

            if responses:
                for _, response in responses:
                    mac_address = response[Ether].src.upper()
                    print(f"{Fore.GREEN}[+] MAC address of {host_ip}: {mac_address}{Style.RESET_ALL}")
                    return mac_address
            else:
                print(f"{Fore.RED}[!] No MAC address found for {host_ip}.{Style.RESET_ALL}")
                return None

        except KeyboardInterrupt:
            print(f"\n{Fore.RED}[!] Process interrupted by user.{Style.RESET_ALL}")
            return None

        except Exception as e:
            print(f"{Fore.RED}[!] Error: {e}{Style.RESET_ALL}")
            return None

    def scan(self) -> Dict[str, Any]:
        """Thực hiện quét MAC address cho các targets.
        
        Returns:
            Dict[str, Any]: Kết quả quét với key là IP và value là MAC address
        """
        if os.geteuid() != 0:
            print(f"{Fore.RED}[!] This scanner requires root privileges{Style.RESET_ALL}")
            return self.results

        print(f"{Fore.YELLOW}[*] Starting MAC address scan...{Style.RESET_ALL}")
        
        try:
            for target in self.targets:
                mac = self._get_mac_address(target)
                if mac:
                    self.results[target] = {
                        'mac_address': mac,
                        'status': 'found'
                    }
                else:
                    self.results[target] = {
                        'mac_address': None,
                        'status': 'not found'
                    }

        except KeyboardInterrupt:
            print(f"\n{Fore.RED}[!] Scan interrupted by user{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[!] Error during scan: {e}{Style.RESET_ALL}")

        return self.results

    def print_results(self) -> None:
        """In kết quả quét MAC address."""
        print("\nMAC Address Scan Results:")
        print("-" * 60)
        
        if not self.results:
            print(f"{Fore.YELLOW}[!] No results to display{Style.RESET_ALL}")
            return

        for ip, info in self.results.items():
            print(f"\nTarget IP: {Fore.CYAN}{ip}{Style.RESET_ALL}")
            if info['status'] == 'found':
                print(f"MAC Address: {Fore.GREEN}{info['mac_address']}{Style.RESET_ALL}")
            else:
                print(f"Status: {Fore.RED}MAC address not found{Style.RESET_ALL}")
