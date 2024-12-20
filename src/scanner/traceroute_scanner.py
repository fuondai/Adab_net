import socket
import sys
from colorama import Fore, Style
from typing import List, Dict, Any, Optional
from .base import BaseScanner

class TracerouteScanner(BaseScanner):
    """Scanner để thực hiện traceroute đến các targets"""
    
    def __init__(self, targets: List[str], **kwargs):
        super().__init__(targets, **kwargs)
        self.maxhops = kwargs.get('maxhops', 30)
        self.timeout = kwargs.get('timeout', 1.0)
        self.results = {}

    def _traceroute(self, host: str) -> List[Optional[str]]:
        """Thực hiện traceroute đến một host.
        
        Args:
            host: Tên host hoặc địa chỉ IP cần trace
            
        Returns:
            List[Optional[str]]: Danh sách các IP của mỗi hop
        """
        try:
            host_addr = socket.gethostbyname(host)
        except socket.gaierror:
            print(f"[{Fore.RED}!{Style.RESET_ALL}] Không thể phân giải host: {host}")
            return []

        print(f"[{Fore.YELLOW}?{Style.RESET_ALL}] Tracing route to {host} [{host_addr}] with max {self.maxhops} hops\n")
        
        result = []
        
        for ttl in range(1, self.maxhops + 1):
            try:
                # Tạo socket ICMP để nhận phản hồi
                with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as rx:
                    rx.settimeout(self.timeout)
                    rx.bind(('', 0))  # Sử dụng cổng ngẫu nhiên
                    
                    # Tạo socket UDP để gửi gói tin
                    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as tx:
                        tx.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
                        tx.sendto(b'', (host_addr, 33434))
                        
                        try:
                            # Nhận phản hồi từ hop hiện tại
                            data, (curr_addr, _) = rx.recvfrom(512)
                        except socket.timeout:
                            curr_addr = None
                    
                    if curr_addr:
                        print(f"[{ttl}] {Fore.GREEN}{curr_addr}{Style.RESET_ALL}")
                    else:
                        print(f"[{ttl}] {Fore.YELLOW}*{Style.RESET_ALL}")
                    
                    result.append(curr_addr)
                    
                    # Kiểm tra nếu đã đến đích
                    if curr_addr == host_addr:
                        print(f"\n[{Fore.GREEN}+{Style.RESET_ALL}] Đã đến đích: {host} [{host_addr}]")
                        break

            except PermissionError:
                print(f"[{Fore.RED}!{Style.RESET_ALL}] Cần chạy với quyền root/administrator.")
                return []
            except Exception as e:
                print(f"[{Fore.RED}!{Style.RESET_ALL}] Lỗi: {e}")
                return []

        return result

    def scan(self) -> Dict[str, Any]:
        """Thực hiện traceroute cho tất cả các targets.
        
        Returns:
            Dict[str, Any]: Kết quả traceroute với key là target và value là list các hop
        """
        if os.geteuid() != 0:
            print(f"{Fore.RED}[!] This scanner requires root privileges{Style.RESET_ALL}")
            return self.results

        print(f"{Fore.YELLOW}[*] Starting traceroute scan...{Style.RESET_ALL}")
        
        try:
            for target in self.targets:
                hops = self._traceroute(target)
                self.results[target] = {
                    'hops': hops,
                    'hop_count': len(hops),
                    'reached_target': hops and hops[-1] is not None
                }

        except KeyboardInterrupt:
            print(f"\n{Fore.RED}[!] Scan interrupted by user{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[!] Error during scan: {e}{Style.RESET_ALL}")

        return self.results

    def print_results(self) -> None:
        """In kết quả traceroute."""
        print("\nTraceroute Results:")
        print("-" * 60)
        
        if not self.results:
            print(f"{Fore.YELLOW}[!] No results to display{Style.RESET_ALL}")
            return

        for target, info in self.results.items():
            print(f"\nTarget: {Fore.CYAN}{target}{Style.RESET_ALL}")
            if info['reached_target']:
                print(f"Status: {Fore.GREEN}Reached target in {info['hop_count']} hops{Style.RESET_ALL}")
            else:
                print(f"Status: {Fore.RED}Could not reach target{Style.RESET_ALL}")
            
            print("\nRoute:")
            for i, hop in enumerate(info['hops'], 1):
                if hop:
                    print(f"  [{i}] {Fore.GREEN}{hop}{Style.RESET_ALL}")
                else:
                    print(f"  [{i}] {Fore.YELLOW}*{Style.RESET_ALL}")
