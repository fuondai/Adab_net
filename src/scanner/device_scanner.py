from scapy.all import ARP, Ether, srp
from colorama import Fore, Style
import socket
from typing import List, Dict
from .base import BaseScanner

class DeviceScanner(BaseScanner):
    """Scanner để quét các thiết bị trong mạng"""

    def __init__(self, targets: List[str], **kwargs):
        super().__init__(targets, **kwargs)
        self.discovered_devices = []

    def scan(self) -> Dict[str, List[Dict]]:
        """
        Thực hiện quét thiết bị trong mạng
        
        Returns:
            Dict với key là subnet và value là list các thiết bị tìm thấy
        """
        results = {}
        for network in self.targets:
            devices = self.scan_local_devices(network)
            if devices:
                results[network] = devices
                self.discovered_devices.extend(devices)
        
        return results

    def scan_local_devices(self, network: str) -> List[Dict]:
        """Quét các thiết bị trong mạng cục bộ dựa trên dải IP với ARP."""
        print(f'[{Fore.YELLOW}?{Style.RESET_ALL}] Scanning for devices on {Fore.YELLOW}{network}{Style.RESET_ALL} network...')
        
        # Tạo gói ARP request
        arp_request = ARP(pdst=network)
        ether_frame = Ether(dst="ff:ff:ff:ff:ff:ff") / arp_request

        try:
            # Gửi gói ARP request và nhận các phản hồi
            result = srp(ether_frame, timeout=3, verbose=False)[0]
        except Exception as e:
            print(f'[{Fore.RED}!{Style.RESET_ALL}] Error: {Fore.RED}{e}{Style.RESET_ALL}')
            return []

        devices = []
        # Quá trình quét hoàn tất, duyệt qua các phản hồi
        for sent, received in result:
            device_info = {
                "ip": received.psrc,
                "mac": received.hwsrc,
                "hostname": None
            }
            
            # Thử lấy tên máy chủ
            try:
                device_info['hostname'] = socket.gethostbyaddr(received.psrc)[0]
            except:
                pass
            
            devices.append(device_info)
        
        return devices

    def print_results(self) -> None:
        """In kết quả quét thiết bị."""
        if self.discovered_devices:
            print(f"\n[{Fore.GREEN}+{Style.RESET_ALL}] Discovered devices:")
            print(f"{'IP Address':<20}{'Hostname':<30}{'MAC Address'}")
            print("-" * 60)
            
            for device in self.discovered_devices:
                hostname = device.get('hostname', 'Unknown')
                print(f"{device['ip']:<20}{hostname:<30}{device['mac']}")
        else:
            print(f"[{Fore.RED}!{Style.RESET_ALL}] No devices found.") 