from scapy.all import ARP, Ether, srp
from colorama import Fore, Style
import socket

def scan_local_devices(network):
    """Quét các thiết bị trong mạng cục bộ dựa trên dải IP với ARP."""
    print(f'[{Fore.YELLOW}?{Style.RESET_ALL}] Scanning for devices on {Fore.YELLOW}{network}{Style.RESET_ALL} network...')
    
    # Tạo gói ARP request để gửi đến dải IP đã nhập
    arp_request = ARP(pdst=network)
    ether_frame = Ether(dst="ff:ff:ff:ff:ff:ff") / arp_request

    try:
        # Gửi gói ARP request và nhận các phản hồi
        result = srp(ether_frame, timeout=3, verbose=False)[0]
    except KeyboardInterrupt:
        print(f'\n[{Fore.RED}!{Style.RESET_ALL}] Scan interrupted by user.')
        return []
    except Exception as e:
        print(f'[{Fore.RED}!{Style.RESET_ALL}] Error: {Fore.RED}{e}{Style.RESET_ALL}')
        return []

    devices = []
    # Quá trình quét hoàn tất, duyệt qua các phản hồi
    for sent, received in result:
        device_info = {"host": received.psrc, "mac": received.hwsrc}
        
        # Thử lấy tên máy chủ nếu có
        try:
            device_info['hostname'] = socket.gethostbyaddr(received.psrc)[0]
        except:
            device_info['hostname'] = None
        
        devices.append(device_info)
    
    return devices

def print_device_list(devices):
    """In danh sách các thiết bị đã quét được."""
    if devices:
        print(f"\n[{Fore.GREEN}+{Style.RESET_ALL}] Discovered devices:")
        print(f"{'IP Address':<20}{'Hostname':<30}{'MAC Address'}")
        print("-" * 60)
        
        for device in devices:
            # Kiểm tra 'hostname' và 'mac', thay thế 'None' bằng 'Unknown' nếu cần
            hostname = device.get('hostname', 'Unknown') if device.get('hostname') else 'Unknown'
            mac_address = device.get('mac', 'Unknown') if device.get('mac') else 'Unknown'
            
            print(f"{device['host']:<20}{hostname:<30}{mac_address}")
    else:
        print(f"[{Fore.RED}!{Style.RESET_ALL}] No devices found.")


