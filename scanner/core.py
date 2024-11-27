import socket
import ipaddress
import threading
from scapy.all import ICMP, IP, sr1, ARP, Ether, srp

def ping_check(ip):
    """Kiểm tra xem một IP có thể ping được hay không."""
    try:
        packet = IP(dst=ip) / ICMP()
        reply = sr1(packet, timeout=2, verbose=0)
        
        if reply is not None:
            print(f"{ip} is reachable.")
        else:
            print(f"{ip} is unreachable.")
    except Exception:
        print(f"Error occurred while checking {ip}.")

def arp_scan(network_cidr, iface=None):
    """Quét ARP trong mạng và trả về danh sách IP và MAC."""
    try:
        # Gửi ARP request tới địa chỉ broadcast
        packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=network_cidr)
        answered, _ = srp(packet, iface=iface, timeout=2, verbose=0)  #_ là biến không sử dụng vì không cần lưu lại gói tin không trả lời
                                                                            #srp trả về 2 danh sách answered và unanswered, ta chỉ cần answered
        # Trích xuất IP và MAC từ phản hồi
        devices = []
        for sent, received in answered:
            devices.append({"ip": received.psrc, "mac": received.hwsrc})
        
        return devices
    except PermissionError:  # Lỗi thiếu quyền hạn
        print("Error: This action requires administrative/root privileges.")
        print("Please run this script as an administrator (Windows) or with sudo (Linux).")
        return []
    except Exception as e:
        print(f"Error during ARP scan: {e}")
        return []
