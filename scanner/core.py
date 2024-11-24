import socket
import ipaddress
from scapy.all import ICMP, IP, sr1, ARP, Ether, srp

# def is_reachable(ip, timeout=2):
#     """Kiểm tra xem một IP có thể ping được hay không."""
#     try:
#         packet = IP(dst=ip) / ICMP()
#         reply = sr1(packet, timeout=timeout, verbose=0)
#         return reply is not None
#     except Exception:
#         return False

# def resolve_hostname(hostname):
#     """Chuyển hostname thành IP."""
#     try:
#         return socket.gethostbyname(hostname)
#     except socket.gaierror:
#         return None

# def get_ip_range(target):
#     """Phân tích target thành danh sách IP."""
#     try:
#         if "-" in target:  # IP range (e.g., 192.168.1.1-192.168.1.100)
#             start_ip, end_ip = target.split("-")
#             return [str(ip) for ip in ipaddress.summarize_address_range(
#                 ipaddress.IPv4Address(start_ip), ipaddress.IPv4Address(end_ip))]
#         elif "/" in target:  # CIDR (e.g., 192.168.1.0/24)
#             return [str(ip) for ip in ipaddress.IPv4Network(target, strict=False)]
#         else:  # Single IP or hostname
#             resolved_ip = resolve_hostname(target)
#             return [resolved_ip] if resolved_ip else []
#     except ValueError:
#         return []

def arp_scan(network_cidr, iface=None, timeout=2):
    """Quét ARP trong mạng và trả về danh sách IP và MAC."""
    try:
        # Gửi ARP request tới địa chỉ broadcast
        packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=network_cidr)
        answered, _ = srp(packet, iface=iface, timeout=timeout, verbose=0)  #_ là biến không sử dụng vì không cần lưu lại gói tin không trả lời
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
