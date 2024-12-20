import socket
import sys
from colorama import Fore, Style

def tracert(host, maxhops=30, timeout=1.0):
    """
    Hàm thực hiện traceroute đến host đích bằng UDP và ICMP.
    
    :param host: Tên host hoặc địa chỉ IP cần trace.
    :param maxhops: Số hop tối đa (mặc định là 30).
    :param timeout: Thời gian chờ cho mỗi hop (mặc định là 1.0 giây).
    :return: Danh sách các IP của mỗi hop.
    """
    try:
        host_addr = socket.gethostbyname(host)
    except socket.gaierror:
        print(f"[{Fore.RED}!{Style.RESET_ALL}] Không thể phân giải host: {host}")
        return []

    print(f"[{Fore.YELLOW}?{Style.RESET_ALL}] Tracing route to {host} [{host_addr}] with max {maxhops} hops\n")
    
    result = []
    
    for ttl in range(1, maxhops + 1):
        try:
            # Tạo socket ICMP để nhận phản hồi
            with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as rx:
                rx.settimeout(timeout)
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
