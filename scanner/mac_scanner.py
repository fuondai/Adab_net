import os
from scapy.all import Ether, ARP, srp
from colorama import Fore, Style
import socket

def get_mac_address(host_ip, timeout=2, retries=5):
    """Lấy địa chỉ MAC của một địa chỉ IP cụ thể.

    Args:
        host_ip (str): Địa chỉ IP cần tìm MAC.
        timeout (int): Thời gian chờ cho mỗi lần gửi gói tin (mặc định là 2 giây).
        retries (int): Số lần thử lại nếu không có phản hồi (mặc định là 5 lần).

    Returns:
        str: Địa chỉ MAC nếu tìm thấy, hoặc None nếu không tìm thấy.
    """
    if os.geteuid() != 0:
        print(f"{Fore.RED}[!] Permission error: You need root privileges for this feature.{Style.RESET_ALL}")
        return None

    # Kiểm tra kết nối mạng
    try:
        socket.create_connection(('8.8.8.8', 53), timeout=timeout)
    except OSError:
        print(f"{Fore.RED}[!] No network connection found.{Style.RESET_ALL}")
        return None

    print(f"\n{Fore.YELLOW}[?] Trying to get MAC address of {host_ip}...{Style.RESET_ALL}")

    # Tạo gói tin ARP request để broadcast
    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op="who-has", pdst=host_ip)

    try:
        # Gửi gói tin và chờ phản hồi
        responses, _ = srp(packet, timeout=timeout, retry=retries, verbose=False)

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
