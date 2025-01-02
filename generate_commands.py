from colorama import Fore, Style
import ipaddress

def generate_sample_commands(target_ip):
    """Tạo các câu lệnh mẫu dựa trên IP đích."""
    
    # Kiểm tra IP hợp lệ
    try:
        ipaddress.ip_address(target_ip)
    except ValueError:
        print(f"{Fore.RED}[!] Địa chỉ IP không hợp lệ!{Style.RESET_ALL}")
        return

    # Lấy network từ IP (giả sử subnet /24)
    network = '.'.join(target_ip.split('.')[:-1]) + '.0/24'
    
    commands = [
        f"# Quét cơ bản",
        f"sudo python main.py {target_ip}",
        f"\n# Quét port cụ thể",
        f"sudo python main.py {target_ip} -p 20,21,22,23,24,25,80,81,82,8080",
        f"sudo python main.py {target_ip} -p 20-25,80,81,82,8080",
        f"\n# Các loại quét đặc biệt",
        f"sudo python main.py -sn {target_ip}",
        f"sudo python main.py -sU {target_ip}",
        f"sudo python main.py -sS {target_ip}",
        f"sudo python main.py -sT {target_ip}",
        f"\n# Quét xác thực",
        f"sudo python main.py --auth {target_ip}",
        f"\n# Chạy server xác thực bản quyền",
        f"sudo python server/server.py",
        f"\n# Chạy server test dirbuster",
        f"sudo python server/notjail.py",
        f"\n# Chạy server exploit",
        f"sudo python server/localhost_server.py",
        f"\n# Kích hoạt bản quyền",
        f"sudo python main.py --enterprise",
        f"\n# Lấy địa chỉ MAC",
        f"sudo python main.py --get-mac {target_ip}",
        f"\n# Quét thiết bị trong mạng",
        f"sudo python main.py --scan-devices {network}",
        f"\n# Traceroute",
        f"sudo python main.py --traceroute {target_ip}",
        f"\n# Wireshark",
        f"sudo python main.py --wireshark eth0",
        f"\n# Quét thư mục web (nếu có web server)",
        f"sudo python main.py --dirbust {target_ip}:80 wordlists/directory-list-2.3-small.txt"
    ]

    print(f"{Fore.GREEN}[+] Các lệnh mẫu để quét {target_ip}:{Style.RESET_ALL}\n")
    for cmd in commands:
        if cmd.startswith('#'):
            print(f"{Fore.YELLOW}{cmd}{Style.RESET_ALL}")
        else:
            print(cmd)

def main():
    print(f"{Fore.CYAN}=== Tạo Lệnh Quét Mẫu ==={Style.RESET_ALL}")
    target_ip = input(f"\n{Fore.YELLOW}[?] Nhập địa chỉ IP cần quét: {Style.RESET_ALL}").strip()
    generate_sample_commands(target_ip)

if __name__ == "__main__":
    main()
