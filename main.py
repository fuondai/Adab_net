import time
import os
import requests

LICENSE_FILE = "license.key" 
SECRET_KEY_FILE = "secret.key"

from cryptography.fernet import Fernet
from colorama import init, Fore, Style
from scanner.cli import parse_args
from scanner.core import ServiceVersionScanner, PingChecker, ArpScanner
from scanner.utils import parse_input, get_input_from_file
from scanner.dns_scanner import DnsScanner
from scanner.specialized_scan import SpecializedScanner
from scanner.auth_scanner import AuthScanner
from scanner.mac_scanner import get_mac_address
from scanner.thank_you import welcome
from scanner.dirbuster import dirbust
from scanner.device_scanner import scan_local_devices, print_device_list
from scanner.subdomain_scanner import sdenum
from scanner.vuln_scanner import get_user_api_key, vulnscan
from scanner.whois_scanner import whoisinfo
from scanner.traceroute_scanner import tracert
from scanner.wireshark_scanner import start_packet_capture

def load_secret_key():
    """Load khóa bí mật từ file."""
    # Kiểm tra xem file 'secret.key' có tồn tại trong cùng thư mục với main.py không
    if not os.path.isfile(SECRET_KEY_FILE):
        # In thông báo lỗi nếu file không tồn tại
        print(f"{Fore.RED}[!] Error: The secret key file '{SECRET_KEY_FILE}' is missing or could not be loaded. Are you using a cracked version?{Style.RESET_ALL}")
        return None
    
    with open(SECRET_KEY_FILE, "rb") as key_file:
        secret_key = key_file.read()
    
    try:
        # Thử khởi tạo Fernet với khóa đọc được để kiểm tra tính hợp lệ
        Fernet(secret_key)
    except Exception as e:
        print(f"{Fore.RED}[!] Error: The secret key file '{SECRET_KEY_FILE}' is invalid. Flag{{Wh0_Cr4ck_A_0p3n_S0ur3}}{Style.RESET_ALL}")
        return None

    return secret_key


def encrypt_api_key(api_key):
    """Mã hóa API key và lưu vào file LICENSE_FILE."""
    secret_key = load_secret_key()
    cipher = Fernet(secret_key)
    encrypted_key = cipher.encrypt(api_key.encode())
    with open(LICENSE_FILE, "wb") as license_file:
        license_file.write(encrypted_key)

def decrypt_api_key():
    """Giải mã API key từ file LICENSE_FILE."""
    if not os.path.exists(LICENSE_FILE):
        return None
    secret_key = load_secret_key()
    cipher = Fernet(secret_key)
    with open(LICENSE_FILE, "rb") as license_file:
        encrypted_key = license_file.read()
    try:
        return cipher.decrypt(encrypted_key).decode()
    except Exception:
        return None
        
def is_enterprise_activated():
    """Kiểm tra xem bản quyền enterprise đã kích hoạt chưa."""
    return os.path.exists(LICENSE_FILE)


def save_license_key(api_key):
    """Lưu API key vào tệp license.key."""
    with open(LICENSE_FILE, "w") as f:
        f.write(api_key)


def get_saved_license_key():
    """Đọc API key từ tệp license.key."""
    if os.path.exists(LICENSE_FILE):
        with open(LICENSE_FILE, "r") as f:
            return f.read().strip()
    return None


def verify_license_key(api_key):
    """Xác minh API key bằng cách gửi yêu cầu tới máy chủ."""
    try:
        response = requests.post("http://localhost:5000/verify", json={"api_key": api_key})
        if response.status_code == 200 and response.json().get("status") == "valid":
            welcome()	
            return True
    except requests.exceptions.RequestException:
        pass
    return False
    
def main():
    
    # Kiểm tra xem enterprise đã kích hoạt chưa
    saved_api_key = decrypt_api_key()
    enterprise_activated = saved_api_key is not None
    print_logo(is_enterprise=enterprise_activated)

    # Load secret key và kiểm tra nếu khóa hợp lệ
    secret_key = load_secret_key()
    if secret_key is None:
        return  # Dừng chương trình nếu khóa bí mật không hợp lệ
        
    # Parse command-line arguments
    args = parse_args()
    
    # Nếu người dùng chọn chế độ enterprise và chưa kích hoạt bản quyền
    if args.enterprise and not enterprise_activated:
        api_key = input("Enter API KEY: ").strip()
        if not api_key or not verify_license_key(api_key):
            print("Invalid API key. EXIT.")
            return
        encrypt_api_key(api_key)
        print("Enterprise license activated successfully!")
        enterprise_activated = True
        exit()
                
    # Quét subdomain nếu người dùng sử dụng tùy chọn --scan-subdomains
    if args.scan_subdomains:
        domain = args.scan_subdomains
        if not args.wordlist:
            print(f"[{Fore.RED}!{Style.RESET_ALL}] Error: You must provide a wordlist with --wordlist.")
            return

        wordlist = args.wordlist  # Đọc đường dẫn wordlist từ dòng lệnh
        sdenum(domain, wordlist)  # Gọi module quét subdomain
        return
    
    # Device Scan
    if args.scan_devices:
        network = args.scan_devices
        devices = scan_local_devices(network)
        print_device_list(devices)
        return
    
    #WhoIS
    if args.whois:
        host = args.whois
        whoisinfo(host)  # Gọi module WHOIS để lấy thông tin
        return
    
    # Traceroute
    if args.traceroute:
        host = args.traceroute
        tracert(host)  # Gọi module traceroute
        return
        
    # Vuln Scan
    if args.vuln_scan:
        perform_vuln_scan(args.vuln_scan)
        return
         
    # MAC FIND
    if args.get_mac:
        get_mac_address(args.get_mac) 
        return
        
    # DNS Scan
    if args.dns:
        perform_dns_scan(args.dns)
        return
    
    # Wireshark
    if args.wireshark:
        interface = args.wireshark
        start_packet_capture(interface)  
        
    # Directory Busting
    if args.dirbust:
        host, wordlist = args.dirbust
        dirbust(host, wordlist)
        return

    # Nếu chỉ quét xác thực, bỏ qua quét cổng
    if args.auth:
        perform_security_scans(targets, args)
        return
        
    # Validate and process targets
    targets = process_targets(args)
    if not targets:
        return
        	        
    # Specialized scans
    if args.sn or args.sS or args.sT or args.sU:
        perform_specialized_scans(targets, args)
        return

    # Port scanning
    if args.ports:
        perform_port_scan(targets, args)
        
def print_logo(is_enterprise=False):
    init(autoreset=True)
    if is_enterprise:
        logo = fr"""
{Fore.YELLOW}{Style.BRIGHT}
    ___       __      __               __ 
   /   | ____/ /___ _/ /_  ____  ___  / /_
  / /| |/ __  / __ / __ \/ __ \/ _ \/ __/
 / ___ / /_/ / /_/ / /_/ / / / /  __/ /_  
/_/  |_\__,_/\__,_/_.___/_/ /_/\___/\__/  
   _   _   _   _   _   _   _   _   _   _  
  / \ / \ / \ / \ / \ / \ / \ / \ / \ / \ 
 ( e | n | t | e | r | p | r | i | s | e )
  \_/ \_/ \_/ \_/ \_/ \_/ \_/ \_/ \_/ \_/                                               
{Style.RESET_ALL}
        """
    else:
        logo = fr"""
{Fore.CYAN}{Style.BRIGHT}
    ___       __      __               __ 
   /   | ____/ /___ _/ /_  ____  ___  / /_
  / /| |/ __  / __ / __ \/ __ \/ _ \/ __/
 / ___ / /_/ / /_/ / /_/ / / / /  __/ /_  
/_/  |_\__,_/\__,_/_.___/_/ /_/\___/\__/                                            
{Style.RESET_ALL}
        """
    print(logo)
    
def perform_dns_scan(domains):
    """Perform DNS scanning on specified domains."""
    dns_scanner = DnsScanner(domains)
    results = dns_scanner.scan()
    print("DNS Scan Results:")
    for result in results:
        domain = result['domain']
        ip = result['ip'] or "Resolution failed"
        print(f"{domain}: {ip}")

def process_targets(args):
    """Process and validate target inputs."""
    # Nếu có --scan-subdomains, không cần parse target từ file hay địa chỉ IP
    if args.scan_subdomains:
        return [args.scan_subdomains]    

    # Kiểm tra nếu có --get-mac, xử lý mục tiêu
    if args.get_mac:
        # Trả về mục tiêu cho quét MAC
        return [args.get_mac]
        
    # Kiểm tra nếu có --dns, xử lý mục tiêu
    if args.dns:
        # Nếu có --dns, ta sẽ trả về mục tiêu cho quét DNS
        return [args.dns]
        
    # Kiểm tra nếu có --dirbust, xử lý mục tiêu
    if args.dirbust:
        host = args.dirbust[0]  # Mục tiêu (host)
        wordlist = args.dirbust[1]  # Wordlist
        return [(host, wordlist)]  # Trả về tuple chứa host và wordlist cho việc quét
        
    # Nếu có --scan-devices, sử dụng giá trị đó làm mục tiêu
    if args.scan_devices:
        # Trả về một danh sách với địa chỉ mạng được quét
        return [args.scan_devices]
    # Check for conflicting target inputs
    if args.file and args.targets:
        print("Error: Specify targets either directly or through a file, not both.")
        return []

    if args.exclude_file and args.exclude_targets:
        print("Error: Specify exclude targets either directly or through a file, not both.")
        return []

    # Get targets
    targets = get_input_from_file(args.file) if args.file else parse_input(','.join(args.targets)) if args.targets else []
    
    # Get exclude targets
    exclude_targets = get_input_from_file(args.exclude_file) if args.exclude_file else parse_input(','.join(args.exclude_targets)) if args.exclude_targets else []

    # Remove excluded targets
    targets = [target for target in targets if target not in exclude_targets]

    if not targets:
        print("No valid targets specified.")
        return []

    return targets

def perform_vuln_scan(host):
    api_key = get_user_api_key()
    vulnscan(host, api_key)

def perform_port_scan(targets, args):
    """Perform port scanning on specified targets."""
    for target in targets:
        start_time = time.time()
        scanner = ServiceVersionScanner(target, args.ports, args.protocol)
        results = scanner.scan()
        end_time = time.time() - start_time

        print(f"Results for target: {target}")
        print(f"{'PORT':<8}{'STATE':<8}{'SERVICE':<12}", end="")
        if args.version:
            print(f"{'VERSION'}", end="")
        print("\n" + "-" * 50)

        for port, state, service, version in results:
            line = f"{port:<8}{state:<8}{service:<12}"
            if args.version:
                line += f"{version}"
            print(line)

        print(f"\nScanning completed in {end_time:.2f} seconds.")

def perform_specialized_scans(targets, args):
    """Perform specialized network scans."""
    scan_types = {
        'sn': ('Ping Scan', 'Live Hosts'),
        'sS': ('SYN Stealth Scan', 'Open Ports'),
        'sT': ('TCP Connect Scan', 'Open Ports'),
        'sU': ('UDP Scan', 'Open Ports')
    }

    for scan_type, (scan_name, result_label) in scan_types.items():
        if getattr(args, scan_type):
            scanner = SpecializedScanner(
                targets,
                scan_type=scan_type,
                ports=args.ports if scan_type != 'sn' else None
            )
            results = scanner.scan()

            # In tiêu đề quét
            print(f"\n{Fore.CYAN}{'-' * 50}")
            print(f"{scan_name} Results")
            print(f"{'-' * 50}{Style.RESET_ALL}")

            # Kiểm tra nếu không có kết quả
            if not results:
                print(f"{Fore.RED}No {result_label} found.{Style.RESET_ALL}")
                continue

            # In tiêu đề cột
            print(f"{'Target':<20}{'Port':<8}{'Status':<10}")
            print(f"{'-' * 40}")

            # In kết quả từng dòng
            for result in results:
                if ':' in result:
                    target, port = result.split(':')
                    print(f"{Fore.GREEN}{target:<20}{port:<8}{'Open':<10}{Style.RESET_ALL}")
                else:
                    print(f"{Fore.GREEN}{result:<20}{'':<8}{'Up':<10}{Style.RESET_ALL}")

            print(f"{Fore.CYAN}{'-' * 50}{Style.RESET_ALL}")


def perform_security_scans(targets, args):
    """Perform authentication scanning."""
    if args.auth:
        auth_scanner = AuthScanner(targets, credentials_file=args.creds)
        
        # Common Services
        ports_services = {
            21: ("ftp", auth_scanner._check_ftp),
            22: ("ssh", auth_scanner._check_ssh),
            23: ("telnet", auth_scanner._check_telnet),
            25: ("smtp", auth_scanner._check_smtp),
            #3306: ("mysql", auth_scanner._check_mysql),        
            5432: ("postgresql", auth_scanner._check_postgresql), 
            6379: ("redis", auth_scanner._check_redis),        
            80: ("http", auth_scanner._check_http_basic_auth)  
        }

        auth_results = auth_scanner.scan(ports_services)


    # Ping and ARP scans
    if args.ping_check:
        perform_ping_check(targets)

    if args.arp:
        perform_arp_scan(targets, args.iface)

def perform_ping_check(targets):
    """Perform ping check on targets."""
    start_time = time.time()
    ping_checker = PingChecker(targets)
    reachable_ips = ping_checker.check()
    end_time = time.time() - start_time
    
    print("Reachable IPs:")
    for ip in reachable_ips:
        print(ip)
    print(f"\nPing check completed in {end_time:.2f} seconds.")

def perform_arp_scan(targets, interface):
    """Perform ARP scanning."""
    if not targets[0].count('/') == 1:  # Check for CIDR notation
        print("ARP scan requires CIDR notation.")
        return

    start_time = time.time()
    arp_scanner = ArpScanner(targets[0], iface=interface)
    devices = arp_scanner.scan()
    end_time = time.time() - start_time

    if not devices:
        print("No devices found or insufficient privileges.")
    else:
        print("Discovered devices (IP -> MAC):")
        for device in devices:
            print(f"  {device['ip']:16} -> {device['mac']:18}")
    print(f"\nARP scan completed in {end_time:.2f} seconds.")

if __name__ == "__main__":
    main()
