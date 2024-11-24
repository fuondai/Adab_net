# Description: Module chứa hàm main() và hàm parse_args() để xử lý các tham số dòng lệnh.

import argparse
from .core import arp_scan # Import the arp_scan function from scanner/core.py

def parse_args(): # Hàm parse_args() để xử lý các tham số dòng lệnh
    parser = argparse.ArgumentParser(description="Network Scanner Tool")
    parser.add_argument("-t", "--targets", # Thêm tham số --targets hoặc -t để chứa danh sách mục tiêu 
        nargs="+",
        type=str,
        required=True,  
        help="IP(s), IP range, CIDR, hoặc hostname (vd: 1.2.3.4,1.1.1.1,10.0.0.1 | 192.168.1.16-192.168.1.32 | 192.168.1.0/24 | example.org)."
    )
    parser.add_argument("-f", "--file", # Thêm tham số --file hoặc -f để chứa file chứa danh sách mục tiêu
        type=str, 
        help="File chứa danh sách mục tiêu để quét (mỗi dòng một mục tiêu)."
    )
    parser.add_argument("--timeout", # Thêm tham số --timeout để chọn thời gian chờ cho mỗi yêu cầu
        type=int, 
        default=2,
        help="Thời gian chờ cho mỗi yêu cầu (mặc định: 2 giây)."
    )
    parser.add_argument("-arp", # Thêm tham số -arp để thực hiện ARP scan
        action="store_true", 
        help="Sử dụng ARP scan để lấy địa chỉ MAC của các host trong mạng (chỉ áp dụng với CIDR)."
    )
    parser.add_argument("-i", "--iface", # Thêm tham số --iface hoặc -i để chọn card mạng
        type=str, 
        default=None, 
        help="Chọn interface (vd: eth0, wlan0, Ethernet). Nếu không chỉ định, sẽ dùng interface mặc định."
    )
    return parser.parse_args()

def main():

    args = parse_args() # Gọi hàm parse_args() để xử lý các tham số dòng lệnh
    targets = args.targets # Lấy danh sách mục tiêu từ tham số --targets hoặc -t

    # Nếu có file, thêm các mục tiêu từ file
    if args.file:
        with open(args.file, "r") as f:
            targets.extend(line.strip() for line in f if line.strip())  #lặp qua từng dòng, xóa các khoảng trắng đầu và cuối dòng, 
                                                                        #nếu dòng không trống thì thêm vào danh sách mục tiêu
    
    # Thực hiện ARP scan nếu được yêu cầu
    if args.arp:
        # Quét ARP
        for target in targets:
            print(f"Performing ARP scan on {target} using interface {args.iface or 'default'}")
            devices = arp_scan(target, iface=args.iface, timeout=args.timeout) 
            if not devices: # Nếu không có thiết bị nào được tìm thấy hoặc không đủ quyền
                print("No devices found or insufficient privileges.") 
            else: 
                print("Discovered devices (IP -> MAC):")
                for device in devices:
                    print(f"  {device['ip']:16} -> {device['mac']:18}")# In ra IP và MAC của từng thiết bị