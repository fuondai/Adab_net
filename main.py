import time

from scanner.cli import parse_args # Import the parse_args function from scanner/cli.py
from scanner.core import ServiceVersionScanner, PingChecker, ArpScanner # Import classes from scanner/core.py
from scanner.utils import parse_input, get_input_from_file # Import the get_input_from_file function from scanner/utils.py

args = parse_args() # Gọi hàm parse_args() để xử lý các tham số dòng lệnh

# Kiểm tra xem user có sử dụng cả tham số trực tiếp và file cho targets không
if args.file and args.targets:
    print("Error: Please specify either targets directly or through a file, not both.")
    exit()

# Kiểm tra xem user có sử dụng cả tham số trực tiếp và file cho exclude targets không
if args.exclude_file and args.exclude_targets:
    print("Error: Please specify either exclude targets directly or through a file, not both.")
    exit()

# Xử lý mục tiêu từ file hoặc trực tiếp
if args.file:
    targets = get_input_from_file(args.file)
else:
    targets = parse_input(','.join(args.targets)) if args.targets else []

# Xử lý mục tiêu loại trừ từ file hoặc trực tiếp
if args.exclude_file:
    exclude_targets = get_input_from_file(args.exclude_file)
else:
    exclude_targets = parse_input(','.join(args.exclude_targets)) if args.exclude_targets else []

targets = [target for target in targets if target not in exclude_targets] # Loại trừ các mục tiêu cần loại trừ

if not targets: # Nếu không có mục tiêu nào
    print("No targets specified.")
    exit()

if args.ports:
    if args.ports == "all":
        ports = list(range(1, 65535))
    else:
        ports = [int(port) for port in args.ports.split(",")]

    for target in targets:
        start_time = time.time()
        scanner = ServiceVersionScanner(target, ports, args.protocol)
        results = scanner.scan()
        end_time = time.time() - start_time

        # Hiển thị kết quả
        print(f"Results for target: {target}")
        print(f"{'PORT':<8}{'STATE':<8}{'SERVICE':<12}", end="")
        if args.version:
            print(f"{'VERSION'}", end="")
        print("\n" + "-" * 50)

        for port, state, service, version in results:
            print(f"{port:<8}{state:<8}{service:<12}", end="")
            if args.version:
                print(f"{version}", end="")
            print()

        print(f"\nScanning completed in {end_time:.2f} seconds.")

# Thực hiện kiểm tra ping nếu được yêu cầu
if args.ping_check:
    start_time = time.time()
    ping_checker = PingChecker(targets)
    reachable_ips = ping_checker.check()
    end_time = time.time() - start_time
    print("Reachable IPs:")
    for ip in reachable_ips:
        print(ip)
    print(f"\nPing check completed in {end_time:.2f} seconds.")

# Thực hiện ARP scan nếu được yêu cầu
if args.arp:
    if not args.targets[0].count('/') == 1: # Nếu không phải CIDR
        print("ARP scan can only be used with CIDR notation.")
    else:
        start_time = time.time()
        arp_scanner = ArpScanner(targets[0], iface=args.iface)
        devices = arp_scanner.scan()
        end_time = time.time() - start_time
        if not devices: # Nếu không có thiết bị nào được tìm thấy hoặc không đủ quyền
            print("No devices found or insufficient privileges.")
        else:
            print("Discovered devices (IP -> MAC):")
            for device in devices:
                print(f"  {device['ip']:16} -> {device['mac']:18}") # In ra IP và MAC của từng thiết bị
        print(f"\nARP scan completed in {end_time:.2f} seconds.")

