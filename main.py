from scanner.cli import parse_args # Import the parse_args function from scanner/cli.py
from scanner.core import ping_check, arp_scan # Import functions from scanner/core.py
from scanner.utils import parse_input, get_input_from_file # Import the get_input_from_file function from scanner/utils.py

args = parse_args() # Gọi hàm parse_args() để xử lý các tham số dòng lệnh

# Nếu có file, thêm các mục tiêu từ file
targets= args.targets or []
exclude_targets = args.exclude_targets or []

if args.file:
    targets += get_input_from_file(args.file)
if args.exclude_file: 
    exclude_targets += get_input_from_file(args.exclude_file)# Loại trừ các mục tiêu cần loại trừ

if not targets: # Nếu không có mục tiêu nào
    print("No targets specified.")
    exit()

# Thực hiện kiểm tra ping nếu được yêu cầu
if args.ping_check:
    targets = parse_input(','.join(targets)) # Chuyển đổi các mục tiêu thành danh sách IP
    exclude_targets = parse_input(','.join(exclude_targets)) if exclude_targets else [] # Chuyển đổi các mục tiêu cần loại trừ thành danh sách IP
    targets = [target for target in targets if target not in exclude_targets] # Loại trừ các mục tiêu cần loại trừ
    for target in targets:
        ping_check(target)

# Thực hiện ARP scan nếu được yêu cầu
if args.arp:
    if not args.targets[0].count('/') == 1: # Nếu không phải CIDR
        print("ARP scan can only be used with CIDR notation.")
    # Quét ARP
    for target in targets:
        print(f"Performing ARP scan on {target} using interface {args.iface or 'default'}")
        devices = arp_scan(target, iface=args.iface) 
        if not devices: # Nếu không có thiết bị nào được tìm thấy hoặc không đủ quyền
            print("No devices found or insufficient privileges.") 
        else: 
            print("Discovered devices (IP -> MAC):")
            for device in devices:
                print(f"  {device['ip']:16} -> {device['mac']:18}")# In ra IP và MAC của từng thiết bị