import socket
import ipaddress
import prettytable

def parse_input(targets):
    try:
        parsed = []
        for target in targets.split(','):
            if '/' in target or '-' in target:
                if '-' in target:
                    start_ip, end_ip = target.split('-')
                    start_ip = ipaddress.ip_address(start_ip)
                    end_ip = ipaddress.ip_address(end_ip)
                    while start_ip <= end_ip:
                        parsed.append(str(start_ip))
                        start_ip += 1
                else:  # CIDR Notation
                    for ip in ipaddress.ip_network(target, strict=False):
                        parsed.append(str(ip))
            else:
                parsed.append(target.strip())
        return parsed
    except Exception as e:
        print(f"Error parsing targets: {e}")
        return []
    
def get_input_from_file(file):
    ips = []
    try:
        with open(file, "r") as f:
            for line in f:
                ip = line.strip()
                if '/' in ip or '-' in ip:
                    ips += parse_input(ip)
                else:
                    ips.append(ip)
        return ips  
    except Exception as e:
        print(f"Error reading file: {e}")
        return []

#def export_output_to_file(file, results):

    
