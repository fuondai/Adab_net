import time

from scanner.cli import parse_args
from scanner.core import ServiceVersionScanner, PingChecker, ArpScanner
from scanner.utils import parse_input, get_input_from_file
from scanner.dns_scanner import DnsScanner
from scanner.specialized_scan import SpecializedScanner
from scanner.auth_scanner import AuthScanner
from scanner.cve_scanner import CVEScanner

def main():
    # Parse command-line arguments
    args = parse_args()

    # DNS Scan
    if args.dns:
        perform_dns_scan(args.dns)
        return

    # Validate and process targets
    targets = process_targets(args)
    if not targets:
        return

    # Port scanning
    if args.ports:
        perform_port_scan(targets, args)

    # Specialized scans
    perform_specialized_scans(targets, args)

    # Authentication and vulnerability scanning
    perform_security_scans(targets, args)

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
            
            print(f"{scan_name} Results:")
            for result in results:
                print(result)

def perform_security_scans(targets, args):
    """Perform authentication and CVE scanning."""
    if args.auth:
        auth_scanner = AuthScanner(targets, credentials_file=args.creds)
        auth_results = auth_scanner.scan()
        print_auth_results(auth_results)

    if args.cve:
        cve_results = perform_cve_scan(targets, args)
        print_cve_results(cve_results)

    # Ping and ARP scans
    if args.ping_check:
        perform_ping_check(targets)

    if args.arp:
        perform_arp_scan(targets, args.iface)

def print_auth_results(auth_results):
    """Print authentication scanning results."""
    print("Authentication Scanning Results:")
    for host, results in auth_results.items():
        print(f"{host}:")
        for service, creds in results.items():
            print(f"  {service.upper()} Vulnerable Credentials:")
            for username, password in creds:
                print(f"    {username}:{password}")

def perform_cve_scan(targets, args):
    """Perform comprehensive CVE scanning."""
    service_scan_results = {}
    for target in targets:
        scanner = ServiceVersionScanner(target, args.ports)
        results = scanner.scan()
        for port, state, service, version in results:
            if state == "OPEN":
                service_scan_results[service] = version
    
    cve_scanner = CVEScanner(nvd_api_key=args.nvd_key)
    return cve_scanner.scan(service_scan_results)

def print_cve_results(cve_results):
    """Print CVE scanning results."""
    print("\nCVE Scanning Results:")
    for service, cves in cve_results.items():
        print(f"{service}:")
        for cve in cves:
            print(f"  CVE: {cve['id']}")
            print(f"  Severity: {cve['severity']}")
            print(f"  Description: {cve['description']}\n")

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
