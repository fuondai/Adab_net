import logging
import argparse
from typing import Optional, List
from src.scanner import ScannerFactory
from src.scanner.base import BaseScanner
from src.exceptions import NetworkScannerError
from src.logging_config import setup_logging
from src.scanner.thank_you import welcome

logger = logging.getLogger(__name__)

def parse_args():
    """Parse command line arguments"""
    epilog = """
Examples:
  Basic port scan:
    python main.py -p 80,443 example.com
    
  SYN stealth scan:
    python main.py -sS -p 1-1000 192.168.1.1
    
  DNS enumeration:
    python main.py --dns example.com
    
  Directory busting:
    python main.py --dirbuster http://example.com --wordlist wordlists/common.txt
    
  Device discovery:
    python main.py --device-scan 192.168.1.0/24
    
  Vulnerability scan:
    python main.py --vuln-scan example.com --shodan-key YOUR_API_KEY
    
  Authentication testing:
    python main.py --auth-scan 192.168.1.1 --creds-file creds.txt
"""

    parser = argparse.ArgumentParser(
        description="Adab Network Security Tools",
        epilog=epilog,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    # Target arguments
    parser.add_argument(
        "targets",
        nargs="*",
        help="Target IP addresses, hostnames, or CIDR ranges"
    )
    
    # Port scanning options
    parser.add_argument(
        "-p", "--ports",
        help="Port(s) to scan (e.g. 80,443 or 1-1000)"
    )
    parser.add_argument(
        "--protocol",
        choices=["TCP", "UDP"],
        default="TCP",
        help="Protocol to use for port scanning"
    )
    
    # Scan types
    parser.add_argument(
        "-sS", action="store_true",
        help="Perform SYN stealth scan"
    )
    parser.add_argument(
        "-sT", action="store_true",
        help="Perform TCP connect scan"
    )
    parser.add_argument(
        "-sU", action="store_true",
        help="Perform UDP scan"
    )
    
    # DNS and Domain options
    parser.add_argument(
        "--dns", nargs="+",
        help="Perform DNS enumeration on specified domains"
    )
    parser.add_argument(
        "--subdomain", nargs="+",
        help="Perform subdomain enumeration"
    )
    parser.add_argument(
        "--whois", nargs="+",
        help="Perform WHOIS lookup"
    )
    
    # Directory scanning
    parser.add_argument(
        "--dirbuster",
        help="Perform directory busting on web server"
    )
    parser.add_argument(
        "--wordlist",
        help="Wordlist file for directory busting"
    )
    
    # Network scanning
    parser.add_argument(
        "--device-scan",
        help="Scan for devices in network (e.g. 192.168.1.0/24)"
    )
    parser.add_argument(
        "--mac",
        help="Get MAC address of specified IP"
    )
    parser.add_argument(
        "--traceroute",
        help="Perform traceroute to target"
    )
    
    # Packet capture
    parser.add_argument(
        "--packet-capture",
        help="Capture packets on specified interface"
    )
    parser.add_argument(
        "--packet-count", type=int, default=10,
        help="Number of packets to capture"
    )
    parser.add_argument(
        "--display-filter",
        help="Display filter for packet capture"
    )
    
    # Output options
    parser.add_argument(
        "-o", "--output",
        help="Output file to write results"
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output results in JSON format"
    )
    
    # Advanced options
    parser.add_argument(
        "--threads",
        type=int,
        default=10,
        help="Number of threads to use"
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=5,
        help="Timeout in seconds for each scan"
    )
    
    # Vulnerability scanning
    parser.add_argument(
        "--vuln-scan",
        help="Perform vulnerability scanning"
    )
    parser.add_argument(
        "--cve",
        help="Check for CVE vulnerabilities"
    )
    parser.add_argument(
        "--shodan-key",
        help="Shodan API key for vulnerability scanning"
    )
    
    # Authentication testing
    parser.add_argument(
        "--auth-scan",
        help="Perform authentication testing"
    )
    parser.add_argument(
        "--creds-file",
        help="Credentials file for auth testing"
    )
    
    # Enterprise features
    parser.add_argument(
        "--enterprise",
        action="store_true", 
        help="Enable enterprise features"
    )
    parser.add_argument(
        "--api-key",
        help="API key for enterprise features"
    )
    
    return parser.parse_args()

class NetworkScanner:
    """Class chính điều khiển toàn bộ chương trình"""
    
    def __init__(self):
        self.enterprise_activated = False
        self.scanners: List[BaseScanner] = []
        setup_logging()
        
    def add_scanner(self, scanner_type: str, **kwargs) -> None:
        """
        Thêm một scanner vào danh sách
        
        Args:
            scanner_type: Loại scanner cần thêm
            **kwargs: Các tham số cho scanner
        """
        try:
            scanner = ScannerFactory.create_scanner(scanner_type, **kwargs)
            self.scanners.append(scanner)
        except ValueError as e:
            logger.error(f"Error adding scanner: {e}")
            raise NetworkScannerError(f"Invalid scanner type: {scanner_type}")
        
    def run_scans(self) -> None:
        """Chạy tất cả các scanner đã được thêm"""
        if not self.scanners:
            logger.warning("No scanners configured")
            return
            
        for scanner in self.scanners:
            try:
                logger.info(f"Running {scanner.__class__.__name__}")
                results = scanner.scan()
                scanner.print_results()
            except Exception as e:
                logger.error(f"Error in scanner {scanner.__class__.__name__}: {e}")
                
    def process_args(self, args) -> None:
        """Xử lý command line arguments"""
        if args.ports:
            scan_type = 'sS' if args.sS else 'sT' if args.sT else 'sU' if args.sU else 'sT'
            self.add_scanner(
                'port',
                targets=args.targets,
                ports=args.ports,
                protocol=args.protocol,
                scan_type=scan_type,
                threads=args.threads,
                timeout=args.timeout
            )
            
        if args.dns:
            self.add_scanner('dns', targets=args.dns)
            
        if args.subdomain:
            self.add_scanner(
                'subdomain',
                targets=args.subdomain,
                wordlist=args.wordlist
            )
            
        if args.whois:
            self.add_scanner('whois', targets=args.whois)
            
        if args.dirbuster:
            self.add_scanner(
                'dirbuster',
                targets=[args.dirbuster],
                wordlist=args.wordlist
            )
            
        if args.device_scan:
            self.add_scanner(
                'device',
                targets=[args.device_scan]
            )
            
        if args.mac:
            self.add_scanner(
                'mac',
                targets=[args.mac]
            )
            
        if args.traceroute:
            self.add_scanner(
                'traceroute',
                targets=[args.traceroute]
            )
            
        if args.packet_capture:
            self.add_scanner(
                'packet',
                interface=args.packet_capture,
                packet_count=args.packet_count,
                display_filter=args.display_filter
            )
        
        if args.vuln_scan:
            self.add_scanner(
                'vuln',
                targets=[args.vuln_scan],
                api_key=args.shodan_key
            )
            
        if args.cve:
            self.add_scanner(
                'cve',
                targets=[args.cve]
            )
            
        if args.auth_scan:
            self.add_scanner(
                'auth',
                targets=[args.auth_scan],
                creds_file=args.creds_file
            )
            
        if args.enterprise:
            if not args.api_key:
                raise NetworkScannerError("API key required for enterprise features")
            self.enterprise_activated = True

def main():
    try:
        args = parse_args()
        
        # Hiển thị welcome banner với API key nếu có
        welcome(args.api_key if args.enterprise else None)
        
        scanner = NetworkScanner()
        scanner.process_args(args)
        scanner.run_scans()
        
        return 0
        
    except Exception as e:
        logger.error(f"Error during execution: {e}")
        return 1

if __name__ == "__main__":
    exit(main())
