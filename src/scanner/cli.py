import argparse
from typing import List, Optional
from dataclasses import dataclass
import logging

logger = logging.getLogger(__name__)

# Định nghĩa các cổng mặc định bằng dataclass để dễ quản lý
@dataclass
class DefaultPorts:
    COMMON = [
        21, 22, 23, 25, 53, 80, 81, 110, 111, 135, 139, 143,
        443, 445, 465, 587, 993, 995, 1433, 1434, 3306, 3389,
        5432, 5900, 8080, 8443
    ]
    TOP_1000 = [
        1,3,4,6,7,9,13,17,19,20,21,22,23,24,25,
        # ... (giữ nguyên danh sách top 1000 ports)
    ]

class PortParser:
    """Xử lý việc parse các port từ input của người dùng"""
    
    @staticmethod
    def parse_port_input(port_input: Optional[str] = None) -> List[int]:
        """
        Parse port input với nhiều định dạng khác nhau:
        - Port đơn: '80'
        - Nhiều port: '80,443,8080'
        - Dải port: '1-1000'
        - Tất cả port: '-' hoặc 'all'
        
        Args:
            port_input: Chuỗi chứa thông tin port cần parse
            
        Returns:
            List[int]: Danh sách các port đã parse
            
        Raises:
            ValueError: Nếu định dạng port không hợp lệ
        """
        if not port_input or port_input == 'all' or port_input == '-':
            return list(range(1, 65536))

        ports = []
        try:
            for part in port_input.split(','):
                if '-' in part:
                    start, end = map(str.strip, part.split('-'))
                    start = 1 if not start else int(start)
                    end = 65535 if not end else int(end)
                    if not (1 <= start <= end <= 65535):
                        raise ValueError(f"Invalid port range: {start}-{end}")
                    ports.extend(range(start, end + 1))
                else:
                    port = int(part.strip())
                    if not (1 <= port <= 65535):
                        raise ValueError(f"Invalid port number: {port}")
                    ports.append(port)
            return sorted(set(ports))
        except ValueError as e:
            logger.error(f"Error parsing ports: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error parsing ports: {e}")
            raise ValueError(f"Invalid port specification: {port_input}")

class ArgumentParser:
    """Xử lý parsing các tham số dòng lệnh"""

    def __init__(self):
        self.parser = argparse.ArgumentParser(
            description="Advanced Network Scanner Tool",
            formatter_class=argparse.RawDescriptionHelpFormatter
        )
        self._add_target_args()
        self._add_port_args() 
        self._add_scan_type_args()
        self._add_output_args()
        self._add_feature_args()

    def _add_target_args(self):
        """Thêm các tham số liên quan đến target"""
        target_group = self.parser.add_argument_group('Target Specification')
        target_group.add_argument(
            "targets", 
            nargs="*",
            help="IP(s), IP range, CIDR, or hostname"
        )
        target_group.add_argument(
            "-f", "--file",
            help="File containing target list (one per line)"
        )
        target_group.add_argument(
            "-xt", "--exclude-targets",
            nargs="+",
            help="Targets to exclude"
        )
        target_group.add_argument(
            "-xf", "--exclude-file",
            help="File containing exclude target list"
        )

    def _add_port_args(self):
        """Thêm các tham số liên quan đến port"""
        port_group = self.parser.add_argument_group('Port Specification')
        port_group.add_argument(
            "-p", "--ports",
            type=str,
            default=','.join(map(str, DefaultPorts.COMMON)),
            help="Port specification (e.g. '80,443' or '1-1000')"
        )
        port_group.add_argument(
            "--protocol",
            choices=["TCP", "UDP"],
            default="TCP",
            help="Protocol to use for scanning"
        )

    def _add_scan_type_args(self):
        """Thêm các tham số cho loại quét"""
        scan_group = self.parser.add_argument_group('Scan Types')
        scan_group.add_argument('-sn', action='store_true', help='Ping Scan')
        scan_group.add_argument('-sS', action='store_true', help='SYN Stealth Scan')
        scan_group.add_argument('-sT', action='store_true', help='TCP Connect Scan')
        scan_group.add_argument('-sU', action='store_true', help='UDP Scan')

    def _add_output_args(self):
        """Thêm các tham số output"""
        output_group = self.parser.add_argument_group('Output Options')
        output_group.add_argument(
            "-o", "--output",
            help="Output file path"
        )
        output_group.add_argument(
            "-V", "--version",
            action="store_true",
            help="Include service version information"
        )

    def _add_feature_args(self):
        """Thêm các tham số cho tính năng bổ sung"""
        feature_group = self.parser.add_argument_group('Additional Features')
        feature_group.add_argument(
            "--dns",
            nargs='+',
            help="DNS record scanning"
        )
        feature_group.add_argument(
            "--auth",
            action="store_true",
            help="Authentication scanning"
        )
        feature_group.add_argument(
            "--enterprise",
            action="store_true", 
            help="Enterprise edition features"
        )
        # Thêm các tính năng khác...

    def parse_args(self):
        """
        Parse và validate các tham số dòng lệnh
        
        Returns:
            argparse.Namespace: Các tham số đã được parse
            
        Raises:
            ValueError: Nếu có tham số không hợp lệ
        """
        args = self.parser.parse_args()
        
        # Validate conflicting arguments
        if args.file and args.targets:
            raise ValueError("Cannot specify both targets and target file")
            
        if args.exclude_file and args.exclude_targets:
            raise ValueError("Cannot specify both exclude targets and exclude file")

        # Parse ports
        if args.ports:
            try:
                args.ports = PortParser.parse_port_input(args.ports)
            except ValueError as e:
                logger.error(f"Port parsing error: {e}")
                raise

        return args

def parse_args():
    """
    Hàm wrapper để tương thích ngược với code cũ
    
    Returns:
        argparse.Namespace: Parsed arguments
    """
    parser = ArgumentParser()
    return parser.parse_args()
