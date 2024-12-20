import logging
from typing import Optional, List
from src.scanner import ScannerFactory
from src.scanner.base import BaseScanner
from src.exceptions import NetworkScannerError
from src.logging_config import setup_logging

logger = logging.getLogger(__name__)

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
            self.add_scanner(
                'port',
                targets=args.targets,
                ports=args.ports,
                protocol=args.protocol,
                version=args.version
            )
            
        if args.dns:
            self.add_scanner(
                'dns',
                targets=args.dns
            )

def main():
    try:
        args = parse_args()
        scanner = NetworkScanner()
        
        scanner.process_args(args)
        scanner.run_scans()
        
        return 0
        
    except Exception as e:
        logger.error(f"Error during execution: {e}")
        return 1

if __name__ == "__main__":
    exit(main())
