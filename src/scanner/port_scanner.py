from typing import List, Dict, Any
from .base import BaseScanner
import socket
import logging
from ..exceptions import ScannerError

logger = logging.getLogger(__name__)

class PortScanner(BaseScanner):
    """Scanner cho port scanning"""
    
    def __init__(self, targets: List[str], ports: List[int], **kwargs):
        super().__init__(targets, **kwargs)
        self.ports = ports
        self.protocol = kwargs.get('protocol', 'TCP')
        self.service_map = {
            21: 'FTP',
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            80: 'HTTP',
            443: 'HTTPS',
            # ... thêm các port phổ biến khác
        }
        
    def _get_service_name(self, port: int) -> str:
        """Lấy tên service từ port number"""
        return self.service_map.get(port, 'unknown')
        
    def _get_version_info(self, target: str, port: int) -> str:
        """Lấy thông tin version của service"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(1)
                sock.connect((target, port))
                sock.send(b'')
                banner = sock.recv(1024).decode().strip()
                return banner
        except:
            return "unknown"
        
    def scan(self) -> Dict[str, Any]:
        """Thực hiện port scan"""
        try:
            for target in self.targets:
                self.results[target] = self._scan_target(target)
            return self.results
        except Exception as e:
            logger.error(f"Error during port scan: {e}")
            raise
            
    def _scan_target(self, target: str) -> Dict[int, Dict[str, Any]]:
        """Quét một target cụ thể"""
        target_results = {}
        for port in self.ports:
            result = self._scan_port(target, port)
            if result['state'] == 'open':
                target_results[port] = result
        return target_results
        
    def _scan_port(self, target: str, port: int) -> Dict[str, Any]:
        """Quét một port cụ thể"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(1)
                result = sock.connect_ex((target, port))
                return {
                    'state': 'open' if result == 0 else 'closed',
                    'service': self._get_service_name(port),
                    'version': self._get_version_info(target, port) if self.options.get('version') else None
                }
        except Exception as e:
            logger.error(f"Error scanning port {port}: {e}")
            return {'state': 'error', 'error': str(e)}
            
    def print_results(self) -> None:
        """In kết quả port scan"""
        for target, ports in self.results.items():
            print(f"\nResults for {target}:")
            print(f"{'PORT':<10}{'STATE':<10}{'SERVICE':<15}{'VERSION':<20}")
            print("-" * 55)
            for port, info in ports.items():
                print(
                    f"{port:<10}{info['state']:<10}{info['service']:<15}"
                    f"{info.get('version', 'N/A'):<20}"
                ) 