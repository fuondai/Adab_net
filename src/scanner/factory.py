from typing import Dict, Any, Type
from .base import BaseScanner
from .specialized_scan import SpecializedScanner
from .dns_scanner import DnsScanner
from .subdomain_scanner import SubdomainScanner
from .whois_scanner import WhoisScanner
from .dirbuster import DirBuster
from .device_scanner import DeviceScanner
from .mac_scanner import MacScanner
from .traceroute_scanner import TracerouteScanner
from .wireshark_scanner import PacketScanner
from .auth_scanner import AuthScanner
from .cve_scanner import CVEScanner
from .vuln_scanner import VulnScanner
from ..exceptions import ScannerError

class ScannerFactory:
    """Factory class để tạo các scanner instances"""
    
    _scanner_types: Dict[str, Type[BaseScanner]] = {
        'port': SpecializedScanner,
        'dns': DnsScanner,
        'subdomain': SubdomainScanner,
        'whois': WhoisScanner,
        'dirbuster': DirBuster,
        'device': DeviceScanner,
        'mac': MacScanner,
        'traceroute': TracerouteScanner,
        'packet': PacketScanner,
        'auth': AuthScanner,
        'cve': CVEScanner,
        'vuln': VulnScanner
    }
    
    @classmethod
    def register_scanner(cls, name: str, scanner_class: Type[BaseScanner]) -> None:
        """Đăng ký một scanner mới"""
        cls._scanner_types[name] = scanner_class
    
    @classmethod
    def create_scanner(cls, scanner_type: str, **kwargs) -> BaseScanner:
        """
        Tạo một scanner instance
        
        Args:
            scanner_type: Loại scanner cần tạo
            **kwargs: Các tham số cho scanner
            
        Returns:
            BaseScanner: Scanner instance
            
        Raises:
            ScannerError: Nếu loại scanner không tồn tại
        """
        try:
            scanner_class = cls._scanner_types[scanner_type]
            # Validate required parameters
            if 'targets' not in kwargs:
                raise ScannerError("Missing required parameter: targets")
            
            return scanner_class(targets=kwargs.pop('targets'), **kwargs)
        except KeyError:
            raise ScannerError(f"Invalid scanner type: {scanner_type}")
        except Exception as e:
            raise ScannerError(f"Error creating scanner: {e}") 