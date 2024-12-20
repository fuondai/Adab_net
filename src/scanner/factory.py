from typing import Dict, Any, Type
from .base import BaseScanner
from .specialized_scan import SpecializedScanner
from .dns_scanner import DnsScanner
from .auth_scanner import AuthScanner
from .device_scanner import DeviceScanner
from ..exceptions import ScannerError

class ScannerFactory:
    """Factory class để tạo các scanner instances"""
    
    _scanner_types: Dict[str, Type[BaseScanner]] = {
        'port': SpecializedScanner,
        'dns': DnsScanner,
        'auth': AuthScanner,
        'device': DeviceScanner
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
            return scanner_class(**kwargs)
        except KeyError:
            raise ScannerError(f"Invalid scanner type: {scanner_type}")
        except Exception as e:
            raise ScannerError(f"Error creating scanner: {e}") 