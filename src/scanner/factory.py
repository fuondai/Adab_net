from typing import Type, Dict, Any
from .base import BaseScanner
from .port_scanner import PortScanner
from .dns_scanner import DnsScanner
# ... import các scanner khác

class ScannerFactory:
    """Factory class để tạo các scanner instances"""
    
    _scanner_map: Dict[str, Type[BaseScanner]] = {
        'port': PortScanner,
        'dns': DnsScanner,
        # ... thêm các scanner khác
    }
    
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
            ValueError: Nếu scanner_type không hợp lệ
        """
        scanner_class = cls._scanner_map.get(scanner_type)
        if not scanner_class:
            raise ValueError(f"Unknown scanner type: {scanner_type}")
            
        return scanner_class(**kwargs) 