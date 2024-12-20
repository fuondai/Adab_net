from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
import logging

logger = logging.getLogger(__name__)

class BaseScanner(ABC):
    """Base class cho tất cả các scanner"""
    
    def __init__(self, targets: List[str], **kwargs):
        self.targets = targets
        self.options = kwargs
        self.results: Dict[str, Any] = {}
        self._validate_targets()
        
    def _validate_targets(self) -> None:
        """Validate danh sách targets"""
        if not self.targets:
            raise ValueError("Targets list cannot be empty")
            
    def _log_scan_start(self) -> None:
        """Log bắt đầu quét"""
        logger.info(f"Starting scan with {self.__class__.__name__}")
        
    def _log_scan_end(self) -> None:
        """Log kết thúc quét"""
        logger.info(f"Scan completed with {self.__class__.__name__}")
        
    @abstractmethod
    def scan(self) -> Dict[str, Any]:
        """
        Thực hiện quét và trả về kết quả
        
        Returns:
            Dict[str, Any]: Kết quả quét
        """
        pass
        
    @abstractmethod
    def print_results(self) -> None:
        """In kết quả quét"""
        pass

class ScanResult:
    """Class đại diện cho kết quả quét"""
    
    def __init__(self, target: str, scan_type: str):
        self.target = target
        self.scan_type = scan_type
        self.start_time = None
        self.end_time = None
        self.status = None
        self.details = {} 