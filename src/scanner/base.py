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