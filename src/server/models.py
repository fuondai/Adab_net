from dataclasses import dataclass
from datetime import datetime
from typing import Optional

@dataclass
class License:
    """Model cho license key"""
    api_key: str
    created_at: datetime
    expires_at: Optional[datetime] = None
    is_active: bool = True

    def is_valid(self) -> bool:
        """Kiểm tra license có còn hiệu lực"""
        if not self.is_active:
            return False
        if self.expires_at and datetime.now() > self.expires_at:
            return False
        return True

@dataclass
class ApiResponse:
    """Model cho API response"""
    status: str
    message: str
    data: Optional[dict] = None 