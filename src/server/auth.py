import hmac
import hashlib
from typing import Optional
from datetime import datetime, timedelta
from .models import License

class LicenseManager:
    """Quản lý license keys"""
    
    def __init__(self, secret_key: str):
        self.secret_key = secret_key
        self._licenses: dict[str, License] = {}

    def create_license(self, duration_days: int = 365) -> License:
        """Tạo license key mới"""
        timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
        message = f"{timestamp}{self.secret_key}"
        
        # Tạo API key bằng HMAC
        api_key = hmac.new(
            self.secret_key.encode(),
            message.encode(),
            hashlib.sha256
        ).hexdigest()

        # Tạo license object
        license = License(
            api_key=api_key,
            created_at=datetime.now(),
            expires_at=datetime.now() + timedelta(days=duration_days)
        )
        
        self._licenses[api_key] = license
        return license

    def verify_license(self, api_key: str) -> bool:
        """Xác thực license key"""
        license = self._licenses.get(api_key)
        if not license:
            return False
        return license.is_valid()

    def revoke_license(self, api_key: str) -> bool:
        """Thu hồi license"""
        if api_key in self._licenses:
            self._licenses[api_key].is_active = False
            return True
        return False 