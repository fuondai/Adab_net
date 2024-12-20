from dataclasses import dataclass
from typing import Optional
import os

@dataclass
class AppConfig:
    """Application configuration"""
    debug: bool = False
    testing: bool = False
    database_url: str = "sqlite:///app.db"
    secret_key: Optional[str] = None
    max_workers: int = 10
    scan_timeout: int = 30
    
    @classmethod
    def from_env(cls):
        """Load config từ environment variables"""
        return cls(
            debug=os.getenv("APP_DEBUG", "false").lower() == "true",
            testing=os.getenv("APP_TESTING", "false").lower() == "true",
            database_url=os.getenv("DATABASE_URL", "sqlite:///app.db"),
            secret_key=os.getenv("SECRET_KEY"),
            max_workers=int(os.getenv("MAX_WORKERS", "10")),
            scan_timeout=int(os.getenv("SCAN_TIMEOUT", "30"))
        ) 