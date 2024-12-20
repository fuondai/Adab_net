import os
from dataclasses import dataclass
from typing import Optional

@dataclass
class ServerConfig:
    """Configuration cho server"""
    host: str = "0.0.0.0"
    port: int = 5000
    debug: bool = False
    secret_key: Optional[str] = None
    
    @classmethod
    def load_from_env(cls) -> 'ServerConfig':
        """Load config từ environment variables"""
        return cls(
            host=os.getenv('SERVER_HOST', '0.0.0.0'),
            port=int(os.getenv('SERVER_PORT', '5000')),
            debug=os.getenv('SERVER_DEBUG', '').lower() == 'true',
            secret_key=os.getenv('SERVER_SECRET_KEY')
        ) 