from flask import Flask, request, jsonify
import logging
from typing import Tuple, Dict, Any
from .auth import LicenseManager
from .models import ApiResponse
from .config import ServerConfig
from flasgger import Swagger

logger = logging.getLogger(__name__)

class LicenseServer:
    """Server xử lý license verification"""
    
    def __init__(self, config: ServerConfig):
        self.app = Flask(__name__)
        self.config = config
        self.license_manager = LicenseManager(config.secret_key)
        
        # Add Swagger documentation
        Swagger(self.app)
        
        self._setup_routes()
        self._setup_error_handlers()
        
    def _setup_routes(self):
        """Thiết lập các routes"""
        
        @self.app.route("/verify", methods=["POST"])
        def verify_license() -> Tuple[Dict[str, Any], int]:
            """
            Verify a license key
            ---
            parameters:
              - name: body
                in: body
                required: true
                schema:
                  type: object
                  properties:
                    api_key:
                      type: string
                      description: License key to verify
            responses:
              200:
                description: License is valid
              403:
                description: Invalid license
            """
            try:
                data = request.get_json()
                api_key = data.get("api_key")
                
                if not api_key:
                    return self._create_response(
                        "error",
                        "API key is required",
                        status_code=400
                    )
                
                is_valid = self.license_manager.verify_license(api_key)
                
                if is_valid:
                    return self._create_response(
                        "success",
                        "License is valid",
                        {"status": "valid"}
                    )
                else:
                    return self._create_response(
                        "error",
                        "Invalid license",
                        {"status": "invalid"},
                        status_code=403
                    )
                    
            except Exception as e:
                logger.error(f"Error verifying license: {e}")
                return self._create_response(
                    "error",
                    "Internal server error",
                    status_code=500
                )
                
        @self.app.route("/license", methods=["POST"])
        def create_license() -> Tuple[Dict[str, Any], int]:
            try:
                data = request.get_json()
                duration = data.get("duration", 365)
                
                license = self.license_manager.create_license(duration)
                
                return self._create_response(
                    "success",
                    "License created successfully",
                    {"api_key": license.api_key}
                )
                
            except Exception as e:
                logger.error(f"Error creating license: {e}")
                return self._create_response(
                    "error",
                    "Internal server error",
                    status_code=500
                )
    
    def _setup_error_handlers(self):
        """Thiết lập error handlers"""
        
        @self.app.errorhandler(404)
        def not_found(e) -> Tuple[Dict[str, Any], int]:
            return self._create_response(
                "error",
                "Resource not found",
                status_code=404
            )
            
        @self.app.errorhandler(500)
        def server_error(e) -> Tuple[Dict[str, Any], int]:
            return self._create_response(
                "error",
                "Internal server error",
                status_code=500
            )
    
    def _create_response(
        self,
        status: str,
        message: str,
        data: Dict[str, Any] = None,
        status_code: int = 200
    ) -> Tuple[Dict[str, Any], int]:
        """Tạo response chuẩn"""
        response = ApiResponse(status, message, data)
        return jsonify(vars(response)), status_code
    
    def run(self):
        """Khởi động server"""
        self.app.run(
            host=self.config.host,
            port=self.config.port,
            debug=self.config.debug
        )

def create_app() -> Flask:
    """Factory function để tạo Flask app"""
    config = ServerConfig.load_from_env()
    server = LicenseServer(config)
    return server.app

if __name__ == "__main__":
    config = ServerConfig.load_from_env()
    server = LicenseServer(config)
    server.run() 