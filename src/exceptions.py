class NetworkScannerError(Exception):
    """Base exception cho network scanner"""
    pass

class ScannerError(NetworkScannerError):
    """Exception cho các lỗi scanner cụ thể"""
    pass

class EncryptionError(NetworkScannerError):
    """Exception cho các lỗi liên quan đến mã hóa"""
    pass

class AuthenticationError(NetworkScannerError):
    """Exception cho các lỗi xác thực"""
    pass

class ConfigurationError(NetworkScannerError):
    """Exception cho các lỗi cấu hình"""
    pass

class ValidationError(NetworkScannerError):
    """Exception cho các lỗi validation"""
    pass 