class NetworkScannerError(Exception):
    """Base exception class for NetworkScanner"""
    pass

class ScannerError(NetworkScannerError):
    """Raised when scanning operations fail"""
    pass

class ConfigurationError(NetworkScannerError):
    """Raised when there's a configuration error"""
    pass 