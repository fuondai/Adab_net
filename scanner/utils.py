import ipaddress
import prettytable

def validate_target(target):
    """Kiểm tra định dạng hợp lệ của target."""
    try:
        if "-" in target or "/" in target:
            list(ipaddress.ip_network(target, strict=False))  # CIDR or Range 
        else:
            ipaddress.ip_address(target)  # Single IP
        return True
    except ValueError:
        return False
