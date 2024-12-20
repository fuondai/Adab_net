import socket
import ssl
import ipaddress
import threading
from scapy.all import conf, ICMP, IP, sr1, ARP, Ether, srp
import logging
from typing import List, Tuple

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Define a dictionary to map ports to service handling functions
port_service_map = {
    20: ("ftp-data", lambda banner: banner if banner else "Unknown FTP-data"),
    21: ("ftp", lambda banner: banner.splitlines()[0] if banner else "Unknown FTP"),
    22: ("ssh", lambda banner: banner if banner else "Unknown SSH"),
    23: ("telnet", lambda banner: banner if banner else "Unknown Telnet"),
    25: ("smtp", lambda banner: banner.split("\n")[0] if banner else "Unknown SMTP"),
    38: ("rap", lambda banner: banner if banner else "Unknown RAP"),
    42: ("nameserver", lambda banner: banner if banner else "Unknown NameServer"),
    53: ("domain", lambda banner: banner.split("version")[1].strip() if "version" in banner else "ISC BIND (version not found)"),
    67: ("dhcp-server", lambda banner: banner if banner else "Unknown DHCP"),
    68: ("dhcp-client", lambda banner: banner if banner else "Unknown DHCP"),
    80: ("http", lambda banner: banner.split("Server: ")[1].split("\n")[0] if "Server" in banner else "Unknown Apache"),
    443: ("https", lambda banner: banner),
    3128: ("http-proxy", lambda banner: banner.split("Server: ")[1].split("\n")[0] if "Server" in banner else "Unknown Proxy"),
    102: ("rpc", lambda banner: banner if banner else "Unknown RPC"),
    110: ("pop3", lambda banner: banner if banner else "Unknown POP3"),
    111: ("rpcbind", lambda banner: banner.split("RPC")[1].strip() if "RPC" in banner else "Unknown RPC"),
    123: ("ntp", lambda banner: banner if banner else "Unknown NTP"),
    135: ("msrpc", lambda banner: banner if banner else "Unknown MSRPC"),
    139: ("netbios-ssn", lambda banner: banner.splitlines()[0] if banner else "Unknown SMB"),
    143: ("imap", lambda banner: " ".join([line.split("ready")[0].strip() for line in banner.splitlines() if "ready" in line]) if "ready" in banner else "Unknown IMAP"),
    199: ("smux", lambda banner: banner if banner else "Unknown SMUX"),
    445: ("smb", lambda banner: banner if banner else "Unknown SMB"),
    512: ("exec", lambda banner: banner if banner else "Unknown Exec"),
    513: ("login", lambda banner: banner if banner else "Unknown Login"),
    514: ("shell", lambda banner: banner if banner else "Unknown Syslog"),
    548: ("afp", lambda banner: banner if banner else "Unknown AFP"),
    554: ("rtsp", lambda banner: banner if banner else "Unknown RTSP"),
    691: ("msexchange", lambda banner: banner if banner else "Unknown MS"),
    993: ("ssl/imap", lambda banner: " ".join([line.split("ready")[0].strip() for line in banner.splitlines() if "ready" in line]) if "ready" in banner else "Unknown IMAP"),
    995: ("ssl/pop3", lambda banner: banner if banner else "Unknown POP3"),
    1099: ("rmi", lambda banner: banner if banner else "Unknown RMI"),
    1723: ("pptp", lambda banner: banner if banner else "Unknown PPTP"),
    1524: ("ingreslock", lambda banner: banner if banner else "Unknown Ingres Lock"),
    2049: ("nfs", lambda banner: banner if banner else "Unknown NFS"),
    2121: ("ccproxy-ftp", lambda banner: banner if banner else "Unknown FTP"),
    3306: ("mysql", lambda banner: f"MySQL {banner.split()[1].split()[0]}" if banner else "Unknown MySQL"),
    3389: ("ms-wbt-server", lambda banner: banner if banner else "Unknown MS-WBT"),
    3632: ("distcc", lambda banner: banner if banner else "Unknown DistCC"),
    5432: ("postgresql", lambda banner: banner if banner else "Unknown PostgreSQL"),
    5900: ("vnc", lambda banner: banner if banner else "Unknown VNC"),
    6000: ("x11", lambda banner: banner if banner else "Unknown X11"),
    6667: ("irc", lambda banner: banner if banner else "Unknown IRC"),
    6697: ("irc-u", lambda banner: banner if banner else "Unknown IRC"),
    8009: ("ajp13", lambda banner: banner if banner else "Unknown AJP13"),
    8080: ("tcpwrapped", lambda banner: banner if banner else "Unknown TCPW"),
    8180: ("http", lambda banner: banner if banner else "Unknown ...."),
    8787: ("drb", lambda banner: banner if banner else "Unknown DRB"),
    36150: ("status", lambda banner: banner if banner else "Unknown Status"),
    49639: ("nlockmgr", lambda banner: banner if banner else "Unknown NLOCKMGR"),
    54016: ("java-rmi", lambda banner: banner if banner else "Unknown Java-RMI"),
    56108: ("mount", lambda banner: banner if banner else "Unknown Mount")
}

class PingChecker:
    def __init__(self, target_ips):
        self.target_ips = target_ips
        conf.verb = 0  # Suppress Scapy warnings

    def check(self):
        """Kiểm tra xem các IP có thể ping được hay không và trả về danh sách các IP có thể ping được."""
        reachable_ips = []
        for ip in self.target_ips:
            try:
                packet = IP(dst=ip) / ICMP()
                reply = sr1(packet, timeout=2, verbose=0)
                
                if reply is not None:
                    reachable_ips.append(ip)
            except Exception:
                pass
        return reachable_ips

class ArpScanner:
    def __init__(self, network_cidr, iface=None):
        self.network_cidr = network_cidr
        self.iface = iface

    def scan(self):
        """Quét ARP trong mạng và trả về danh sách IP và MAC."""
        try:
            # Gửi ARP request tới địa chỉ broadcast
            packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=self.network_cidr)
            answered, _ = srp(packet, iface=self.iface, timeout=2, verbose=0)
            # Trích xuất IP và MAC từ phản hồi
            devices = []
            for sent, received in answered:
                devices.append({"ip": received.psrc, "mac": received.hwsrc})
            
            return devices
        except PermissionError:  # Lỗi thiếu quyền hạn
            print("Error: This action requires administrative/root privileges.")
            print("Please run this script as an administrator (Windows) or with sudo (Linux).")
            return []
        except Exception as e:
            print(f"Error during ARP scan: {e}")
            return []

# --- BannerScanner ---
class BannerScanner:
    def __init__(self, ip, port, protocol="TCP"):
        self.ip = ip
        self.port = port
        self.protocol = protocol.upper()

    def banner_grabbing(self):
        try:
            if self.protocol == "UDP":
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(5)

                # Truy vấn DNS hợp lệ cho port 53
                if self.port == 53:
                    query = b"\xaa\xaa\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01"
                    sock.sendto(query, (self.ip, self.port))
                    response, _ = sock.recvfrom(512)  # Nhận phản hồi DNS
                    return response.decode("utf-8", errors="ignore").strip()
                
                sock.sendto(b"\n", (self.ip, self.port))  # Truy vấn mặc định
                response, _ = sock.recvfrom(1024)
                return response.decode("utf-8", errors="ignore").strip()

            else:  # Xử lý TCP
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                sock.connect((self.ip, self.port))
                
                if self.port == 443:
                    context = ssl.create_default_context()
                    with context.wrap_socket(sock, server_hostname=self.ip) as ssock:
                        cert = ssock.getpeercert()
                        return f"TLS Certificate: {cert.get('subject', 'Unknown')}"
                
                sock.sendall(b"HEAD / HTTP/1.1\r\nHost: example.com\r\n\r\n" if self.port in [80, 3128] else b"\n")
                banner = sock.recv(1024)
                return banner.decode("utf-8", errors="ignore").strip()

        except Exception as e:
            return f"Error: {e}"


# --- Service Version Scanner ---
class ServiceVersionScanner:
    def __init__(self, target: str, ports: List[int], protocol: str = "TCP"):
        self.target = target
        self.ports = ports
        self.protocol = protocol.upper()
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")

    def scan(self) -> List[Tuple[int, str, str, str]]:
        """
        Thực hiện quét phiên bản dịch vụ.
        
        Returns:
            List[Tuple[int, str, str, str]]: Danh sách kết quả quét
            (port, state, service, version)
        """
        try:
            results = []
            for port in self.ports:
                self.logger.debug(f"Scanning port {port}")
                state, service, version = self.detect_service_version(port)
                results.append((port, state, service, version))
            return results
        except Exception as e:
            self.logger.error(f"Error during scan: {str(e)}")
            raise

    def detect_service_version(self, port):
        state = "CLOSED"
        service, version = "N/A", "N/A"

        try:
            if self.protocol == "TCP":
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                result = sock.connect_ex((self.target, port))
                if result != 0:
                    return state, service, version
            else:  # UDP
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(10)
                sock.sendto(b"\n", (self.target, port))
                response, _ = sock.recvfrom(1024)
                banner = response.decode("utf-8", errors="ignore")
                state = "OPEN"
                return state, "udp-service", banner

            banner_scanner = BannerScanner(self.target, port, self.protocol)
            banner = banner_scanner.banner_grabbing()
            service, version = self.parse_banner(port, banner)

            state = "OPEN"
            return state, service, version

        except Exception as e:
            return state, service, str(e)

    def parse_banner(self, port, banner):
        if port in port_service_map:
            service, version_func = port_service_map[port]
            version = version_func(banner)
            return service, version
        return "unknown", "Unknown"