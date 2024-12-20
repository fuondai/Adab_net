import ftplib
import telnetlib
import paramiko
import smtplib
import socket
import threading
from typing import List, Dict, Tuple, Optional

class AuthScanner:
    def __init__(
        self, 
        targets: List[str], 
        credentials_file: Optional[str] = None,
        timeout: int = 5
    ):
        """
        Khởi tạo AuthScanner.
        
        Args:
            targets: Danh sách các target cần quét
            credentials_file: File chứa credentials (optional)
            timeout: Thời gian timeout cho mỗi kết nối
        """
        self.targets = targets
        self.credentials = self._load_credentials(credentials_file)
        self.timeout = timeout
        self.results: Dict[str, Dict[str, List[Tuple[str, str]]]] = {}
        
    def _load_credentials(self, credentials_file: str) -> List[Tuple[str, str]]:
        """
        Load credentials from a file or use default credentials
        
        :param credentials_file: Path to credentials file
        :return: List of (username, password) tuples
        """
        default_creds = [
            ('admin', 'admin'),
            ('root', 'root'),
            ('user', 'user'),
            ('test', 'test'),
            ('admin', ''),
            ('', '')
        ]
        
        if not credentials_file:
            return default_creds
        
        try:
            with open(credentials_file, 'r') as f:
                custom_creds = [tuple(line.strip().split(':')) for line in f]
                return custom_creds + default_creds
        except Exception as e:
            print(f"Error loading credentials: {e}")
            return default_creds
    
    def _check_ftp(self, host: str, username: str, password: str) -> bool:
        """Check FTP authentication"""
        try:
            ftp = ftplib.FTP(timeout=self.timeout)
            ftp.connect(host)
            ftp.login(username, password)
            ftp.quit()
            return True
        except Exception:
            return False
    
    def _check_telnet(self, host: str, username: str, password: str) -> bool:
        """Check Telnet authentication"""
        try:
            tn = telnetlib.Telnet(host, timeout=self.timeout)
            tn.read_until(b"login: ")
            tn.write(username.encode('ascii') + b"\n")
            tn.read_until(b"Password: ")
            tn.write(password.encode('ascii') + b"\n")
            response = tn.read_some()
            tn.close()
            return b"Welcome" in response or b"successful" in response
        except Exception:
            return False
    
    def _check_ssh(self, host: str, username: str, password: str) -> bool:
        """Check SSH authentication"""
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(host, username=username, password=password, timeout=self.timeout)
            client.close()
            return True
        except Exception:
            return False
    
    def _check_smtp(self, host: str, username: str, password: str) -> bool:
        """Check SMTP authentication"""
        try:
            smtp = smtplib.SMTP(host, timeout=self.timeout)
            smtp.login(username, password)
            smtp.quit()
            return True
        except Exception:
            return False
    
    def _scan_host(self, host: str, port: int = 21):
        """Scan a single host for authentication vulnerabilities"""
        host_results = {
            'ftp': [],
            'telnet': [],
            'ssh': [],
            'smtp': []
        }
        
        for username, password in self.credentials:
            try:
                if port == 21:  # FTP
                    if self._check_ftp(host, username, password):
                        host_results['ftp'].append((username, password))
                
                elif port == 23:  # Telnet
                    if self._check_telnet(host, username, password):
                        host_results['telnet'].append((username, password))
                
                elif port == 22:  # SSH
                    if self._check_ssh(host, username, password):
                        host_results['ssh'].append((username, password))
                
                elif port == 25:  # SMTP
                    if self._check_smtp(host, username, password):
                        host_results['smtp'].append((username, password))
            except Exception:
                pass
        
        # Only store results with successful credentials
        filtered_results = {k: v for k, v in host_results.items() if v}
        if filtered_results:
            self.results[host] = filtered_results
    
    def scan(self, ports: List[int] = None):
        """
        Perform authentication scanning on targets
        
        :param ports: List of ports to scan (default: [21, 22, 23, 25])
        :return: Dictionary of scan results
        """
        ports = ports or [21, 22, 23, 25]
        threads = []
        
        for host in self.targets:
            for port in ports:
                thread = threading.Thread(target=self._scan_host, args=(host, port))
                thread.start()
                threads.append(thread)
        
        for thread in threads:
            thread.join()
        
        return self.results
