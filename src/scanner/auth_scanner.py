from typing import List, Dict, Any
from .base import BaseScanner
import ftplib
import telnetlib
import paramiko
import smtplib
import socket
import threading
from colorama import Fore, Style

class AuthScanner(BaseScanner):
    """Scanner để kiểm tra xác thực"""
    
    def __init__(self, targets: List[str], **kwargs):
        super().__init__(targets, **kwargs)
        self.creds_file = kwargs.get('creds_file')
        self.timeout = kwargs.get('timeout', 5)
        self.results = {}
        self._load_credentials()

    def _load_credentials(self):
        """Load credentials từ file"""
        self.credentials = [
            ('admin', 'admin'),
            ('root', 'root'),
            ('admin', ''),
            ('', '')
        ]
        
        if self.creds_file:
            try:
                with open(self.creds_file, 'r') as f:
                    for line in f:
                        if ':' in line:
                            user, pwd = line.strip().split(':')
                            self.credentials.append((user, pwd))
            except Exception as e:
                print(f"[{Fore.RED}!{Style.RESET_ALL}] Error loading credentials: {e}")

    def _check_ftp(self, host: str, username: str, password: str) -> bool:
        """Kiểm tra xác thực FTP"""
        try:
            with ftplib.FTP(timeout=self.timeout) as ftp:
                ftp.connect(host, 21)
                ftp.login(username, password)
                return True
        except:
            return False

    def _check_ssh(self, host: str, username: str, password: str) -> bool:
        """Kiểm tra xác thực SSH"""
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(host, username=username, password=password, timeout=self.timeout)
            ssh.close()
            return True
        except:
            return False

    def _check_telnet(self, host: str, username: str, password: str) -> bool:
        """Kiểm tra xác thực Telnet"""
        try:
            tn = telnetlib.Telnet(host, timeout=self.timeout)
            tn.read_until(b"login: ")
            tn.write(username.encode('ascii') + b"\n")
            tn.read_until(b"Password: ")
            tn.write(password.encode('ascii') + b"\n")
            response = tn.read_some()
            tn.close()
            return b'Welcome' in response or b'success' in response
        except:
            return False

    def scan(self) -> Dict[str, Any]:
        """Thực hiện quét xác thực"""
        for target in self.targets:
            self.results[target] = {
                'ftp': [],
                'ssh': [],
                'telnet': []
            }
            
            for username, password in self.credentials:
                # Check FTP
                if self._check_ftp(target, username, password):
                    self.results[target]['ftp'].append((username, password))
                    
                # Check SSH
                if self._check_ssh(target, username, password):
                    self.results[target]['ssh'].append((username, password))
                    
                # Check Telnet
                if self._check_telnet(target, username, password):
                    self.results[target]['telnet'].append((username, password))
                    
        return self.results

    def print_results(self) -> None:
        """In kết quả quét xác thực"""
        print("\nAuthentication Scan Results:")
        print("-" * 60)
        
        for target, services in self.results.items():
            print(f"\nTarget: {Fore.YELLOW}{target}{Style.RESET_ALL}")
            
            for service, creds in services.items():
                if creds:
                    print(f"\n{Fore.GREEN}{service.upper()}{Style.RESET_ALL} - Vulnerable credentials found:")
                    for username, password in creds:
                        print(f"  Username: {Fore.RED}{username}{Style.RESET_ALL}")
                        print(f"  Password: {Fore.RED}{password}{Style.RESET_ALL}")
                else:
                    print(f"\n{service.upper()} - No vulnerable credentials found") 