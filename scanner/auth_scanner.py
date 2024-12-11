import ftplib
import telnetlib
import paramiko
import smtplib
import socket
import threading
#import mysql.connector
import psycopg2
import redis
import requests
from typing import List, Dict, Tuple


class AuthScanner:
    def __init__(self, targets: List[str], credentials_file: str = None, max_threads: int = 50):
        """
        Initialize AuthScanner with targets and optional credentials file

        :param targets: List of target IPs or hostnames
        :param credentials_file: Path to file with credentials (optional)
        :param max_threads: Maximum number of concurrent threads
        """
        self.targets = targets
        self.credentials = self._load_credentials(credentials_file)
        self.results = {}
        self.lock = threading.Lock()
        self.semaphore = threading.Semaphore(max_threads)
    
    def _load_credentials(self, credentials_file: str) -> List[Tuple[str, str]]:
        """Load credentials from a file or use default credentials"""
        default_creds = [
            ('admin', 'admin'),
            ('root', 'root'),
            ('user', 'user'),
            ('test', 'test'),
            ('admin', ''),
            ('msfadmin', 'msfadmin'),
            ('', '')
        ]

        if not credentials_file:
            return default_creds

        try:
            with open(credentials_file, 'r') as f:
                custom_creds = [tuple(line.strip().split(':')) for line in f if ':' in line]
                return custom_creds + default_creds
        except Exception as e:
            print(f"Error loading credentials: {e}")
            return default_creds
    
    # --- Service Check Methods ---
    
    def _check_ftp(self, host: str, username: str, password: str) -> bool:
        try:
            ftp = ftplib.FTP(timeout=5)
            ftp.connect(host)
            ftp.login(username, password)
            ftp.quit()
            return True
        except Exception:
            return False
    
    def _check_telnet(self, host: str, username: str, password: str) -> bool:
        try:
            tn = telnetlib.Telnet(host, timeout=5)
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
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(host, username=username, password=password, timeout=5)
            client.close()
            return True
        except Exception:
            return False
    def _check_smtp(self, host: str, username: str, password: str) -> bool:
        try:
            smtp = smtplib.SMTP(host, timeout=5)
            smtp.login(username, password)
            smtp.quit()
            return True
        except Exception:
            return False
    def _check_postgresql(self, host: str, username: str, password: str) -> bool:
        try:
            connection = psycopg2.connect(host=host, user=username, password=password, connect_timeout=5)
            connection.close()
            return True
        except Exception:
            return False
    def _check_redis(self, host: str, password: str) -> bool:
        try:
            client = redis.StrictRedis(host=host, password=password, socket_timeout=5)
            client.ping()
            return True
        except Exception:
            return False
    def _check_http_basic_auth(self, host: str, username: str, password: str) -> bool:
        try:
            response = requests.get(f"http://{host}", auth=(username, password), timeout=5)
            return response.status_code == 200
        except Exception:
            return False
    """      
    def _check_mysql(self, host: str, username: str, password: str) -> bool:
        try:
            connection = mysql.connector.connect(host=host, user=username, password=password, connect_timeout=5)
            connection.close()
            return True
        except Exception:
            return False
    """
    
    # --- Host Scanning Method ---
    
    def _scan_host(self, host: str, port: int, service: str, check_function):
        for username, password in self.credentials:
            try:
                if check_function(host, username, password):
                    with self.lock:
                        print(f"[+] {service.upper()} login successful on {host}:{port} with {username}/{password}")
                        self.results.setdefault(host, []).append((service, port, username, password))
            except Exception:
                pass
        self.semaphore.release()
    
    # --- Main Scan Method ---
    
    def scan(self, ports_services: Dict[int, Tuple[str, callable]]):
        threads = []

        for host in self.targets:
            for port, (service, check_function) in ports_services.items():
                self.semaphore.acquire()
                thread = threading.Thread(target=self._scan_host, 
                                          args=(host, port, service, check_function))
                thread.start()
                threads.append(thread)

        for thread in threads:
            thread.join()

        return self.results
