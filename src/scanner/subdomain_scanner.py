import requests
import sys
from threading import Thread, Lock, Semaphore
from queue import Queue
from colorama import Fore, Style
import time
from typing import List, Dict, Any
from .base import BaseScanner

class SubdomainScanner(BaseScanner):
    """Scanner để quét subdomain"""
    
    def __init__(self, targets: List[str], **kwargs):
        super().__init__(targets, **kwargs)
        self.wordlist = kwargs.get('wordlist', None)
        self.threads = kwargs.get('threads', 10)
        self.timeout = kwargs.get('timeout', 5)
        self.results = {}
        self.discovered_domains = []
        
        # Khởi tạo các đối tượng thread-safe
        self.queue = Queue()
        self.list_lock = Lock()
        self.semaphore = Semaphore(self.threads)
        
    def _attempt_request(self, url: str) -> requests.Response:
        """Cố gắng gửi yêu cầu HTTP, retry nếu gặp lỗi."""
        retries = 0
        max_retries = 3
        
        while retries < max_retries:
            try:
                response = requests.get(url, timeout=self.timeout)
                if response.status_code == 200:
                    return response
            except requests.ConnectionError:
                retries += 1
                time.sleep(1)  # Delay before retrying
            except Exception as e:
                print(f"[{Fore.RED}!{Style.RESET_ALL}] Error during request to {url}: {e}")
                break
        return None

    def _scan_subdomain(self, domain: str):
        """Quét một subdomain."""
        while True:
            try:
                subdomain = self.queue.get()
                url = f"http://{subdomain}.{domain}"

                response = self._attempt_request(url)
                if response:
                    print(f'[{Fore.GREEN}+{Style.RESET_ALL}] Discovered subdomain: {Fore.GREEN}{url}{Style.RESET_ALL}')
                    with self.list_lock:
                        self.discovered_domains.append(url)
                else:
                    print(f"[{Fore.YELLOW}?{Style.RESET_ALL}] Subdomain {Fore.YELLOW}{url}{Style.RESET_ALL} is not reachable.")

            except Exception as e:
                print(f'[{Fore.RED}!{Style.RESET_ALL}] Error: {Fore.RED}{e}{Style.RESET_ALL}')
            finally:
                self.queue.task_done()
                self.semaphore.release()

    def scan(self) -> Dict[str, Any]:
        """Thực hiện quét subdomain."""
        for domain in self.targets:
            try:
                # Load subdomains từ wordlist
                if self.wordlist:
                    with open(self.wordlist, 'r') as file:
                        subdomains = file.read().splitlines()
                else:
                    # Default wordlist
                    subdomains = ['www', 'mail', 'ftp', 'admin', 'blog', 'dev', 'test']

                print(f'[{Fore.YELLOW}?{Style.RESET_ALL}] Starting subdomain enumeration for {Fore.YELLOW}{domain}{Style.RESET_ALL}...')
                print('Press CTRL-C to cancel.')

                # Đưa subdomains vào queue
                for subdomain in subdomains:
                    self.queue.put(subdomain)

                # Khởi tạo và chạy threads
                threads = []
                for _ in range(self.threads):
                    worker = Thread(target=self._scan_subdomain, args=(domain,))
                    worker.daemon = True
                    worker.start()
                    threads.append(worker)

                # Đợi queue hoàn thành
                self.queue.join()

                # Lưu kết quả
                self.results[domain] = self.discovered_domains.copy()
                self.discovered_domains.clear()

            except KeyboardInterrupt:
                print("\nScan cancelled by user")
                break
            except Exception as e:
                print(f'[{Fore.RED}!{Style.RESET_ALL}] Error scanning {domain}: {Fore.RED}{e}{Style.RESET_ALL}')

        return self.results

    def print_results(self) -> None:
        """In kết quả quét subdomain."""
        print("\nSubdomain Scan Results:")
        print("-" * 60)
        
        for domain, subdomains in self.results.items():
            print(f"\nTarget Domain: {domain}")
            if subdomains:
                print(f"\nDiscovered {Fore.GREEN}{len(subdomains)}{Style.RESET_ALL} subdomain(s):")
                for subdomain in subdomains:
                    print(f"  {Fore.GREEN}{subdomain}{Style.RESET_ALL}")
            else:
                print("No subdomains found")
