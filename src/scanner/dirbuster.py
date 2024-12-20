import requests
import sys
from threading import Thread, Lock
from queue import Queue
from colorama import Fore, Style, init
from typing import List, Dict, Any
from .base import BaseScanner

# Khởi tạo colorama
init(autoreset=True)

class DirBuster(BaseScanner):
    """Scanner để quét thư mục web"""
    
    def __init__(self, targets: List[str], **kwargs):
        super().__init__(targets, **kwargs)
        self.wordlist = kwargs.get('wordlist')
        self.threads = kwargs.get('threads', 8)
        self.timeout = kwargs.get('timeout', 5)
        self.results = {}
        
        # Thread-safe objects
        self.queue = Queue()
        self.list_lock = Lock()
        self.discovered_directories = []

    def _scan_directory(self, host: str):
        """Quét một thư mục."""
        while not self.queue.empty():
            directory = self.queue.get()
            url = f"http://{host}/{directory}"

            try:
                response = requests.head(url, timeout=self.timeout)
                if response.status_code != 404:
                    print(f"[{Fore.GREEN}+{Style.RESET_ALL}] Discovered directory: {Fore.GREEN}{url}{Style.RESET_ALL}")
                    with self.list_lock:
                        self.discovered_directories.append(url)

            except requests.RequestException as e:
                print(f"[{Fore.RED}!{Style.RESET_ALL}] Error: {Fore.RED}{e}{Style.RESET_ALL}")

            finally:
                self.queue.task_done()

    def scan(self) -> Dict[str, Any]:
        """Thực hiện quét thư mục."""
        if not self.wordlist:
            raise ValueError("Wordlist is required for directory busting")

        try:
            # Đọc wordlist
            with open(self.wordlist, "r") as file:
                directories = file.read().splitlines()

            # Quét từng target
            for host in self.targets:
                print(f"[{Fore.YELLOW}?{Style.RESET_ALL}] Performing directory busting on {Fore.YELLOW}{host}{Style.RESET_ALL}...")
                
                # Reset queue và discovered directories
                self.queue = Queue()
                self.discovered_directories = []

                # Đưa các thư mục vào queue
                for directory in directories:
                    self.queue.put(directory)

                # Khởi tạo và chạy threads
                threads = []
                for _ in range(self.threads):
                    worker = Thread(target=self._scan_directory, args=(host,))
                    worker.daemon = True
                    worker.start()
                    threads.append(worker)

                # Đợi queue hoàn thành
                self.queue.join()

                # Lưu kết quả
                self.results[host] = self.discovered_directories.copy()

                print(f"\n[{Fore.GREEN}+{Style.RESET_ALL}] Completed scanning {host}")
                print(f"[{Fore.GREEN}+{Style.RESET_ALL}] Found {Fore.GREEN}{len(self.discovered_directories)}{Style.RESET_ALL} directories")

        except FileNotFoundError:
            print(f"[{Fore.RED}!{Style.RESET_ALL}] Error: Wordlist file not found: {self.wordlist}")
        except KeyboardInterrupt:
            print(f"\n[{Fore.RED}!{Style.RESET_ALL}] Scan interrupted by user")
        except Exception as e:
            print(f"[{Fore.RED}!{Style.RESET_ALL}] Error: {Fore.RED}{e}{Style.RESET_ALL}")

        return self.results

    def print_results(self) -> None:
        """In kết quả quét thư mục."""
        print("\nDirectory Busting Results:")
        print("-" * 60)
        
        for host, directories in self.results.items():
            print(f"\nTarget: {Fore.CYAN}{host}{Style.RESET_ALL}")
            if directories:
                print(f"Found {Fore.GREEN}{len(directories)}{Style.RESET_ALL} directories:")
                for directory in directories:
                    print(f"  {Fore.GREEN}{directory}{Style.RESET_ALL}")
            else:
                print(f"[{Fore.YELLOW}-{Style.RESET_ALL}] No directories discovered")
