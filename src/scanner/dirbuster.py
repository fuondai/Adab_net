import requests
import sys
from threading import Thread, Lock
from queue import Queue
from colorama import Fore, Style, init

# Khởi tạo colorama để hỗ trợ màu sắc
init(autoreset=True)

# Biến toàn cục
q = Queue()
list_lock = Lock()
discovered_directories = []


def scan_directories(host):
    """Quét các thư mục từ hàng đợi và kiểm tra xem có tồn tại hay không."""
    while not q.empty():
        directory = q.get()
        url = f"http://{host}/{directory}"

        try:
            response = requests.head(url, timeout=5)
            if response.status_code != 404:
                print(f"[{Fore.GREEN}+{Style.RESET_ALL}] Discovered directory: {Fore.GREEN}{url}{Style.RESET_ALL}")
                with list_lock:
                    discovered_directories.append(url)

        except requests.RequestException as e:
            print(f"[{Fore.RED}!{Style.RESET_ALL}] Error: {Fore.RED}{e}{Style.RESET_ALL}")

        finally:
            q.task_done()


def dirbust(host, wordlist, threads=8):
    """Hàm chính để thực hiện quét thư mục."""
    try:
        # Đọc wordlist từ file
        with open(wordlist, "r") as file:
            directories = file.read().splitlines()

        print(f"[{Fore.YELLOW}?{Style.RESET_ALL}] Performing directory busting on {Fore.YELLOW}{host}{Style.RESET_ALL}...\n")

        # Đưa các thư mục vào hàng đợi
        for directory in directories:
            q.put(directory)

        # Tạo và khởi động các luồng
        for _ in range(threads):
            worker = Thread(target=scan_directories, args=(host,))
            worker.daemon = True
            worker.start()

        # Chờ tất cả các luồng hoàn thành
        q.join()

        # Hiển thị kết quả sau khi quét
        if discovered_directories:
            print(f"\n[{Fore.GREEN}+{Style.RESET_ALL}] Scan completed. {Fore.GREEN}{len(discovered_directories)}{Style.RESET_ALL} directories discovered.")
        else:
            print(f"\n[{Fore.YELLOW}-{Style.RESET_ALL}] Scan completed. No directories were discovered.")

    except FileNotFoundError:
        print(f"[{Fore.RED}!{Style.RESET_ALL}] Error: Wordlist file not found: {wordlist}")
    except KeyboardInterrupt:
        sys.exit(f"\n[{Fore.RED}!{Style.RESET_ALL}] Scan interrupted by user.")
    except Exception as e:
        print(f"[{Fore.RED}!{Style.RESET_ALL}] Error: {Fore.RED}{e}{Style.RESET_ALL}")
