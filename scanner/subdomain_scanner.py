import requests
import sys
from threading import Thread, Lock, Semaphore
from queue import Queue
from colorama import Fore, Style
import time

# Khởi tạo đối tượng Queue và Lock
q = Queue()
list_lock = Lock()
semaphore = Semaphore(10)  # Hạn chế số lượng thread đồng thời (10 threads)
discovered_domains = []

# Tối đa số lần retry khi không thể kết nối
MAX_RETRIES = 3

def scan_subdomains(domain):
    """Quét subdomains từ hàng đợi."""
    global q
    while True:
        try:
            # Lấy subdomain từ queue
            subdomain = q.get()
            # Xây dựng URL từ subdomain
            url = f"http://{subdomain}.{domain}"

            # Gửi yêu cầu HTTP
            response = attempt_request(url)
            if response:
                print(f'[{Fore.GREEN}+{Style.RESET_ALL}] Discovered subdomain: {Fore.GREEN}{url}{Style.RESET_ALL}')
                with list_lock:
                    discovered_domains.append(url)
            else:
                print(f"[{Fore.YELLOW}?{Style.RESET_ALL}] Subdomain {Fore.YELLOW}{url}{Style.RESET_ALL} is not reachable.")

        except KeyboardInterrupt:
            sys.exit('^C')
        except Exception as e:
            print(f'[{Fore.RED}!{Style.RESET_ALL}] Error: {Fore.RED}{e}{Style.RESET_ALL}')
        finally:
            # Đảm bảo hoàn thành công việc trong queue
            q.task_done()

        semaphore.release()

def attempt_request(url):
    """Cố gắng gửi yêu cầu HTTP, retry nếu gặp lỗi."""
    retries = 0
    while retries < MAX_RETRIES:
        try:
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                return response
        except requests.ConnectionError:
            retries += 1
            time.sleep(1)  # Delay before retrying
        except Exception as e:
            print(f"[{Fore.RED}!{Style.RESET_ALL}] Error during request to {url}: {e}")
            break
    return None

def main(domain, threads, subdomains):
    """Điều khiển quá trình quét subdomain."""
    print(f'[{Fore.YELLOW}?{Style.RESET_ALL}] Starting subdomain enumeration for {Fore.YELLOW}{domain}{Style.RESET_ALL}...\nPress CTRL-C to cancel.')

    # Đưa các subdomains vào queue
    try:
        for subdomain in subdomains:
            q.put(subdomain)

        # Khởi tạo và bắt đầu các threads
        for _ in range(threads):
            worker = Thread(target=scan_subdomains, args=(domain,))
            worker.daemon = True  # Thread sẽ tự động dừng khi chương trình chính dừng
            worker.start()

    except KeyboardInterrupt:
        sys.exit('^C')
    except Exception as e:
        print(f'[{Fore.RED}!{Style.RESET_ALL}] Error: {Fore.RED}{e}{Style.RESET_ALL}')

def sdenum(domain, wordlist):
    """Hàm thực hiện quét subdomain."""
    threads = 10  # Sử dụng 10 threads đồng thời

    try:
        with open(wordlist, 'r') as file:
            subdomains = file.read().splitlines()

        main(domain=domain, threads=threads, subdomains=subdomains)
        q.join()

        # In kết quả
        if discovered_domains:
            print(f'\nScan completed. {Fore.GREEN}{len(discovered_domains)}{Style.RESET_ALL} subdomain(s) discovered.\n')
        else:
            print(f'Scan completed. No subdomains found.\n')

    except KeyboardInterrupt:
        sys.exit('^C')
    except Exception as e:
        print(f'[{Fore.RED}!{Style.RESET_ALL}] Error: {Fore.RED}{e}{Style.RESET_ALL}')
