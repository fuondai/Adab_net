import whois
from typing import List, Dict, Any
from colorama import Fore, Style
from .base import BaseScanner

class WhoisScanner(BaseScanner):
    """Scanner để truy vấn thông tin WHOIS"""
    
    def __init__(self, targets: List[str], **kwargs):
        super().__init__(targets, **kwargs)
        self.results = {}

    def _handle_date_field(self, date_field) -> str:
        """Xử lý trường dữ liệu ngày tháng."""
        if isinstance(date_field, list):
            return "\n\t".join(str(d) for d in date_field)
        return str(date_field) if date_field else "Not available"

    def _format_list_field(self, field) -> str:
        """Format trường dữ liệu dạng list."""
        if not field:
            return "Not available"
        if isinstance(field, list):
            return "\n\t".join(str(f) for f in field)
        return str(field)

    def scan(self) -> Dict[str, Any]:
        """Thực hiện quét WHOIS."""
        for host in self.targets:
            try:
                print(f'[{Fore.YELLOW}?{Style.RESET_ALL}] Retrieving WHOIS info for {Fore.YELLOW}{host}{Style.RESET_ALL}...')    
                whois_info = whois.whois(host)
                
                self.results[host] = {
                    'domain_name': self._format_list_field(whois_info.domain_name),
                    'registrar': whois_info.registrar,
                    'whois_server': whois_info.whois_server,
                    'name_servers': self._format_list_field(whois_info.name_servers),
                    'creation_date': self._handle_date_field(whois_info.creation_date),
                    'updated_date': self._handle_date_field(whois_info.updated_date),
                    'expiration_date': self._handle_date_field(whois_info.expiration_date),
                    'status': self._format_list_field(whois_info.status),
                    'emails': self._format_list_field(whois_info.emails),
                    'org': whois_info.org,
                    'state': whois_info.state,
                    'country': whois_info.country
                }
                
            except Exception as e:
                print(f'[{Fore.RED}!{Style.RESET_ALL}] Error: {e}')
                self.results[host] = None

        return self.results

    def print_results(self) -> None:
        """In kết quả quét WHOIS."""
        for host, info in self.results.items():
            if not info:
                print(f"\n[{Fore.RED}!{Style.RESET_ALL}] No WHOIS information found for {host}")
                continue

            print(f"\nWHOIS Information for {Fore.CYAN}{host}{Style.RESET_ALL}")
            print("-" * 60)

            # In thông tin domain
            print(f'[{Fore.GREEN}+{Style.RESET_ALL}] Domain name: {Fore.GREEN}{info["domain_name"]}{Style.RESET_ALL}')
            print(f'[{Fore.GREEN}+{Style.RESET_ALL}] Registrar: {Fore.GREEN}{info["registrar"]}{Style.RESET_ALL}')
            print(f'[{Fore.GREEN}+{Style.RESET_ALL}] WHOIS server: {Fore.GREEN}{info["whois_server"]}{Style.RESET_ALL}')

            # In name servers
            print(f'[{Fore.GREEN}+{Style.RESET_ALL}] Name servers:')
            print(f'\t{Fore.GREEN}{info["name_servers"]}{Style.RESET_ALL}')

            # In thông tin ngày tháng
            print(f'[{Fore.GREEN}+{Style.RESET_ALL}] Creation date:')
            print(f'\t{Fore.GREEN}{info["creation_date"]}{Style.RESET_ALL}')
            
            print(f'[{Fore.GREEN}+{Style.RESET_ALL}] Updated date:')
            print(f'\t{Fore.GREEN}{info["updated_date"]}{Style.RESET_ALL}')
            
            print(f'[{Fore.GREEN}+{Style.RESET_ALL}] Expiration date:')
            print(f'\t{Fore.GREEN}{info["expiration_date"]}{Style.RESET_ALL}')

            # In status và thông tin liên hệ
            print(f'[{Fore.GREEN}+{Style.RESET_ALL}] Status:')
            print(f'\t{Fore.GREEN}{info["status"]}{Style.RESET_ALL}')
            
            print(f'[{Fore.GREEN}+{Style.RESET_ALL}] Emails:')
            print(f'\t{Fore.GREEN}{info["emails"]}{Style.RESET_ALL}')
            
            print(f'[{Fore.GREEN}+{Style.RESET_ALL}] Organization: {Fore.GREEN}{info["org"]}{Style.RESET_ALL}')
            print(f'[{Fore.GREEN}+{Style.RESET_ALL}] State: {Fore.GREEN}{info["state"]}{Style.RESET_ALL}')
            print(f'[{Fore.GREEN}+{Style.RESET_ALL}] Country: {Fore.GREEN}{info["country"]}{Style.RESET_ALL}\n')
