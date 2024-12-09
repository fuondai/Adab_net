import whois
from colorama import Fore, Style


def whoisinfo(host):
    """Quét thông tin WHOIS của một domain."""
    try:
        print(f'[{Fore.YELLOW}?{Style.RESET_ALL}] Retrieving WHOIS info for {Fore.YELLOW}{host}{Style.RESET_ALL}...')    
        whois_info = whois.whois(host)
    except Exception as e:
        print(f'[{Fore.RED}!{Style.RESET_ALL}] Error: {e}')
    else:
        display_whois_info(host, whois_info)


def display_whois_info(host, whois_info):
    """Hiển thị thông tin WHOIS của host."""
    if isinstance(whois_info.domain_name, str):
        print(f'[{Fore.GREEN}+{Style.RESET_ALL}] Domain name: {Fore.GREEN}{whois_info.domain_name}{Style.RESET_ALL}')
    else:
        print(f'[{Fore.GREEN}+{Style.RESET_ALL}] Domain names:')
        whois_checker(host, whois_info.domain_name)

    print(f'[{Fore.GREEN}+{Style.RESET_ALL}] Registrar: {Fore.GREEN}{whois_info.registrar}{Style.RESET_ALL}')
    print(f'[{Fore.GREEN}+{Style.RESET_ALL}] WHOIS server: {Fore.GREEN}{whois_info.whois_server}{Style.RESET_ALL}')

    print(f'[{Fore.GREEN}+{Style.RESET_ALL}] Name servers:')
    whois_checker(host, whois_info.name_servers)

    print(f'[{Fore.GREEN}+{Style.RESET_ALL}] Creation date:')
    handle_date_field(host, whois_info.creation_date)

    print(f'[{Fore.GREEN}+{Style.RESET_ALL}] Updated date:')
    handle_date_field(host, whois_info.updated_date)

    print(f'[{Fore.GREEN}+{Style.RESET_ALL}] Expiration date:')
    handle_date_field(host, whois_info.expiration_date)

    print(f'[{Fore.GREEN}+{Style.RESET_ALL}] Status:')
    whois_checker(host, whois_info.status)

    print(f'[{Fore.GREEN}+{Style.RESET_ALL}] Email:')
    whois_checker(host, whois_info.emails)

    print(f'[{Fore.GREEN}+{Style.RESET_ALL}] Organization:')
    whois_checker(host, whois_info.org)

    print(f'[{Fore.GREEN}+{Style.RESET_ALL}] State: {Fore.GREEN}{whois_info.state}{Style.RESET_ALL}')
    print(f'[{Fore.GREEN}+{Style.RESET_ALL}] Country: {Fore.GREEN}{whois_info.country}{Style.RESET_ALL}\n')


def handle_date_field(host, date_field):
    """Xử lý trường dữ liệu ngày tháng trong thông tin WHOIS."""
    if isinstance(date_field, list):
        print(f'[{Fore.GREEN}+{Style.RESET_ALL}] Multiple dates:')
        whois_checker(host, date_field)
    else:
        print(f'[{Fore.GREEN}+{Style.RESET_ALL}] {date_field}')


def whois_checker(host, dictionary):
    """Kiểm tra và in các giá trị từ danh sách hoặc chuỗi WHOIS."""
    try:
        length = len(dictionary)
    except:
        print(f'\t{Fore.GREEN}{dictionary}{Style.RESET_ALL}')
    else:
        for value in dictionary:
            print(f'\t{Fore.GREEN}{value}{Style.RESET_ALL}')
