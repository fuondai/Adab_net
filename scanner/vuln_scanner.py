import shodan
import requests
import time
import sys
from colorama import Fore, Style


def get_host_ip(target, api_key):
    """Resolve domain to IP using Shodan DNS resolve API."""
    try:
        dns_resolve_url = f'https://api.shodan.io/dns/resolve?hostnames={target}&key={api_key}'
        resolved = requests.get(dns_resolve_url)
        resolved.raise_for_status()  # Check for HTTP request errors

        # Return resolved IP if successful
        return resolved.json().get(target)
    
    except requests.RequestException as e:
        print(f'[{Fore.RED}!{Style.RESET_ALL}] Error resolving domain {target}: {e}')
        return None


def vulnscan(host, api_key):
    """Perform vulnerability scanning using Shodan API."""
    try:
        print(f'[{Fore.YELLOW}?{Style.RESET_ALL}] Vulnerability scanning on {Fore.YELLOW}{host}{Style.RESET_ALL}...')
        
        # Initialize Shodan API client
        api = shodan.Shodan(api_key)
        
        # Resolve host to IP address
        host_ip = get_host_ip(host, api_key)
        if not host_ip:
            return

        # Perform a Shodan search on that IP
        host_info = api.host(host_ip)
        print(f'[{Fore.GREEN}+{Style.RESET_ALL}] Target: {host}')
        print(f"[{Fore.GREEN}+{Style.RESET_ALL}] IP: {host_info['ip_str']}")
        print(f"[{Fore.GREEN}+{Style.RESET_ALL}] Organization: {host_info.get('org', 'n/a')}")
        print(f"[{Fore.GREEN}+{Style.RESET_ALL}] Operating System: {host_info.get('os', 'n/a')}\n")

        # Print all banners (ports and services)
        for item in host_info['data']:
            print(f"[{Fore.GREEN}+{Style.RESET_ALL}] Port: {Fore.GREEN}{item['port']}{Style.RESET_ALL}")
            print(f"[{Fore.GREEN}+{Style.RESET_ALL}] Banner: {Fore.GREEN}{item['data']}{Style.RESET_ALL}")

        # Print vulnerability information
        if 'vulns' in host_info and len(host_info['vulns']) > 0:
            print(f"[{Fore.GREEN}+{Style.RESET_ALL}] {len(host_info['vulns'])} vulnerability(ies) found on {Fore.YELLOW}{host}{Style.RESET_ALL}")
            for vuln in host_info['vulns']:
                CVE = vuln.replace('!', '')
                print(f"\n[{Fore.GREEN}+{Style.RESET_ALL}] Vulnerability: {Fore.GREEN}{vuln}{Style.RESET_ALL}")
                
                # Wait a second to avoid hitting rate limits
                time.sleep(1)
                
                # Fetch exploits for the CVE
                exploits = api.exploits.search(CVE)
                for exploit in exploits['matches']:
                    print(f"Exploit description: {exploit.get('description', 'No description available')}")
        else:
            print(f"[{Fore.GREEN}+{Style.RESET_ALL}] No vulnerabilities found on {Fore.YELLOW}{host}{Style.RESET_ALL}.\n{Fore.YELLOW}Disclaimer{Style.RESET_ALL}: This doesn't mean the host isn't vulnerable.\n")

    except KeyboardInterrupt:
        sys.exit('^C\n')
    except shodan.APIError as e:
        print(f'[{Fore.RED}!{Style.RESET_ALL}] Shodan API error: {Fore.RED}{e}{Style.RESET_ALL}')
    except Exception as e:
        print(f'[{Fore.RED}!{Style.RESET_ALL}] Unexpected error: {Fore.RED}{e}{Style.RESET_ALL}')
