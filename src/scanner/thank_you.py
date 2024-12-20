import os
import random
import time
import subprocess
import requests
from colorama import Fore, Back, Style

# Biến global để theo dõi trạng thái hiển thị
_banner_shown = False
_api_key_verified = False

def verify_api_key(api_key: str) -> bool:
    """Xác thực API key với server"""
    global _api_key_verified
    
    # Nếu đã xác thực thành công trước đó thì trả về True
    if _api_key_verified:
        return True
        
    try:
        # Gửi request đến server để xác thực
        response = requests.post(
            "http://localhost:5000/verify",
            json={"api_key": api_key},
            timeout=5
        )
        
        # Kiểm tra response
        if response.status_code == 200:
            _api_key_verified = True
            return True
        return False
        
    except requests.exceptions.RequestException as e:
        print(f"{Fore.RED}[!] Error connecting to license server: {e}{Style.RESET_ALL}")
        return False

def intro():
    """Hiển thị logo và thông tin"""
    logo = f"""
{Fore.CYAN}   
****************************************************************************************************************************************************************************
                                                             														
	 █████╗ ██████╗  █████╗ ██████╗ ███╗   ██╗███████╗████████╗    ███████╗███╗   ██╗████████╗███████╗██████╗ ██████╗ ██████╗ ██╗███████╗███████╗
	██╔══██╗██╔══██╗██╔══██╗██╔══██╗████╗  ██║██╔════╝╚══██╔══╝    ██╔════╝████╗  ██║╚══██╔══╝██╔════╝██╔══██╗██╔══██╗██╔══██╗██║██╔════╝██╔════╝
	███████║██║  ██║███████║██████╔╝██╔██╗ ██║█████╗     ██║       █████╗  ██╔██╗ ██║   ██║   █████╗  ██████╔╝██████╔╝██████╔╝██║███████╗█████╗  
	���█╔══██║██║  ██║██╔══██║██╔══██╗██║╚██╗██║██╔══╝     ██║       ██╔══╝  ██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗██╔═══╝ ██╔══██╗██║╚════██║██╔══╝  
	██║  ██║██████╔╝██║  ██║██████╔╝██║ ╚████║███████╗   ██║       ███████╗██║ ╚████║   ██║   ███████╗██║  ██║██║     ██║  ██║██║███████║███████╗
	╚═╝  ╚═╝╚═════╝ ╚═╝  ╚═╝╚═════╝ ╚═╝  ╚═══╝╚══════╝   ╚═╝       ╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝  ╚═╝╚═╝╚══════╝╚══════╝

	888    888                        888            .d888                                                        888                        d8b                   
	888    888                        888           d88P"                                                         888                        Y8P                   
	888    888                        888           888                                                           888                                              
	888888 88888b.   8888b.  88888b.  888  888      888888 .d88b.  888d888      88888b.  888  888 888d888 .d8888b 88888b.   8888b.  .d8888b  888 88888b.   .d88b.  
	888    888 "88b     "88b 888 "88b 888 .88P      888   d88""88b 888P"        888 "88b 888  888 888P"  d88P"    888 "88b     "88b 88K      888 888 "88b d88P"88b 
	888    888  888 .d888888 888  888 888888K       888   888  888 888          888  888 888  888 888    888      888  888 .d888888 "Y8888b. 888 888  888 888  888 
	Y88b.  888  888 888  888 888  888 888 "88b      888   Y88..88P 888          888 d88P Y88b 888 888    Y88b.    888  888 888  888      X88 888 888  888 Y88b 888 
	 "Y888 888  888 "Y888888 888  888 888  888      888    "Y88P"  888          88888P"   "Y88888 888     "Y8888P 888  888 "Y888888  88888P' 888 888  888  "Y88888 
		                                                                    888                                                                            888 
		                                                                    888                                                                       Y8b d88P 
                                            
****************************************************************************************************************************************************************************
{Style.RESET_ALL}

{Fore.YELLOW}Repo:{Style.RESET_ALL} https://github.com/fuondai/Adab_net/
{Fore.YELLOW}Email:{Style.RESET_ALL} fuondai1314@gmail.com
{Fore.YELLOW}License:{Style.RESET_ALL} MIT

{Fore.GREEN}███{Fore.RED}███{Fore.GREEN}███{Fore.YELLOW}███{Fore.LIGHTBLUE_EX}███{Fore.MAGENTA}██��{Fore.CYAN}███{Fore.WHITE}███
{Fore.LIGHTBLACK_EX}███{Fore.LIGHTRED_EX}███{Fore.LIGHTGREEN_EX}███{Fore.LIGHTYELLOW_EX}███{Fore.BLUE}███{Fore.LIGHTMAGENTA_EX}███{Fore.LIGHTCYAN_EX}███{Fore.LIGHTWHITE_EX}███
{Style.RESET_ALL}
"""
    print(logo)

def welcome(api_key: str = None):
    """Hiển thị welcome banner và kiểm tra API key"""
    global _banner_shown
    
    # Chỉ hiển thị banner khi chưa hiển thị trước đó và có API key hợp lệ
    if not _banner_shown and api_key:
        # Xác thực API key với server
        if verify_api_key(api_key):
            # Clear screen
            subprocess.call(['clear'] if os.name != 'nt' else ['cls'])
            
            # Hiển thị intro
            intro()
            
            print(f"{Fore.GREEN}[+] Valid API key - Enterprise features activated{Style.RESET_ALL}")
            _banner_shown = True
            
            # Delay để người dùng đọc
            time.sleep(3)
            
            # Clear screen again
            subprocess.call(['clear'] if os.name != 'nt' else ['cls'])