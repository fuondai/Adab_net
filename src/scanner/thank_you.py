import os
import random
import time
import subprocess
from colorama import Fore, Back, Style
from cryptography.fernet import Fernet

def verify_api_key(api_key: str) -> bool:
    """Xác thực API key"""
    try:
        # Đọc secret key
        with open("secret.key", "rb") as key_file:
            secret_key = key_file.read()
            
        # Đọc license key đã mã hóa
        with open("license.key", "rb") as license_file:
            encrypted_license = license_file.read()
            
        # Giải mã license key
        f = Fernet(secret_key)
        decrypted_license = f.decrypt(encrypted_license).decode()
        
        # So sánh với API key được cung cấp
        return api_key == decrypted_license
    except Exception:
        return False

def intro():
    """Hiển thị logo và thông tin"""
    logo = f"""
{Fore.CYAN}   
****************************************************************************************************************************************************************************
                                                             														
	 █████╗ ██████╗  █████╗ ██████╗ ███╗   ██╗███████╗████████╗    ███████╗███╗   ██╗████████╗███████╗██████╗ ██████╗ ██████╗ ██╗███████╗███████╗
	██╔══██╗██╔══██╗██╔══██╗██╔══██╗████╗  ██║██╔════╝╚══██╔══╝    ██╔════╝████╗  ██║╚══██╔══╝██╔════╝██╔══██╗██╔══██╗██╔══██╗██║██╔════╝██╔════╝
	███████║██║  ██║███████║██████╔╝██╔██╗ ██║█████╗     ██║       █████╗  ██╔██╗ ██║   ██║   █████╗  ██████╔╝██████╔╝██████╔╝██║███████╗█████╗  
	██╔══██║██║  ██║██╔══██║██╔══██╗██║╚██╗██║██╔══╝     ██║       ██╔══╝  ██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗██╔═══╝ ██╔══██╗██║╚════██║██╔══╝  
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

{Fore.GREEN}███{Fore.RED}███{Fore.GREEN}███{Fore.YELLOW}███{Fore.LIGHTBLUE_EX}███{Fore.MAGENTA}███{Fore.CYAN}███{Fore.WHITE}███
{Fore.LIGHTBLACK_EX}███{Fore.LIGHTRED_EX}███{Fore.LIGHTGREEN_EX}███{Fore.LIGHTYELLOW_EX}███{Fore.BLUE}███{Fore.LIGHTMAGENTA_EX}███{Fore.LIGHTCYAN_EX}███{Fore.LIGHTWHITE_EX}███
{Style.RESET_ALL}
"""
    print(logo)

def welcome(api_key: str = None):
    """Hiển thị welcome banner và kiểm tra API key"""
    # Clear screen
    subprocess.call(['clear'] if os.name != 'nt' else ['cls'])
    
    # Hiển thị intro
    intro()
    
    # Kiểm tra API key nếu được cung cấp
    if api_key and verify_api_key(api_key):
        print(f"{Fore.GREEN}[+] Valid API key - Enterprise features activated{Style.RESET_ALL}")
    
    # Delay để người dùng đọc
    time.sleep(3)
    
    # Clear screen again
    subprocess.call(['clear'] if os.name != 'nt' else ['cls']) 