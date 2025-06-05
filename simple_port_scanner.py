import socket
from colorama import Fore, Style
import time

def scan_target(target, ports):
    print(f"\n{Fore.YELLOW}Scanning target: {target}{Style.RESET_ALL}")
    start_time = time.time()
    
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)  # short timeout for faster scanning
        
        result = sock.connect_ex((target, port))
        if result == 0:
            print(f"{Fore.GREEN}[+] Port {port} is OPEN{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}[-] Port {port} is closed{Style.RESET_ALL}")
        sock.close()
    
    print(f"\n{Fore.CYAN}Scan completed in {round(time.time() - start_time, 2)} seconds.{Style.RESET_ALL}")

if __name__ == "__main__":
    target = input("Enter the IP address or domain: ")
    ports = list(range(1, 1025))  # Common ports 1-1024
    scan_target(target, ports)
