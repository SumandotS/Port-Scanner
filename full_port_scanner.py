import socket
import nmap
from scapy.all import IP, UDP, sr1, ICMP
from colorama import Fore, Style
import time

# ------------------ TCP SCANNER ------------------ #
def basic_tcp_scan(target, ports):
    print(f"\n{Fore.YELLOW}[*] Basic TCP Port Scan on {target}{Style.RESET_ALL}")
    start_time = time.time()
    
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((target, port))
            if result == 0:
                print(f"{Fore.GREEN}[+] Port {port} is OPEN{Style.RESET_ALL}")
            sock.close()
        except Exception as e:
            print(f"{Fore.RED}[!] Error scanning port {port}: {e}{Style.RESET_ALL}")
    
    print(f"{Fore.CYAN}[*] TCP Scan completed in {round(time.time() - start_time, 2)}s.{Style.RESET_ALL}")

# ------------------ NMAP SCANNER ------------------ #
def nmap_scan(target, ports="1-1024"):
    print(f"\n{Fore.YELLOW}[*] Nmap Scan on {target} - Ports: {ports}{Style.RESET_ALL}")
    scanner = nmap.PortScanner()
    scanner.scan(hosts=target, arguments=f'-p {ports} -sV')

    for host in scanner.all_hosts():
        print(f"Host: {host} ({scanner[host].hostname()})")
        print(f"State: {scanner[host].state()}")
        for proto in scanner[host].all_protocols():
            print(f"Protocol: {proto}")
            for port in sorted(scanner[host][proto].keys()):
                info = scanner[host][proto][port]
                print(f"  Port: {port} | State: {info['state']} | Service: {info['name']}")

# ------------------ UDP SCANNER ------------------ #
def udp_scan(target, ports):
    print(f"\n{Fore.YELLOW}[*] UDP Port Scan on {target}{Style.RESET_ALL}")
    for port in ports:
        pkt = IP(dst=target)/UDP(dport=port)
        resp = sr1(pkt, timeout=1, verbose=0)
        if resp is None:
            print(f"{Fore.BLUE}[?] Port {port}: Open|Filtered{Style.RESET_ALL}")
        elif resp.haslayer(UDP):
            print(f"{Fore.GREEN}[+] Port {port}: Open{Style.RESET_ALL}")
        elif resp.haslayer(ICMP):
            icmp = resp.getlayer(ICMP)
            if icmp.type == 3 and icmp.code == 3:
                print(f"{Fore.RED}[-] Port {port}: Closed{Style.RESET_ALL}")
            else:
                print(f"{Fore.MAGENTA}[!] Port {port}: Filtered (ICMP type {icmp.type}){Style.RESET_ALL}")

# ------------------ MAIN ------------------ #
if __name__ == "__main__":
    target = input("Enter target IP/domain: ").strip()
    
    try:
        socket.gethostbyname(target)
    except:
        print(f"{Fore.RED}[!] Invalid target. Exiting.{Style.RESET_ALL}")
        exit()

    print(f"\n{Fore.CYAN}=== Port Scanner Menu ==={Style.RESET_ALL}")
    print("1. Basic TCP Scan")
    print("2. Nmap Scan")
    print("3. UDP Scan")
    print("4. All of the above")

    choice = input("Select scan type [1-4]: ")

    # Define default ports
    common_tcp_ports = list(range(1, 1025))
    common_udp_ports = [53, 67, 69, 123, 161, 500, 520]

    if choice == '1':
        basic_tcp_scan(target, common_tcp_ports)
    elif choice == '2':
        nmap_scan(target)
    elif choice == '3':
        udp_scan(target, common_udp_ports)
    elif choice == '4':
        basic_tcp_scan(target, common_tcp_ports)
        nmap_scan(target)
        udp_scan(target, common_udp_ports)
    else:
        print(f"{Fore.RED}[!] Invalid choice.{Style.RESET_ALL}")
