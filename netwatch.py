import os
import ipaddress
from datetime import datetime
from scapy.all import sniff, IP, get_if_list
from colorama import Fore, Style, init

init(autoreset=True)

stats = {
    "permission_denied": 0,
    "memory_errors": 0,
    "packets_processed": 0,
    "foreign_packets": 0
}

LOG_FILE = "suspicious_packets.log"


BR_RANGES = [
    ipaddress.ip_network("177.0.0.0/8"),
    ipaddress.ip_network("191.0.0.0/8"),
    ipaddress.ip_network("200.128.0.0/10"),
    ipaddress.ip_network("201.0.0.0/8"),
    ipaddress.ip_network("186.192.0.0/11"),
]

def clear():
    os.system("cls")

def banner():
    print(Fore.GREEN + r"""
 ███████╗██████╗  ██████╗ ███╗   ██╗████████╗███████╗██╗██████╗  █████╗ 
 ██╔════╝██╔══██╗██╔═══██╗████╗  ██║╚══██╔══╝██╔════╝██║██╔══██╗██╔══██╗
 █████╗  ██████╔╝██║   ██║██╔██╗ ██║   ██║   █████╗  ██║██████╔╝███████║
 ██╔══╝  ██╔══██╗██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██║██╔══██╗██╔══██║
 ██║     ██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║██║  ██║██║  ██║
 ╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝╚═╝  ╚═╝╚═╝  ╚═╝
""")
    print("  Egress Monitor | -- | CIDR Based (BR)\n")

def is_ip_from_brazil(ip_str):
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        for net in BR_RANGES:
            if ip_obj in net:
                return True
        return False
    except ValueError:
        return True

def handle_packet(pkt):
    try:
        if IP not in pkt:
            return

        stats["packets_processed"] += 1

        dst_ip = pkt[IP].dst

        if not is_ip_from_brazil(dst_ip):
            stats["foreign_packets"] += 1

            print(
                f"{Fore.RED}[ALERT] Foreign traffic detected "
                f"{pkt[IP].src} ➜ {dst_ip}"
            )

            with open(LOG_FILE, "a", encoding="utf-8") as f:
                f.write("\n=== SUSPICIOUS PACKET ===\n")
                f.write(f"Time: {datetime.now()}\n")
                f.write(pkt.show(dump=True))
                f.write("\n")

    except MemoryError:
        stats["memory_errors"] += 1
        print(Fore.RED + "[!] MemoryError — packet dropped")

    except PermissionError:
        stats["permission_denied"] += 1
        print(Fore.RED + "[!] Permission Denied while handling packet")

    except Exception:
        print(Fore.YELLOW + "[!] Non-fatal packet error")

def main():
    clear()
    banner()

    print(Fore.YELLOW + "[*] Available interfaces:\n")
    interfaces = get_if_list()

    for i, iface in enumerate(interfaces):
        print(f"[{i}] {iface}")

    try:
        idx = int(input("\nSelect interface >>> "))
        iface = interfaces[idx]
    except:
        print(Fore.RED + "[!] Invalid interface selection")
        return

    print(Fore.GREEN + f"\n[*] Monitoring interface: {iface}")
    print(Fore.GREEN + "[*] Promiscuous mode requested via Npcap")
    print(Fore.GREEN + "[*] Press CTRL+C to stop\n")

    try:
        sniff(
            iface=iface,
            prn=handle_packet,
            store=False
        )

    except PermissionError:
        stats["permission_denied"] += 1
        print(Fore.RED + "[FATAL] Permission Denied — run as Administrator")

    except KeyboardInterrupt:
        pass

    finally:
        print("\n===== OPERATION SUMMARY =====")
        for k, v in stats.items():
            print(f"{k}: {v}")

if __name__ == "__main__":
    main()