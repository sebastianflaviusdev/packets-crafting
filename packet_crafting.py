from scapy.layers.inet import IP, TCP, UDP, sr1, ICMP
import sys

TARGET = "scanme.nmap.org"

def send_and_check(packet):
    print("[+] Sending Packet...")
    resp = sr1(packet)

    if resp:
        resp.show()
    else:
        print("[-] Couldn't receive any response.")

def craft_packet(dst, dport):
    print(f"[+] Crafting packet, {dst}:{dport}")
    ip = IP(dst=dst)
    packet = ip / dport
    send_and_check(packet)


def send_syn_tcp(dst=TARGET, dport=80):
    tcp = TCP(dport=dport, flags='S')
    craft_packet(dst, tcp)

def send_udp(dst=TARGET, dport=80):
    udp = UDP(dport=dport)
    craft_packet(dst, udp)

def send_icmp(dst=TARGET):
    icmp = ICMP()
    craft_packet(dst, icmp)


def main():
    try:
        send_syn_tcp()
        send_udp()
        send_icmp()
    except KeyboardInterrupt:
        print("[!] Interrupted by user.")
        sys.exit()
    except PermissionError:
        print("[-] Permission denied. Run this script with sudo or as admin.")
        sys.exit()


if __name__ == '__main__':
    main()