import sys
from scapy.sendrecv import send
from scapy.layers.inet import IP, TCP, fragment

TARGET = "scanme.nmap.org"
DST_PORT = 80

def syn_fragmented():
    ip = IP(dst=TARGET)
    tcp = TCP(sport=DST_PORT, dport=80, flags='S', seq=12345)

    packet = ip / tcp
    print(f"[+] Packet created successfully for {TARGET}:{DST_PORT}.")

    # Fragment it into pieces of 8-byte chunks (artificially low to force many fragments)
    fragments = fragment(packet, 8)
    print("[+] Fragmented successfully.")

    for frag in fragments:
        send(frag, timeout=2, verbose=0)

    print("[+] Fragments sent successfully.")

if __name__ == '__main__':
    try:
        syn_fragmented()
    except KeyboardInterrupt:
        print("[!] User interrupted the process.")
        sys.exit()
    except PermissionError:
        print("[-] Permission denied, run with sudo or administration.")