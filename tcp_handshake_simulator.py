from scapy.layers.inet import IP, TCP
from scapy.sendrecv import sr1, send
import sys
import random

TARGET = "scanme.nmap.org"
DST_PORT = 80

def tcp_handshake(dst=TARGET, dport=DST_PORT):
    src_port = random.randint(1024, 29999)
    print(f"[+] Creating packets for {TARGET}:{DST_PORT}")
    seq = 1000

    ip = IP(dst=dst)
    syn = TCP(sport=src_port, dport=dport, flags ='S', seq=seq)
    packet_syn = ip / syn
    packet_syn.show()

    print("[+] Sending SYN packet...")
    syn_ack = sr1(packet_syn, verbose=0)

    if syn_ack is None:
        print("[-] No SYN-ACK received, the target might be down or filtered.")
        return

    print("[+] Received SYN-ACK Packet")
    syn_ack.show()

    if syn_ack.haslayer(TCP) and syn_ack[TCP].flags == 0x12:
        ack = TCP(sport=src_port, dport=dport, flags='A', seq=syn_ack.ack, ack=syn_ack.seq + 1)
        packet_ack = ip / ack

        print("[+] Sending ACK packet...")
        packet_ack.show()

        send(packet_ack, verbose=0)

        print("[+] Sending RST packet...")
        rst = TCP(sport=src_port, dport=dport, flags='R', seq=syn_ack.ack)
        packet_rst = ip / rst

        send(packet_rst, verbose=0)
        print("[+] Successfully simulated the 3 ways TCP handshake.")
    else:
        print("[+] Received SYN-ACK does not contains TCP layer or 0x12 flag.")
        return


if __name__ == '__main__':
    try:
        tcp_handshake()
    except KeyboardInterrupt:
        print("[-] User interrupted the process.")
        sys.exit()
    except PermissionError:
        print("[!] Permission denied, run with sudo or administrator.")
        sys.exit()