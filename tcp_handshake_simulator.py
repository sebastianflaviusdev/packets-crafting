from scapy.layers.inet import IP, TCP
from scapy.sendrecv import sr1, send
import sys
import random

TARGET = "scanme.nmap.org"
DST_PORT = 80


def tcp_handshake(dst=TARGET, dport=DST_PORT):
    src_port = random.randint(1024, 29999)
    print(f"Creating packets for {TARGET}:{DST_PORT}")

    ip = IP(dst=dst)
    syn = TCP(sport=src_port, dport=dport, flags ='S',seq=1000)

    print("Sending SYN packet...")
    syn_ack = sr1(ip / syn, timeout=2, verbose=0)

    if syn_ack is None:
        print("No SYN-ACK received, the target might be down or filtered.")
        return

    if syn_ack.haslayer(TCP) and syn_ack[TCP].flags == 0x12:
        print("SYN-ACK received successfully.")
        ack = TCP(sport=src_port, dport=dport, flags='A', seq=syn_ack.ack, ack=syn_ack.seq + 1)

        print("Sending ACK packet...")
        send(ip/ack, timeout=2, verbose=0)

        print("Sending RST packet...")
        rst = TCP(sport=src_port, dport=dport, flags='R', seq=syn_ack.ack)
        send(ip/rst, timeout=2, verbose=0)

        print("Successfully simulated the 3 ways TCP handshake.")
    else:
        print("Received SYN-ACK does not contains TCP layer or 0x12 flag.")
        return


if __name__ == '__main__':
    try:
        tcp_handshake()
    except KeyboardInterrupt:
        print("User interrupted the process.")
        sys.exit()
    except PermissionError:
        print("Permission denied, run with sudo or administrator.")
        sys.exit()