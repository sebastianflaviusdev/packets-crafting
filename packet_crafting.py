from scapy.layers.inet import IP, TCP, UDP, sr1, ICMP
import sys

TARGET = "scanme.nmap.org"

def send_and_check(packet):
    print("Sending Packet...")
    resp = sr1(packet)

    if resp:
        resp.show()
    else:
        print("Null response")


def send_syn_tcp(dst=TARGET, dport=80):
    print(f"Crafting packet, destination: {dst}, protocol: TCP, destination port: {dport}")
    packet = IP(dst=dst) / TCP(dport=dport, flags = 'S')
    send_and_check(packet)

def send_udp(dst=TARGET, dport=80):
    print(f"Crafting packet, destination: {dst}, protocol: UDP, destination port: {dport}")
    packet = IP(dst=dst) / UDP(dport=dport)
    send_and_check(packet)


def send_icmp(dst=TARGET):
    print(f"Crafting packet, destination: {dst}, protocol: ICMP")
    packet = IP(dst=dst) / ICMP()
    send_and_check(packet)

def main():
    try:
        send_syn_tcp()
        send_udp()
        send_udp()
    except KeyboardInterrupt:
        print("\nInterrupted by user.")
        sys.exit()
    except PermissionError:
        print("Permission denied. Run this script with sudo or as admin.")
        sys.exit()


if __name__ == '__main__':
    main()