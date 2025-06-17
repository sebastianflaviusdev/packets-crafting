import socket
import sys

def grab_banner(target, port=80):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(3)
            s.connect((target, port))

            if port == 80:
                s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")

            banner = s.recv(1024)
            print(f"[+] Banner from {target}:{port}:\n{banner.decode(errors='ignore')}")

    except socket.timeout:
        print(f"[-] Timeout connecting to {target}:{port}.")
    except socket.error:
        print(f"[-] Error connecting to {target}:{port}.")
    except KeyboardInterrupt:
        print(f"[!] User interrupted the process.")
        sys.exit()

def main():
    target = "scanme.nmap.org"
    ports = [22, 80, 443]

    for port in ports:
        grab_banner(target, port)


if __name__ == "__main__":
    main()








