"""
port_scanner.py
===============
TCP port scanner with optional banner grabbing.
Usage: python port_scanner.py <host> -p <port_range> [--banners]

Author: Poushali Majumder
"""

import socket
import argparse
import sys
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed


def scan_port(host: str, port: int, timeout: float = 1.0, grab_banner: bool = False):
    """Attempt TCP connection to host:port. Returns (port, open, banner)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((host, port))
            if result == 0:
                banner = ""
                if grab_banner:
                    try:
                        s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                        banner = s.recv(1024).decode(errors="ignore").strip()
                    except Exception:
                        pass
                return (port, True, banner)
    except socket.error:
        pass
    return (port, False, "")


def parse_ports(port_str: str) -> list:
    """Parse port string like '22,80,443' or '1-1024' into a list."""
    ports = []
    for part in port_str.split(","):
        if "-" in part:
            start, end = part.split("-")
            ports.extend(range(int(start), int(end) + 1))
        else:
            ports.append(int(part))
    return ports


def main():
    parser = argparse.ArgumentParser(description="TCP Port Scanner with Banner Grabbing")
    parser.add_argument("host", help="Target host (IP or hostname)")
    parser.add_argument("-p", "--ports", default="1-1024", help="Ports to scan (e.g. 22,80 or 1-1024)")
    parser.add_argument("--banners", action="store_true", help="Attempt banner grabbing on open ports")
    parser.add_argument("--threads", type=int, default=100, help="Number of threads (default: 100)")
    parser.add_argument("--timeout", type=float, default=1.0, help="Connection timeout in seconds")
    args = parser.parse_args()

    # Resolve hostname
    try:
        target_ip = socket.gethostbyname(args.host)
    except socket.gaierror:
        print(f"[!] Could not resolve host: {args.host}")
        sys.exit(1)

    ports = parse_ports(args.ports)
    open_ports = []

    print(f"\n{'='*55}")
    print(f"  PORT SCANNER")
    print(f"{'='*55}")
    print(f"  Target   : {args.host} ({target_ip})")
    print(f"  Ports    : {args.ports} ({len(ports)} total)")
    print(f"  Threads  : {args.threads}")
    print(f"  Started  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*55}\n")

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {
            executor.submit(scan_port, target_ip, port, args.timeout, args.banners): port
            for port in ports
        }
        for future in as_completed(futures):
            port, is_open, banner = future.result()
            if is_open:
                service = ""
                try:
                    service = socket.getservbyport(port)
                except Exception:
                    pass
                open_ports.append((port, service, banner))

    open_ports.sort(key=lambda x: x[0])

    if open_ports:
        print(f"  {'PORT':<8} {'SERVICE':<15} {'BANNER'}")
        print(f"  {'-'*50}")
        for port, service, banner in open_ports:
            banner_short = banner[:40].replace("\n", " ") if banner else ""
            print(f"  {port:<8} {service:<15} {banner_short}")
    else:
        print("  No open ports found.")

    print(f"\n  Scan complete. {len(open_ports)} open port(s) found.")
    print(f"  Finished  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")


if __name__ == "__main__":
    main()
