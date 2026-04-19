# Python Socket Cheatsheet for Security

A quick reference for using Python's `socket` module in security scripts.

---

## Basic TCP Connection

```python
import socket

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(1)
result = s.connect_ex(('192.168.1.1', 80))  # returns 0 if open
s.close()
```

---

## Basic UDP Socket

```python
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.sendto(b"ping", ('192.168.1.1', 53))
data, addr = s.recvfrom(1024)
```

---

## Banner Grabbing

```python
import socket

def grab_banner(ip, port):
    try:
        s = socket.socket()
        s.settimeout(2)
        s.connect((ip, port))
        s.sendall(b'HEAD / HTTP/1.0\r\n\r\n')
        banner = s.recv(1024).decode(errors='ignore')
        return banner.strip()
    except Exception as e:
        return str(e)
    finally:
        s.close()

print(grab_banner('192.168.1.1', 80))
```

---

## Resolve Hostname to IP

```python
ip = socket.gethostbyname('example.com')
print(ip)
```

---

## Get Service Name from Port

```python
service = socket.getservbyport(443)  # returns 'https'
```

---

## Threaded Port Scanner (Simple)

```python
import socket
from concurrent.futures import ThreadPoolExecutor

def check_port(host, port):
    try:
        with socket.socket() as s:
            s.settimeout(0.5)
            if s.connect_ex((host, port)) == 0:
                print(f"[OPEN] {port}")
    except:
        pass

host = "192.168.1.1"
with ThreadPoolExecutor(max_workers=100) as ex:
    for port in range(1, 1025):
        ex.submit(check_port, host, port)
```

---

## Socket Families

| Constant | Meaning |
|---|---|
| `AF_INET` | IPv4 |
| `AF_INET6` | IPv6 |
| `SOCK_STREAM` | TCP |
| `SOCK_DGRAM` | UDP |
| `SOCK_RAW` | Raw socket |

---

## Common Ports Reference

| Port | Service |
|---|---|
| 21 | FTP |
| 22 | SSH |
| 23 | Telnet |
| 25 | SMTP |
| 53 | DNS |
| 80 | HTTP |
| 443 | HTTPS |
| 445 | SMB |
| 3306 | MySQL |
| 3389 | RDP |

---

## MITRE Mapping
- T1046 — Network Service Discovery (port scanning)
- T1595 — Active Scanning (banner grabbing)
