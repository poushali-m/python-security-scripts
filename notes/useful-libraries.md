# Useful Python Libraries for Security Work

A curated list of Python libraries used in security scripting, automation, and analysis.

---

## Standard Library (No Install Needed)

| Library | Use Case |
|---|---|
| `socket` | Port scanning, banner grabbing, raw connections |
| `re` | Regex log parsing, pattern matching |
| `hashlib` | MD5, SHA-1, SHA-256 hashing |
| `email` | Parse and analyse .eml email files |
| `argparse` | Build CLI tools |
| `json` | Parse/generate JSON reports |
| `subprocess` | Run system commands from Python |
| `os` / `pathlib` | File system operations |
| `datetime` | Timestamps in reports |
| `collections` | `defaultdict`, `Counter` for log analysis |
| `concurrent.futures` | Threaded scanning |
| `urllib.parse` | Parse and inspect URLs |
| `ipaddress` | Validate and work with IP ranges |

---

## Network & Scanning

```python
# scapy — packet crafting and sniffing
pip install scapy

from scapy.all import IP, TCP, sr1
packet = IP(dst="192.168.1.1")/TCP(dport=80, flags="S")
response = sr1(packet, timeout=1)
```

```python
# python-nmap — Nmap wrapper
pip install python-nmap

import nmap
nm = nmap.PortScanner()
nm.scan('192.168.1.1', '22-443')
print(nm['192.168.1.1']['tcp'])
```

```python
# requests — HTTP requests for web recon
pip install requests

import requests
r = requests.get('https://example.com', timeout=5)
print(r.status_code, r.headers)
```

---

## DNS & Domain Recon

```python
# dnspython — DNS lookups
pip install dnspython

import dns.resolver
answers = dns.resolver.resolve('example.com', 'MX')
for r in answers:
    print(r.exchange)
```

```python
# whois — WHOIS lookups
pip install python-whois

import whois
w = whois.whois('example.com')
print(w.registrar, w.creation_date)
```

---

## Cryptography & Hashing

```python
# cryptography — encryption, decryption, key management
pip install cryptography

from cryptography.fernet import Fernet
key = Fernet.generate_key()
f = Fernet(key)
token = f.encrypt(b"sensitive data")
```

```python
# passlib — password hashing
pip install passlib

from passlib.hash import bcrypt
hashed = bcrypt.hash("password123")
```

---

## Log Analysis & Data

```python
# pandas — structured log analysis
pip install pandas

import pandas as pd
df = pd.read_csv('access.log', sep=' ', header=None)
print(df[5].value_counts())  # status codes
```

---

## Reporting & Visualisation

```python
# rich — beautiful terminal output
pip install rich

from rich.console import Console
from rich.table import Table
console = Console()
table = Table(title="Scan Results")
table.add_column("IP")
table.add_column("Port")
console.print(table)
```

```python
# jinja2 — HTML report templates
pip install jinja2

from jinja2 import Template
t = Template("<h1>{{ title }}</h1>")
print(t.render(title="Security Report"))
```

---

## Web App Testing

```python
# beautifulsoup4 — HTML parsing
pip install beautifulsoup4

from bs4 import BeautifulSoup
soup = BeautifulSoup(html, 'html.parser')
links = [a['href'] for a in soup.find_all('a', href=True)]
```

---

## Quick Install — Core Security Set

```bash
pip install requests scapy python-nmap dnspython python-whois pandas rich beautifulsoup4
```

---

## Library → MITRE Technique Mapping

| Library | Relevant Technique |
|---|---|
| `socket` / `nmap` | T1046 — Network Service Discovery |
| `scapy` | T1595 — Active Scanning |
| `requests` | T1190 — Exploit Public-Facing Application |
| `dnspython` | T1590 — Gather Victim Network Info |
| `hashlib` | T1110 — Brute Force (hash cracking) |
