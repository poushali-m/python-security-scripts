# MITRE ATT&CK Mapping — Python Security Automation

Maps common Python security scripts and techniques to the MITRE ATT&CK framework.

---

## What is MITRE ATT&CK?

MITRE ATT&CK is a globally recognised knowledge base of adversary tactics and techniques. It's used by defenders to understand how attackers operate and to map defensive tools to real-world threats.

> Using ATT&CK mapping in your scripts shows you understand the *why* behind the technique, not just the *how*.

---

## Reconnaissance (TA0043)

| Technique | ID | Python Implementation |
|---|---|---|
| Network Service Discovery | T1046 | Port scanner using `socket` |
| Active Scanning | T1595 | Nmap wrapper, banner grabbing |
| Gather Victim Network Info | T1590 | WHOIS, DNS enumeration |
| Phishing for Information | T1598 | Phishing email analyser |

```python
# T1046 — Network Service Discovery
import socket
def is_open(host, port):
    with socket.socket() as s:
        s.settimeout(0.5)
        return s.connect_ex((host, port)) == 0
```

---

## Initial Access (TA0001)

| Technique | ID | Python Implementation |
|---|---|---|
| Phishing | T1566 | Email header/body analyser |
| Spearphishing Link | T1566.002 | URL reputation checker |
| Spearphishing Attachment | T1566.001 | Attachment type analyser |

---

## Credential Access (TA0006)

| Technique | ID | Python Implementation |
|---|---|---|
| Brute Force | T1110 | Auth log brute-force detector |
| Password Spraying | T1110.003 | Failed login pattern analyser |
| OS Credential Dumping | T1003 | (Detection only — log monitoring) |

```python
# T1110 — Detecting Brute Force
from collections import defaultdict
import re

pattern = re.compile(r'Failed password.*from ([\d.]+)')
counts = defaultdict(int)

with open('/var/log/auth.log') as f:
    for line in f:
        m = pattern.search(line)
        if m:
            counts[m.group(1)] += 1

for ip, n in counts.items():
    if n >= 5:
        print(f"[T1110] Brute force from {ip}: {n} attempts")
```

---

## Defence Evasion (TA0005)

| Technique | ID | Python Implementation |
|---|---|---|
| Indicator Removal | T1070 | Log tampering detection |
| Masquerading | T1036 | File extension mismatch checker |

---

## Discovery (TA0007)

| Technique | ID | Python Implementation |
|---|---|---|
| Network Service Discovery | T1046 | Port scanner |
| System Info Discovery | T1082 | Banner grabbing |
| File & Directory Discovery | T1083 | Directory brute-forcer |

---

## Impact / Integrity (TA0040)

| Technique | ID | Python Implementation |
|---|---|---|
| Data Manipulation | T1565 | File integrity checker (detect changes) |
| Defacement | T1491 | Web page hash monitoring |

```python
# T1565 — Detecting File Tampering
import hashlib, json, os

def hash_file(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            h.update(chunk)
    return h.hexdigest()

# Compare against saved baseline
with open('baseline.json') as f:
    baseline = json.load(f)

for filepath, expected_hash in baseline.items():
    if os.path.exists(filepath):
        current = hash_file(filepath)
        if current != expected_hash:
            print(f"[T1565] MODIFIED: {filepath}")
    else:
        print(f"[T1565] DELETED: {filepath}")
```

---

## Defensive Mapping (Blue Team View)

| Your Script | Detects | ATT&CK Technique |
|---|---|---|
| `brute_force_detector.py` | SSH brute force | T1110 |
| `phishing_analyser.py` | Phishing emails | T1566, T1598 |
| `file_integrity_checker.py` | File tampering | T1565 |
| `port_scanner.py` | Network recon simulation | T1046 |

---

## Resources

- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)
- [D3FEND (Defensive Techniques)](https://d3fend.mitre.org/)
