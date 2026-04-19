# Regex Patterns for Log Parsing

Essential regex patterns for parsing common security log formats in Python.

---

## Quick Reference

```python
import re

# Test a pattern
pattern = re.compile(r'your_pattern_here')
match = pattern.search(log_line)
if match:
    print(match.groups())
```

---

## SSH / Auth Log Patterns

```python
# Failed SSH login
FAILED_SSH = re.compile(
    r'(\w+\s+\d+\s[\d:]+).*Failed password for (?:invalid user )?(\S+) from ([\d.]+)'
)

# Successful SSH login
ACCEPTED_SSH = re.compile(
    r'(\w+\s+\d+\s[\d:]+).*Accepted password for (\S+) from ([\d.]+)'
)

# Invalid user attempt
INVALID_USER = re.compile(
    r'Invalid user (\S+) from ([\d.]+)'
)

# SSH disconnection
DISCONNECT = re.compile(
    r'Disconnected from ([\d.]+) port (\d+)'
)
```

**Example log line:**
```
Apr 14 09:23:11 server sshd[1234]: Failed password for root from 192.168.1.100 port 54321 ssh2
```

---

## IP Address Extraction

```python
# Match any IPv4 address
IPV4 = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')

# Match private IP ranges only
PRIVATE_IP = re.compile(
    r'\b(10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)\b'
)

# Extract all IPs from a log file
with open('/var/log/auth.log') as f:
    content = f.read()
    ips = IPV4.findall(content)
    print(set(ips))  # unique IPs
```

---

## Apache / Nginx Access Log

```python
# Combined Log Format
APACHE_ACCESS = re.compile(
    r'([\d.]+)\s+'           # IP
    r'\S+\s+\S+\s+'          # ident, authuser
    r'\[([^\]]+)\]\s+'       # timestamp
    r'"(\S+)\s+(\S+)\s+\S+"\s+'  # method, path
    r'(\d+)\s+'              # status code
    r'(\d+)'                 # bytes
)

# Example usage
line = '192.168.1.1 - - [14/Apr/2026:09:00:00 +0000] "GET /admin HTTP/1.1" 404 512'
m = APACHE_ACCESS.match(line)
if m:
    ip, ts, method, path, status, size = m.groups()
```

---

## Windows Event Log Patterns

```python
# Event ID extraction
EVENT_ID = re.compile(r'EventID[=:\s]+(\d+)')

# Failed logon (Event 4625)
FAILED_LOGON = re.compile(
    r'Account Name:\s+(\S+).*'
    r'Source Network Address:\s+([\d.]+)',
    re.DOTALL
)

# Logon type
LOGON_TYPE = re.compile(r'Logon Type:\s+(\d+)')
```

**Logon Type Reference:**

| Type | Description |
|---|---|
| 2 | Interactive (local) |
| 3 | Network |
| 4 | Batch |
| 5 | Service |
| 10 | RemoteInteractive (RDP) |

---

## URL & Domain Extraction

```python
# Extract URLs
URL = re.compile(r'https?://[^\s<>"\'()]+')

# Extract domains
DOMAIN = re.compile(r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b')

# Suspicious file extensions in URLs
SUSPICIOUS_EXT = re.compile(r'https?://\S+\.(exe|bat|ps1|vbs|js|jar|scr)\b')
```

---

## Useful Flags

```python
re.IGNORECASE   # case insensitive
re.MULTILINE    # ^ and $ match line boundaries
re.DOTALL       # . matches newlines too
re.VERBOSE      # allows comments in pattern
```

---

## Brute Force Detection (Full Example)

```python
import re
from collections import defaultdict

pattern = re.compile(
    r'Failed password for (?:invalid user )?(\S+) from ([\d.]+)'
)

counts = defaultdict(int)

with open('/var/log/auth.log') as f:
    for line in f:
        m = pattern.search(line)
        if m:
            ip = m.group(2)
            counts[ip] += 1

# Flag IPs over threshold
THRESHOLD = 5
for ip, count in counts.items():
    if count >= THRESHOLD:
        print(f"[ALERT] Brute force suspected: {ip} ({count} attempts)")
```
