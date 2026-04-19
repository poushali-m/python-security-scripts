# 🐍 Python for Security — Scripts & Study Notes

A personal reference repo of Python scripts, snippets, and notes built while learning security automation. Covers port scanning, log analysis, hash cracking, network recon, and more.

![Python](https://img.shields.io/badge/Python-3.8+-3776AB?style=flat-square&logo=python&logoColor=white)
![Domain](https://img.shields.io/badge/Domain-Security%20Automation-557C94?style=flat-square)
![Status](https://img.shields.io/badge/Status-Active%20%7C%20Growing-50C8A0?style=flat-square)

> 📚 This repo grows as I learn. Scripts are documented, explained, and mapped to real-world use cases.

---

## 📂 Contents

| Folder | Topic | Scripts |
|---|---|---|
| [`01-networking/`](./01-networking/) | Port scanning, banner grabbing, ping sweeps | 4 |
| [`02-log-analysis/`](./02-log-analysis/) | Auth log parsing, brute-force detection, IP extraction | 4 |
| [`03-hashing/`](./03-hashing/) | MD5/SHA hashing, file integrity checker, hash identifier | 3 |
| [`04-file-analysis/`](./04-file-analysis/) | Suspicious string extractor, metadata reader, entropy calc | 3 |
| [`05-automation/`](./05-automation/) | Directory brute-forcer, subdomain enumerator, report generator | 3 |
| [`notes/`](./notes/) | Concept notes, cheatsheets, and references | — |

---

## 🔧 Scripts Index

### 01 — Networking

| Script | What It Does |
|---|---|
| `port_scanner.py` | TCP port scanner with banner grabbing |
| `ping_sweep.py` | Discover live hosts on a subnet |
| `banner_grabber.py` | Grab service banners from open ports |
| `whois_lookup.py` | WHOIS + basic recon on a domain |

### 02 — Log Analysis

| Script | What It Does |
|---|---|
| `auth_log_parser.py` | Parse `/var/log/auth.log` for failed logins |
| `brute_force_detector.py` | Flag IPs exceeding failed login threshold |
| `ip_extractor.py` | Extract and count unique IPs from any log file |
| `ssh_session_tracker.py` | Track SSH session open/close events |

### 03 — Hashing

| Script | What It Does |
|---|---|
| `hash_generator.py` | Generate MD5, SHA-1, SHA-256 hashes |
| `file_integrity_checker.py` | Baseline and verify file hashes |
| `hash_identifier.py` | Identify hash type from string length/pattern |

### 04 — File Analysis

| Script | What It Does |
|---|---|
| `string_extractor.py` | Extract readable strings from binary files |
| `metadata_reader.py` | Read file metadata (timestamps, permissions) |
| `entropy_calculator.py` | Calculate file entropy (high entropy = possible encryption/packing) |

### 05 — Automation

| Script | What It Does |
|---|---|
| `dir_bruteforcer.py` | HTTP directory brute-forcer using wordlist |
| `subdomain_enum.py` | Enumerate subdomains via DNS resolution |
| `report_generator.py` | Generate structured text/JSON security reports |

---

## 📝 Notes

| Note | Topic |
|---|---|
| [`notes/python-socket-cheatsheet.md`](./notes/python-socket-cheatsheet.md) | Socket programming basics for security |
| [`notes/regex-for-logs.md`](./notes/regex-for-logs.md) | Regex patterns for log parsing |
| [`notes/useful-libraries.md`](./notes/useful-libraries.md) | Key Python libraries for security work |
| [`notes/mitre-mapping.md`](./notes/mitre-mapping.md) | Mapping automation techniques to MITRE ATT&CK |

---

## 🚀 Getting Started

```bash
git clone https://github.com/poushali-m/python-security-scripts
cd python-security-scripts

# Most scripts use standard library only
python 01-networking/port_scanner.py

# Some scripts need extra libraries
pip install requests dnspython
```

---

## ⚠️ Disclaimer

All scripts are for **educational and defensive security purposes only**. Run only against systems you own or have explicit permission to test.

---

## 👩‍💻 Author

**Poushali Majumder** — Aspiring Cyber Security Analyst, London 🇬🇧

[![Portfolio](https://img.shields.io/badge/Portfolio-50C8A0?style=flat-square)](https://poushali-m.github.io)
[![GitHub](https://img.shields.io/badge/GitHub-181717?style=flat-square&logo=github&logoColor=white)](https://github.com/poushali-m)
