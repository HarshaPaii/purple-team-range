# Purple Team Range

An end-to-end offensive + defensive security lab: compromising an intentionally vulnerable target across the full attack chain, then building and debugging the custom detection logic that catches the attack live in a SIEM — all on a Rs 0 / open-source toolchain running on an 8GB-RAM host.

**📄 [Full technical report with CVSS scoring and MITRE ATT&CK mapping →](REPORT.md)**

---

## What this covers

| Phase | What was done |
|---|---|
| **Recon** | Full Nmap service enumeration, SMB null-session enumeration (enum4linux, smbclient) |
| **Vulnerability scanning** | Nikto against two web services |
| **Exploitation** | 4 Metasploit RCEs (vsftpd, Samba, distcc, UnrealIRCd) + 1 fully manual exploit (Tomcat WAR deploy via curl, no Metasploit) |
| **Web application security** | DVWA — SQLi, Blind SQLi, OS Command Injection, Reflected & Stored XSS, LFI, File Upload, CSRF — tested across Low/Medium/High at every level, with source-code review explaining *why* each defense succeeded or failed; Burp Suite + SQLMap |
| **Password attacks** | John the Ripper (offline hash cracking), Hydra (online brute force, including defeating a `sleep()`-based rate limit via multithreading) |
| **Post-exploitation** | Manual Linux privilege escalation (SUID `nmap`) + LinPEAS |
| **Packet analysis** | tcpdump capture + Wireshark TCP handshake/reset analysis |
| **Detection engineering** | Suricata IDS + Wazuh SIEM wired end-to-end; **custom Suricata rule + custom Wazuh correlation rule written, debugged, and verified firing live** against real attack traffic, MITRE-tagged |

## Environment

```
Kali Linux 2026.2 (attacker)  ──┐
  10.10.10.10                   │
                                 ├── Internal Network "purple-range" (10.10.10.0/24, isolated)
Metasploitable2 (target)       │
  10.10.10.20                   │
                                 │
Wazuh SIEM + Suricata (sensor) ─┘
  10.10.10.30 (collector) + 192.168.1.18 (dashboard, bridged)
```
No internet-facing exposure. Entirely open-source tooling (Kali, Metasploit, Suricata, Wazuh, DVWA, Metasploitable2, John, Hydra, SQLMap, Burp Suite Community).

## Key skills demonstrated

- Exploit development/usage across both Metasploit-assisted and fully manual paths
- Source-code-level root-cause analysis of web vulnerabilities (not just "payload worked")
- Defensible CVSS v3.1 scoring from first principles (vector → calculation, not estimation)
- MITRE ATT&CK mapping with judgment about when a technique *doesn't* apply
- SIEM/IDS detection engineering, including real multi-hour debugging of a non-obvious config/field-naming root cause
- Resource-constrained lab operation (8GB RAM, disciplined VM lifecycle management)

## Repo structure

```
├── REPORT.md              ← full findings, CVSS scores, MITRE mapping, detection writeup
├── evidence/               ← screenshots organized by phase
└── detections/
    ├── suricata-local.rules
    └── wazuh-local_rules.xml
```
