# Purple Team Range — Technical Report

**Target:** Metasploitable2 (10.10.10.20) | **Attacker:** Kali Linux 2026.2 (10.10.10.10) | **Detection:** Wazuh 4.9.2 + Suricata 8.0.7 (10.10.10.30)
**Lab network:** isolated VirtualBox Internal Network `purple-range` (10.10.10.0/24), no internet exposure
**Testing window:** 13–26 Oct 2026

---

## 1. Methodology

Every vulnerability class in this engagement was tested using a consistent four-stage approach, applied at each DVWA security level (Low → Medium → High) where applicable:

1. **Black-box / OSINT recon** — fingerprint the target (banners, version strings, public advisories) before touching the app.
2. **Form hypothesis** — predict the likely defense and likely bypass based on the fingerprint.
3. **White-box source review** — confirm the actual server-side logic via View Source / direct file access.
4. **Exploit + document** — execute the bypass, capture evidence, and record the exact mechanism (not just "it worked").

This mirrors how a real detection engineer or pentester validates findings rather than treating a vulnerability scanner's output as ground truth.

---

## 2. Findings Summary (CVSS v3.1)

Each score below is computed from its full vector string, not estimated. Vectors reflect what was actually demonstrated in this lab (e.g., read-only data exfiltration is scored C:H/I:N/A:N, not C:H/I:H/A:H, unless write/execute access was proven).

| # | Finding | CVSS v3.1 Vector | Base Score | Severity | MITRE |
|---|---|---|---|---|---|
| 1 | vsftpd 2.3.4 backdoor — unauthenticated RCE as root (CVE-2011-2523) | `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` | 9.8 | Critical | T1190 |
| 2 | Samba `usermap_script` — unauthenticated RCE as root (CVE-2007-2447) | `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` | 9.8 | Critical | T1190 |
| 3 | distccd — unauthenticated RCE as `daemon` (CVE-2004-2687) | `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` | 9.8 | Critical | T1190 |
| 4 | UnrealIRCd backdoor — unauthenticated RCE as root (CVE-2010-2075) | `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` | 9.8 | Critical | T1190 |
| 5 | Tomcat Manager default credentials (`tomcat:tomcat`) → WAR upload RCE | `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` | 8.7 | High | T1190, T1505.003 |
| 6 | Unrestricted file upload → RCE (DVWA Low/Medium/High bypass chain) | `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` | 8.7 | High | T1190 |
| 7 | OS Command Injection (DVWA Low/Medium bypass) | `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` | 8.7 | High | T1059.004 |
| 8 | SUID `nmap` local privilege escalation (tomcat55 → root) | `AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` | 7.7 | High | T1068 |
| 9 | No effective brute-force protection — DVWA High's `sleep(3)` bypassed via multithreading, admin credentials fully compromised | `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` | 9.1 | Critical | T1110.001 |
| 10 | SQL Injection, incl. Blind (DVWA Low/Medium bypass) — authenticated, read-only data exfiltration | `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` | 6.5 | Medium | T1190 |
| 11 | Local File Inclusion via path traversal (DVWA Low/Medium bypass) | `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` | 6.5 | Medium | T1190 |
| 12 | CSRF — unauthenticated/forged admin password change (DVWA Low/Medium/High bypass) | `AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N` | 6.5 | Medium | — (OWASP A01:2021) |
| 13 | Reflected & Stored XSS — session cookie theft demonstrated | `AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N` | 6.1 | Medium | — (OWASP A03:2021) |
| 14 | Anonymous/null-session SMB enumeration — 34 local users via RID cycling, world-readable share | `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` | 5.3 | Medium | T1087.001 |
| 15 | Outdated/exposed services & info disclosure (Nikto: phpinfo.php, /doc/, /test/ indexing, HTTP TRACE/XST) | `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` | 5.3 | Medium | — |

**Scope note:** findings #10–13 represent the *successful bypass*, not the vulnerable app's worst theoretical case — e.g., SQLi here is scored for the read-only UNION/boolean/time-based extraction actually performed, not a hypothetical write-capable variant that wasn't attempted.

---

## 3. MITRE ATT&CK Technique Coverage

| Technique | ID | Demonstrated via |
|---|---|---|
| Exploit Public-Facing Application | T1190 | vsftpd, Samba, distcc, UnrealIRCd, Tomcat WAR deploy, SQLi, file upload, LFI |
| Network Service Discovery | T1046 | Nmap full scan; detected live by custom Suricata rule (sid 9000001) + custom Wazuh rule (id 100001) |
| Account Discovery: Domain Account (RID cycling analogue) | T1087.001 | enum4linux null-session RID cycling (34 users enumerated) |
| Brute Force: Password Guessing | T1110.001 | Hydra against DVWA Low/Medium/High |
| OS Credential Dumping | T1003.008 | `/etc/shadow` pulled post-exploitation, cracked with John the Ripper |
| Exploitation for Privilege Escalation | T1068 | SUID `nmap` interactive-mode shell-out (tomcat55 → root) |
| Server Software Component: Web Shell | T1505.003 | Manual JSP WAR deployed to Tomcat Manager |
| Command and Scripting Interpreter | T1059.004 | DVWA OS Command Injection (Unix shell) |
| Steal Web Session Cookie | T1539 | XSS payload exfiltrating `PHPSESSID` to an attacker-controlled listener |

**Deliberately not mapped to MITRE:** Reflected/Stored XSS and CSRF are scored and documented under **OWASP Top 10 (2021)** only (A03:2021 — Injection / Cross-Site Scripting, and A01:2021 — Broken Access Control). MITRE ATT&CK's enterprise matrix models post-compromise adversary *behavior*, not web-application vulnerability *classes* — forcing a technique ID onto these would be a mismatch, and OWASP is the correct taxonomy for them.

---

## 4. Detection Engineering

### 4.1 Pipeline
```
Kali (attacker, 10.10.10.10)
   │  nmap -sS (SYN scan)
   ▼
Suricata 8.0.7 on Kali, af-packet on eth1 (purple-range)
   │  ET Open ruleset (53,215 rules) + 1 custom rule (sid:9000001)
   │  writes alerts to eve.json
   ▼
Wazuh agent (kali-attacker, 002) — logcollector tails eve.json
   ▼
Wazuh manager (10.10.10.30) — base Suricata decoder (rule 86601)
   │  + custom correlation rule (id:100001) matching signature_id 9000001
   ▼
Wazuh dashboard — alert rendered with MITRE T1046 tag (Discovery / Network Service Discovery)
```

Metasploitable2 deliberately runs **no** Wazuh agent — Suricata on the wire (monitoring the `purple-range` segment) provides visibility into traffic *to* the target without needing an agent on an intentionally-vulnerable box, which better reflects a real network-tap/IDS deployment model than endpoint-only visibility.

### 4.2 Custom Suricata rule
```
alert tcp 10.10.10.10 any -> 10.10.10.20 any (msg:"PURPLE-RANGE TCP SYN Port Scan Detected"; flags:S; flow:stateless; sid:9000001; rev:4; classtype:attempted-recon;)
```
See [`detections/suricata-local.rules`](detections/suricata-local.rules).

### 4.3 Custom Wazuh rule
```xml
<group name="local,suricata,">
  <rule id="100001" level="10">
    <if_sid>86601</if_sid>
    <field name="alert.signature_id" type="pcre2">^9000001$</field>
    <description>PURPLE-RANGE: Custom Suricata SYN Port Scan rule triggered (sid 9000001)</description>
    <mitre>
      <id>T1046</id>
    </mitre>
  </rule>
</group>
```
See [`detections/wazuh-local_rules.xml`](detections/wazuh-local_rules.xml).

### 4.4 Debugging notes (the part that actually demonstrates understanding)

**Suricata rule not loading (~4 hour root-cause session):** `suricata -T` validated the YAML and reported "0 rules failed," but the live process kept loading exactly 53,215 rules instead of 53,216 across every restart — meaning the custom rule file was never actually being read, despite no error being surfaced. Root cause: the rule file had been appended via `echo | sudo tee -a suricata.yaml`, which landed the new line *outside* the YAML `rule-files:` list structure (correct indentation under the list, but after a point where YAML had already closed the list block). This was isolated using `suricata -r <pcap> -S local.rules -k none` — replaying a captured pcap directly against *only* the candidate rule file, bypassing the full YAML config entirely — which proved the rule's own logic was correct and the bug was in config loading, not rule syntax. Fixed by inserting the `rule-files:` entry at the correct position with `sed`. A second, independent issue (`checksum-checks: no` not set, causing VirtualBox's virtual NIC checksum offload to make Suricata silently drop packets it considered corrupt) was found and fixed in the same session.

**Wazuh rule not firing (two-stage root cause):** The rule was first written against `suricata.signature_id` (guessing a flattened field name) — no match. `wazuh-logtest` with the raw JSON piped in showed the actual Phase 2 decoded field is `data.alert.signature_id` *as displayed in the dashboard/indexer*, but critically, the indexer's `data.` prefix is added at the storage/search layer — it is **not** present in the field as the rule-matching engine sees it internally. Confirmed by inspecting `wazuh-logtest`'s own Phase 2 decoded-field dump directly, which showed the bare field as `alert.signature_id` with no prefix at all. The working rule uses `alert.signature_id`, not `data.alert.signature_id`. This distinction — stored/indexed field name vs. internal rule-matching field name — is the kind of thing that's easy to miss and worth being able to explain in an interview.

---

## 5. Key Findings — Named Patterns Worth Highlighting

These are the findings most worth leading with in an interview, because they show *security reasoning*, not just "ran a tool":

- **"Medium" security labels that don't defend against the relevant threat.** DVWA's Medium Brute Force level adds `mysqli_real_escape_string()` — a SQL injection mitigation — while leaving zero rate-limiting or lockout in place. The brute force succeeded in the same ~30 seconds as Low. The defense addressed the wrong vulnerability class entirely.
- **Escaping protects characters, not meaning.** Medium-level Blind SQLi escapes quote characters, but the injection point requires no quotes at all (hex-encoded literals, time-based `SLEEP()`). A defense can be syntactically correct and semantically useless.
- **`sleep(3)` only throttles sequential requests.** DVWA High's brute-force delay was fully bypassed by Hydra's `-t 16` multithreading — the same total wall-clock cost, parallelized.
- **A "require current password" check is not CSRF protection.** DVWA High's CSRF defense re-validates the current password but has no anti-CSRF token — trivially bypassed by including `password_current=password` (DVWA's known default) in the forged request.
- **Browser-side mitigations can mask (and be mistaken for) app-level defenses.** The CSRF Medium bypass initially appeared to fail via an `<img>` subresource tag — not because of DVWA's broken `eregi("127.0.0.1", ...)` check, but because Firefox's default `SameSite=Lax` cookie policy withholds cookies on subresource loads. Switching to a top-level auto-submitting `<form>` (which Lax does allow) succeeded immediately. The real, intentionally-broken app-level check was confirmed separately via source review.
- **A password-change endpoint that doesn't invalidate existing sessions** turns a one-time CSRF bypass into persistent account takeover — the legitimate admin's already-open session kept working even after their password was silently changed out from under them.

---

## 6. Lessons Learned

- CVSS scoring should reflect what was actually demonstrated, not the theoretical worst case of a vulnerability class — this matters for defensible, credible reporting.
- Detection engineering debugging is rarely about rule syntax; it's about understanding exactly which layer (capture, config load, decode, index) a given field name or behavior belongs to.
- MITRE ATT&CK is the wrong taxonomy for some findings (XSS, CSRF) — knowing when *not* to force a mapping is itself a sign of understanding the framework rather than just filling in a table.
- Hardware constraints (8GB RAM, one VM comfortably at a time) shaped real operational discipline: VMs were shut down between phases rather than left running, mirroring cost/resource-conscious habits relevant to any real SOC environment.

---

## 7. Evidence Index

All screenshots are under [`evidence/`](evidence/), organized by phase:

| Folder | Phase |
|---|---|
| `01-recon/` | Nmap scans, enum4linux, smbclient SMB enumeration |
| `02-vuln-scan/` | Nikto scans (port 80 and port 8180) |
| `03-exploitation/` | Metasploit exploits (vsftpd, Samba, distcc, UnrealIRCd) + manual Tomcat WAR deploy |
| `04-webapp/` | DVWA — SQLi, Blind SQLi, Command Injection, XSS, File Inclusion, File Upload, CSRF, Burp Suite, SQLMap |
| `05-password-attacks/` | John the Ripper, Hydra brute force (Low/Medium/High) |
| `06-privesc/` | SUID nmap privilege escalation, LinPEAS |
| `07-packet-analysis/` | tcpdump capture + Wireshark SYN/SYN-ACK/RST analysis |
| `08-detection/` | Suricata + Wazuh integration, custom rule development, final verification |
