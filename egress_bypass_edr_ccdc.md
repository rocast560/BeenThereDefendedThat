# Bypassing Strong Egress Firewall Rules: A CCDC-Focused Threat Model for EDR Design

**Audience:** Blue team engineers / EDR developers building detection logic against the kind of red team you see at CCDC (NCCDC, regionals, Pacific Rim, etc.).
**Goal:** Synthesize the current attacker playbook for getting traffic *out* of a locked-down network, map each technique to MITRE ATT&CK and observable telemetry, and translate that into concrete EDR detection opportunities.

---

## 1. The CCDC Egress Battle

In CCDC, the central asymmetry is well-known: blue teams inherit a network that is already compromised (pre-planted backdoors, default creds, weak services), and the red team's job is to **maintain** access while blue tries to **kill callbacks**. Strict egress filtering is one of the few defensive controls that actually scales against this, because if the red team can't talk to its C2, the foothold is dead. As the Codelivly red team playbook puts it: "Strict Egress Filtering: This is your single most effective defense against tunneling. If attackers can't call home, their foothold is much less valuable."

The corollary is that almost everything the red team does in the first 30 minutes of a CCDC round revolves around **egress survival**. From the Cobalt Strike CCDC tips post (Raphael Mudge): Beacon at CCDC is specifically designed to be "resilient to blocks and harder to detect" by binding multiple call-home IPs to a single system and rotating across HTTP, DNS A records, DNS TXT records, and SMB named pipes for inter-host comms. That multi-protocol, multi-destination posture is the threat model your EDR needs to assume.

Three operational realities shape what your EDR should optimize for:

1. **Speed over precision.** Competition rounds are short. A 90%-accurate detection that fires in 60 seconds is worth more than a 99.9% one that fires in 20 minutes.
2. **Implants are pre-planted.** The most dangerous beacons don't get installed during the round — they were already there at `t=0`. EDR baselining "from now on" is insufficient; you need to detect the *behavior*, not the install.
3. **Red infrastructure is shared and somewhat known.** National CCDC red team has used the same broad classes of tooling (Cobalt Strike, Sliver, Mythic, Havoc, custom Aggressor scripts, GRID-style distributed C2) for years. Known JA3/JA3S, JARM, and beacon-timing signatures are still surprisingly effective.

---

## 2. Threat Taxonomy: How Attackers Bypass Egress

I'll group techniques by *level of abuse* — from "just turn the firewall off" to "abuse a third-party SaaS API as a C2 transport." This ordering matters because your EDR's noisiest, highest-value detections live at the bottom of the stack (config tampering, process anomalies) and get progressively more analytics-heavy as you go up.

### 2.1. Layer 0 — Just Disable or Modify the Firewall (T1562.004)

The cheapest bypass. If the implant has admin/root, it doesn't need to be clever — it can just rewrite the rules. On Windows: `netsh advfirewall set allprofiles state off`, `New-NetFirewallRule -Action Allow`, or direct registry edits under `HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy`. On Linux: `iptables -F`, `ufw disable`, `firewall-cmd --set-default-zone=trusted`, or systemd unit overrides.

**Telemetry you want:**
- Sysmon Event ID 13 (registry value set) on the FirewallPolicy keys
- Process command-line audit (4688 with cmdline, Sysmon 1) for `netsh`, `New-NetFirewallRule`, `Set-NetFirewallProfile`, `iptables`, `ufw`, `firewall-cmd`, `nft`
- Linux: auditd watches on `/etc/iptables/`, `/etc/nftables.conf`, `/etc/firewalld/`, and on the binaries themselves
- Anything calling the Windows Firewall COM API (`HNetCfg.FwPolicy2`) from a non-Microsoft signed process

**EDR design note:** This is the lowest-hanging fruit and you should have a deterministic rule, not an ML model. Anything that flips the firewall off should page immediately and trigger automatic re-enable. The cost of a false positive is "we re-enabled the firewall." Acceptable.

### 2.2. Layer 1 — Riding Allowed Ports (T1071.001, T1573)

Egress rules almost always allow outbound TCP/443 and TCP/80 to *something* (Windows Update, package mirrors, CRL/OCSP, browsers). Modern C2 frameworks blend in here by default.

**The tooling:**
- **Cobalt Strike Beacon** — HTTP, HTTPS, DNS, SMB. Malleable C2 profiles let the operator forge user-agent strings, URI paths, and TLS cert metadata to mimic Amazon, Office 365, Cloudflare, etc.
- **Sliver, Mythic, Havoc, Brute Ratel** — open-source / commercial successors. Same idea, different malleability surface.
- **PoshC2** — PowerShell-based, default 5-second beacon with 20% jitter, which is a *huge* tell.
- **Realm / Imix** — what you ran for a red team comp; Rust beacon with configurable callback URIs over HTTPS.

**Why naive egress filtering fails:** A rule like "ALLOW outbound TCP/443" doesn't care whether the destination is `update.microsoft.com` or `198.51.100.42`. Even fully qualified allowlists fail against domain fronting (next section).

**Detection opportunities:**

- **JA3/JA3S fingerprinting.** JA3 hashes the TLS Client Hello (version, cipher suites, extensions, curves, formats); JA3S does the same for the server's Server Hello. Cobalt Strike's Beacon initiates TLS via the Windows socket — JA3 `72a589da586844d7f0818ce684948eea` (IP destination) and `a0e9f5d64349fb13191bc781f81f42e1` (domain destination) on Windows 10. PoshC2 has its own well-known JA3 hashes (`c12f54a3f91dc7bafd92cb59fe009a35` for PowerShell variant, `fc54e0d16d9764783542f0146a98b300` for Sharp). These are bypassable (custom HTTP stacks change the fingerprint) but on most CCDC red infra you'll see them out of the box. JA3 alone has false positives, but **rare JA3 + rare destination + beacon-like timing** is high-fidelity.
- **JARM** — server-side TLS fingerprint, useful for *outbound* threat hunting because you can pre-compute JARM hashes for known C2 framework default configs and alert on connections to those servers.
- **Beacon timing analysis.** Tools like [RITA](https://www.activecountermeasures.com/free-tools/rita/) score (src, dst, port) tuples on regularity of inter-connection interval and consistency of payload size. Cobalt Strike default 60s beacon with 0% jitter is trivially detected; even with 20–40% jitter, periodicity is statistically obvious over 10+ minutes. Your EDR should aggregate `tcp_connect` events per (process, dst_ip, dst_port) and compute coefficient of variation on the inter-arrival times.
- **Process-network correlation.** A `powershell.exe` or `wscript.exe` or `rundll32.exe` opening direct outbound HTTPS is almost always interesting. Browsers and updaters do this; LOLBins doing it warrants triage. Sysmon Event 3 + Event 1 join.
- **Certificate anomalies.** Self-signed certs, Let's Encrypt certs to numeric/random hostnames, certs valid for <30 days, mismatched SNI vs HTTP Host. The Darktrace example caught a red team using a typosquat domain (`companyname[.]com` vs the legit corporate one) with a Let's Encrypt cert.

### 2.3. Layer 2 — Domain Fronting and Trusted-SaaS C2 (T1090.004, T1102)

When the firewall allows `*.cloudfront.net`, `*.azureedge.net`, `*.googleapis.com`, or any other CDN, the attacker can put C2 infrastructure behind that CDN. The TLS SNI shows the legitimate fronted domain; the inner HTTP Host header routes to the malicious origin. This used to be widespread; Cloudflare/AWS/Azure have tightened it, but it still works on misconfigured edges and some smaller CDNs.

More common in 2025–2026: **abuse of legitimate SaaS APIs as the C2 channel**. The "Beyond DNS Next-Gen Covert C2" repo lays this out: encoded commands in Slack status updates, GitHub gists/issues/commits, Discord webhooks, Trello cards, Notion blocks, Telegram bots, Ethereum transactions. The traffic is *real* TLS to *real* SaaS, with valid certs and legitimate JA3S — there's nothing wire-level to flag.

**Detection opportunities:**
- TLS inspection at the perimeter (Suricata + cert), if your environment allows it. In CCDC you typically can.
- **Rare destination + beaconing + unusual JA3** combined model — Darktrace's approach. The strength is the *combination*; no single indicator is enough.
- For SaaS abuse: process telemetry is your only real angle. Why is `excel.exe` talking to `api.telegram.org`? Why is `svchost.exe` talking to `gist.githubusercontent.com`? Build an allowlist of (process, destination-domain) tuples for known-legitimate use and alert on novel pairs.
- DNS-level: monitor for resolution of CDN domains where the *first* lookup happens from a host that has no business hitting that CDN (e.g., a domain controller resolving `d3rnpoy7hrxh.cloudfront.net`).

### 2.4. Layer 3 — Protocol Tunneling: DNS, ICMP, NTP, SMTP (T1071.004, T1095, T1048)

When TCP/443 is locked down or inspected, attackers pivot to protocols defenders rarely block outright.

**DNS tunneling** (iodine, dnscat2, sliver-dns, Cobalt Strike DNS Beacon): commands and exfil are encoded into subdomain labels of queries to an attacker-controlled authoritative server. Even airgapped-ish networks usually allow DNS to *some* recursive resolver. Vercara/DigiCert notes T1071.004 has 45+ documented tools and malware families using it. Anchor / BazarLoader use it operationally.

**ICMP tunneling** (icmpsh, ptunnel, icmptunnel, icmpdoor, Hans): TCP encapsulated in ICMP echo request/reply payloads. Bypasses any firewall that allows outbound ping. icmpdoor specifically has been used to bypass older Windows Defender and basic egress controls in competition settings.

**Less common but real:** NTP mode 7 abuse, SMTP body steganography, BitTorrent DHT, custom UDP protocols.

**Detection opportunities for DNS:**
- **Shannon entropy on the QNAME's leftmost labels.** Base32/Base64-encoded payloads have ~5 bits of entropy per character; normal domain labels (`mail.example.com`, `cdn.cloudflare.com`) sit much lower. Threshold around 3.5–4.0 bits captures most tunneling without too many FPs.
- **Label length distribution.** Tunneled labels are usually 30–63 chars (max label size); legitimate hostnames are usually 3–15. Alert on sustained queries with labels >25 chars to a single second-level domain.
- **Query volume + rare RR types.** TXT, NULL, CNAME with long responses. Burst of 500+ TXT queries to a never-before-seen domain is a strong signal.
- **Unauthorized resolvers.** Endpoints querying `8.8.8.8`, `1.1.1.1`, or DoH endpoints (`cloudflare-dns.com`, `dns.google`) directly when policy is "internal resolver only" — often the *first* IoC.
- **Approach:** As Paolo Luise's Medium writeup describes, you can do this purely from DNS server query logs without endpoint telemetry — compute entropy per query, aggregate by second-level domain, surface the top-N entropy domains per day.

**Detection opportunities for ICMP:**
- **Packet size distribution.** Normal `ping` echo requests are 64 bytes (default Windows) or 84 bytes (default Linux). Tunneled ICMP carries TCP payloads inside the data section, so size distribution is highly variable and often >100 bytes. Cynet's writeup highlights this as the cleanest indicator: "varying datagram sizes may indicate that the connection is used for tunneling."
- **ICMP volume per host.** A workstation sending >100 ICMP echo requests/minute is almost never doing legitimate diagnostics.
- **Asymmetry.** Tunneling generates roughly equal counts of echo requests and replies in *both* directions. Real `ping` is unidirectional from the source.
- **Entropy on the ICMP data payload.** Same Shannon-entropy approach as DNS — encrypted tunnel data is high-entropy; the default Windows ping payload is the alphabet repeated.

### 2.5. Layer 4 — Pivoting and Tunneling Tools (T1572)

Once a foothold is established, attackers chain through it to reach segmented internal networks or to multiplex many internal services back out over a single egress channel.

**Modern toolkit:**
- **Chisel** — Go, HTTP-tunneled SSH, reverse SOCKS. The de-facto standard in CCDC and pentest engagements. Server on attacker box, client on victim, victim dials out over TCP/443.
- **Ligolo-ng** — TUN-interface based, faster than SOCKS for nmap and heavy scans, "VPN-like layer 3 tunnel."
- **reGeorg / Neo-reGeorg** — PHP/JSP/ASPX web shells that proxy arbitrary TCP through the compromised web server. Useful when only HTTP(S) inbound to a public web server is reachable.
- **rpivot** — reverse SOCKS over TCP.
- **SSH reverse port forwarding** (`ssh -R`) — if SSH is allowed outbound, you don't need anything fancy.
- **3proxy, Cntlm, OpenVPN-over-HTTP-proxy** — classic.

**Detection opportunities:**
- **Process telemetry on the binary.** Chisel, ligolo, frp, rathole, gost — these are not on a typical CCDC host. Anything spawning a long-lived outbound connection from an unsigned binary in `/tmp`, `C:\ProgramData\`, `C:\Users\Public\`, or a user's Downloads folder is alert-worthy.
- **Network flow shape.** SOCKS proxy traffic over a single TCP/443 connection has very different flow statistics from real HTTPS: extremely long-lived (hours), high bidirectional volume, no TLS session resumption pattern, no SNI variety. Zeek's `conn.log` + `ssl.log` joined on the connection ID gives you everything you need.
- **Suricata signatures.** ET Open has signatures for default Chisel banners, ligolo handshakes, and reGeorg URL patterns. They're trivially bypassable but the default configs trip them.
- **Process-network duration.** A 4-hour TCP connection from `notepad.exe` is anomalous; from a browser, not so much. Process-aware connection duration baselining is one of the highest-value EDR features for CCDC.

### 2.6. Layer 5 — Multi-Channel Resilience (CCDC-Specific)

This is where competition red team differs from typical APT. Per Alex Levinson's "Know Your Opponent" writeup, NCCDC red team uses **GRID** — a distributed C2 infrastructure spanning tens of thousands of IPs, so blue teams "never have direct contact" with the actual C2 servers, only with relay nodes. Beacons rotate through this pool.

Per Mudge's CCDC tips: Beacons are configured with multiple call-home IPs *and* multiple protocols, so blocking the HTTP listener just causes failover to DNS or SMB-named-pipe inter-host comms.

Per BluescreenofJeff's Pacific Rim writeup: red team automates persistence with Aggressor scripts that drop multiple, diverse persistence mechanisms simultaneously — kill one, two more are still alive.

**Implications for EDR:**
- Don't optimize purely for "find the C2 connection." Optimize for "find the implant on the host." Once you've identified the binary/process/scheduled task/service, you've killed all its channels regardless of which protocol it's currently using.
- Inter-host SMB pipe traffic (`\\.\pipe\status_<hex>`, `\\.\pipe\msagent_<hex>`) is a common Cobalt Strike inter-beacon channel. EDR should baseline named-pipe creation and alert on non-standard pipe names from processes that don't normally create pipes.
- Look for **multiple persistence mechanisms on the same host pointing to the same payload**. If you find a scheduled task, a Run key, and a WMI event subscription all launching `C:\ProgramData\update.exe`, that's a CCDC red team signature, not a real-world APT.

---

## 3. Putting It Together: An EDR Detection Stack for CCDC

Working from the noisy-bottom up, here's how I'd prioritize the detection logic if I were building this from scratch:

**Tier 1 — Deterministic, auto-response.** Fire instantly, block automatically, no analyst in the loop.
- Host firewall disabled or critical egress rule modified → re-enable, snapshot the responsible process.
- Unsigned binary from `C:\Users\*\AppData\Local\Temp\`, `C:\ProgramData\`, `/tmp`, `/dev/shm` initiating outbound network connection → kill + quarantine.
- Direct outbound DNS (UDP/53 or TCP/53) from any endpoint to a non-allowlisted resolver → drop + alert.
- Known-bad JA3 / JA3S hashes (Cobalt Strike, PoshC2, Sliver, Metasploit) → block destination IP, alert.
- LOLBins (`certutil`, `bitsadmin`, `mshta`, `regsvr32`, `rundll32`) with outbound network connection → kill.

**Tier 2 — High-fidelity correlation.** Fire within 1–5 minutes.
- Process X opens N outbound connections with inter-arrival CoV < 0.2 over 10+ minutes (RITA-style beaconing).
- DNS QNAME label entropy > 4.0 sustained over 50+ queries to one zone.
- ICMP echo requests with payload size > 100 bytes from non-admin workstation.
- Process with no parent (orphan) holding a long-lived outbound connection.
- Same payload hash launched from multiple persistence mechanisms.

**Tier 3 — Hunting / weak signals.** Surface to analyst for triage.
- Rare (process, dst_domain) pairs.
- Rare JA3 hashes for the environment.
- TLS to CDN with no preceding DNS lookup from the same host.
- Outbound connection to an IP with no rDNS / recently registered domain / Let's Encrypt cert valid <30 days.
- Named pipes with hex-suffixed names.

---

## 4. Telemetry You Need On Every Host

If you're authoring the EDR agent itself rather than ingesting Sysmon/auditd, you need to surface at minimum:

- Process creation with full command line, parent process, image hash, signer.
- Process termination.
- All TCP/UDP `connect()`, `bind()`, `listen()` with PID linkage.
- All DNS queries with PID linkage (this is the killer feature — Sysmon Event 22 gives you this but most EDRs hide it).
- All file creations in writable system directories.
- Registry value sets under autorun keys, services, firewall policy.
- Named pipe creation.
- Scheduled task / cron / systemd unit / WMI subscription creation.
- Loaded module events (DLL injection, manual map detection).
- All ICMP traffic with payload size and entropy (this is unusual but worth it for CCDC).

The process↔network linkage is the single highest-value capability, because it lets you write rules like *"any unsigned process making any outbound connection"* — a single rule that catches a huge fraction of tier-1 red team behavior.

---

## 5. CCDC-Tuned Heuristics That Don't Work in the Real World

Worth calling out: a few detections that are *great* for CCDC and would be way too noisy in production.

- **Alert on any unsigned binary doing network egress.** Real corp networks have tons of in-house unsigned tooling. CCDC environments don't — the default image is "factory" and any unsigned binary at all is suspicious.
- **Alert on direct-IP HTTPS (no DNS).** Real services do this (some CDN edges, some legitimate clients). In CCDC, almost nothing legit talks to a bare IP over 443.
- **Alert on Let's Encrypt + new domain combination.** Plenty of legit small sites use this. In CCDC, this is virtually always red team infrastructure.
- **Alert on any outbound from a domain controller.** DCs do talk outbound for some things (Windows Update, time sync), but the surface is narrow. In CCDC, lock this down hard and any deviation is an alert.

Use these aggressive defaults for the round, but keep a mental note that they wouldn't survive contact with a real enterprise.

---

## 6. ATT&CK Mapping Cheat Sheet

| Technique | ID | Primary observable | EDR priority |
|---|---|---|---|
| Disable/Modify System Firewall | T1562.004 | Process exec + registry/config write | Tier 1 |
| Application Layer Protocol: Web | T1071.001 | JA3, beacon timing, cert anomaly | Tier 2 |
| Application Layer Protocol: DNS | T1071.004 | QNAME entropy, rare RR types | Tier 2 |
| Non-Application Layer Protocol (ICMP) | T1095 | ICMP payload size/volume/entropy | Tier 1/2 |
| Protocol Tunneling | T1572 | Long-lived flow, process-network corr. | Tier 1 |
| Domain Fronting | T1090.004 | SNI/Host mismatch, rare CDN destinations | Tier 3 |
| Web Service C2 | T1102 | (process, SaaS-API) anomalies | Tier 3 |
| Encrypted Channel | T1573 | JARM/JA3S, weak entropy of "encrypted" stream | Tier 2 |
| Proxy: Multi-hop | T1090.003 | Multiple long-lived connections, SOCKS-pattern flows | Tier 2 |
| Exfiltration Over Alt Protocol | T1048 | Volume to non-standard destination | Tier 2 |

---

## 7. Further Reading

- Codelivly, *How Hackers Use Tunneling to Bypass Any Firewall* (2026) — practical tooling overview.
- UncleSp1d3r, *Firewall Bypass Techniques* — Chisel, Ligolo-ng, ACK floods, fragmented scans.
- Cobalt Strike blog, *CCDC Red Teams: Ten Tips to Maximize Success* (Raphael Mudge) — canonical CCDC red team perspective.
- Alex Levinson, *Know Your Opponent: My CCDC Toolbox* — NCCDC red team infra (DOOBY/GRID/WONKA).
- BluescreenofJeff / SpecterOps, *Red Teaming for Pacific Rim CCDC 2017*.
- The DFIR Report, *Cobalt Strike, a Defender's Guide — Part 2* — JA3/JA3S, JARM, RITA, malleable C2 detection.
- Salesforce Engineering, *TLS Fingerprinting with JA3 and JA3S* — original JA3 writeup with concrete Cobalt Strike / Meterpreter hashes.
- LRQA, *Detecting PoshC2 — Indicators of Compromise* — JA3, beacon timing analysis.
- Cyberdefenders, *DNS Tunneling Detection Techniques* (2026) — SOC-focused detection playbook.
- Cato Networks, *How to Detect DNS Tunneling in the Network* — entropy, popularity, beacon combination.
- Vercara/DigiCert, *DNS Data Exfiltration and DNS Tunneling* — T1071.004 ecosystem.
- Cynet, *How Hackers Use ICMP Tunneling to Own Your Network* — icmpsh, ptunnel, icmptunnel detection heuristics.
- LvL23HT, *Beyond DNS: Next-Gen Covert C2 Channels and Detection Techniques* (GitHub) — SaaS abuse, Slack/GitHub/blockchain C2.
- MITRE ATT&CK techniques referenced inline above (attack.mitre.org).
- Active Countermeasures, RITA — open-source beacon detection.
