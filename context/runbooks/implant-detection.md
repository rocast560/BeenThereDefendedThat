# Implant Binary Detection: Design & Runbook

**Audience:** Blue team engineers building the on-host detection layer of [BeenThereDefendedThat](../design/detection-tool-design.md) for CCDC-style competitions.
**Goal:** Detect and stop implant binaries (Sliver, Meterpreter, Havoc, Mythic agents, Cobalt Strike beacons, custom droppers, sniff-shells like [watershell/watershell.c](../samples/watershell/watershell.c)) using the same primitives commercial EDRs use, distilled to what we can ship on an air-gapped LAN in minutes.

This document is the binary-side companion to [egress_bypass_edr_ccdc.md](../research/egress_bypass_edr_ccdc.md). Egress detection asks *"is this host calling home?"* — implant detection asks *"is this binary an implant in the first place?"*

> **See also [custom-implant-detection.md](custom-implant-detection.md)** — the advanced runbook for implants that defeat signatures/JA3/YARA: raw-packet sniff-shells (watershell/BPFdoor), port-piggyback C2, eBPF/XDP covert channels, fileless/injected code, hidden-PID rootkits, and the on-box hardening that blocks command execution. Every technique there is verified (adversarial fact-check, 2026-07-21) and wired to a runnable check in the [`ccdc-audit`](../../../Competition-Playbook/ccdc-audit/) toolkit (`CHECK_RAWSOCK`, `CHECK_MEMEXEC`, `CHECK_EBPF`, `CHECK_HIDDEN_PROC`, `NamedPipes`, `IISModules`, …).

---

## 1. How Commercial EDRs Detect Implants

We are not building Falcon. We *are* copying the parts of Falcon and SentinelOne that work for our threat model. Below is what they actually do, distilled from vendor and third-party writeups (sources at the end).

### 1.1 CrowdStrike Falcon

Falcon's pipeline has four layers that fire in roughly this order:

1. **Sensor-level event collection.** A kernel module (Linux) / minifilter + ETW consumer (Windows) emits ~1000+ event types: `execve`, `clone`, `mmap`/`mprotect`, `connect`, `dns_query`, file opens, registry writes, image loads, named-pipe IPC. The unit of detection is the *event stream*, not the file.
2. **Pre-execution ML (NGAV).** A static ML classifier scores the binary on disk before `execve` completes. Features: PE/ELF header anomalies, imported function profile, section entropy, signature/cert status, packer fingerprints, string sets. This is the layer that catches stock Sliver/Havoc/Meterpreter shellcode loaders before they run.
3. **Indicators of Attack (IOAs).** Behavioral correlations expressed as *patterns of behavior over a process tree* — e.g., "`winword.exe` → `powershell.exe -enc` → `rundll32.exe` with no DLL on disk → outbound TLS." IOAs are graph queries over the event stream, mapped to MITRE ATT&CK techniques. They fire on the *intent* of the action, not its specific signature, which is what makes them resistant to repacking.
4. **Memory scanning.** Periodic memory sweeps with YARA-style rules to catch in-memory beacons (Cobalt Strike sleep masks, reflective loaders) that never touched disk.

The architectural lesson: **identity = process lineage + image + behavior**, not just the file hash.

### 1.2 SentinelOne

Two cooperating engines plus a graph layer:

1. **Static AI Engine.** Supervised ML model trained on ~1B samples, runs pre-execution on every file write/exec. Outputs a maliciousness confidence score; high-confidence verdicts kill before `execve` returns.
2. **Behavioral AI Engine.** Watches kernel process events in real time after execution starts. Flags: RWX allocations, reflective code regions (executable pages with no backing file), thread injection patterns, suspicious child-process chains.
3. **Storyline.** Every process gets a `Storyline ID` (a UUID). All descendant processes, file writes, network connections, and registry changes get tagged with the same ID. This is how SentinelOne "groups" an attack — when one node in the tree is verdicted malicious, every event sharing the Storyline becomes part of the same incident and can be killed/rolled back as a unit.

The architectural lesson: **track the whole tree, not the leaf**. A `bash` is fine; a `bash` whose Storyline includes "wrote ELF to `/tmp`, set +x, ran it, opened raw socket" is not.

### 1.3 Common thread across both vendors

| Layer | Falcon term | SentinelOne term | What it actually does |
|---|---|---|---|
| Static, pre-exec | NGAV ML | Static AI Engine | Score file features before run |
| Runtime behavioral | IOA | Behavioral AI Engine | Watch syscall / API patterns |
| Correlation | Process Tree | Storyline | Tie events to a tree, kill the tree |
| Memory | Memory scanning | In-memory module scan | Catch fileless / reflective beacons |
| Response | Real-time response | Active EDR / Rollback | Kill, quarantine, isolate, revert |

We replicate all five layers in a slimmed-down form.

---

## 2. Detection Signals Our Tool Will Use

A CCDC implant binary almost always exhibits at least three of the following. Any single signal is noisy; the **conjunction** is the detection.

### 2.1 Static (pre-execution) signals
- ELF/PE written to a *non-package-managed* path: `/tmp`, `/var/tmp`, `/dev/shm`, `/home/*/.cache`, `C:\Users\*\AppData\Local\Temp`, `C:\ProgramData`.
- File written then `chmod +x` (Linux) or marked executable then immediately spawned (Windows).
- No code-signing cert, or cert that doesn't chain to a trusted issuer.
- Section entropy > 7.2 (packed) on `.text`, or UPX/Themida/VMProtect markers.
- Suspicious imports: `ptrace`, `mprotect` w/ PROT_EXEC, `memfd_create`, `process_vm_writev`, `NtMapViewOfSection`, `VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread`, `SetThreadContext`.
- Embedded high-entropy blobs (likely shellcode / encrypted config).
- ELF written with `AF_PACKET` / `SOCK_RAW` strings *and* an embedded BPF filter constant (the WaterShell fingerprint).

### 2.2 Runtime behavioral signals
- `execve` of a binary from a writable, non-package-managed path.
- Parent-child anomaly: `sshd` → `sh` → `curl | sh` → ELF, or `services.exe` → `cmd.exe` → `powershell -enc`.
- `mmap`/`mprotect` requesting RWX, or W→X transition on an anonymous mapping (reflective loading).
- `memfd_create` followed by `execveat` (Linux fileless execution).
- Raw socket creation (`socket(AF_PACKET, SOCK_RAW, …)`) by a process not on the allowlist (`dhclient`, `tcpdump`, container runtimes).
- Promiscuous mode enabled on any interface (`ip link` `PROMISC` flag transition).
- Long-running process holding `CAP_NET_RAW` or `CAP_SYS_PTRACE` with no listening port (sniff-shell pattern).
- Beacon-timing on outbound connections: jittered intervals (60s ± 20%) to the same destination.
- DNS queries with high entropy in the subdomain label (DNS C2).
- TLS ClientHello with rare JA3 from a non-browser binary.

### 2.3 Persistence-adjacent signals (often co-occurring)
- New file under `/etc/cron.*`, `/etc/systemd/system/`, `~/.config/systemd/user/`.
- Append to `~/.ssh/authorized_keys`, `~/.bashrc`, `/etc/ld.so.preload`.
- Windows: new `HKLM\…\Run` value, new scheduled task, new service.

A binary that hits **(2.1 path + 2.1 entropy or import) + (2.2 RWX or raw socket) + (2.3 any)** is an implant with very high confidence. Anything two-of-three goes to a quarantine queue for analyst review.

---

## 3. Detection Architecture (How the Agent Implements This)

The agent is a single Go binary per host. It mirrors the Falcon/SentinelOne layering at small scale.

```
+---------------------------------------------------------------+
|                       Per-host agent                          |
|                                                               |
|   +------------+    +-----------+    +-------------+          |
|   | Collectors |--->| Storyline |--->| Rule engine |--->kill  |
|   |  (eBPF/    |    |  tracker  |    | (Sigma-ish) |   /quar  |
|   |   ETW/     |    | (proc UUID|    |   + YARA    |   /sever |
|   |   Sysmon)  |    |  graph)   |    |   + ML opt) |          |
|   +------------+    +-----------+    +-------------+          |
|         |                  |                |                 |
|         v                  v                v                 |
|   +------------------------------------------------+          |
|   |   Local event ring (mmap'd, ~5 min retention)  |          |
|   +------------------------------------------------+          |
|                          |                                    |
|                          v   gRPC bidi, mTLS                  |
+---------------------------------------------------------------+
                           |
                           v
                  Central server (ingest + rules + response orchestrator)
```

**Storyline tracker** is the most important non-obvious piece. Every `execve`/`clone` gets a UUID; child processes inherit a `parent_storyline_id`. File writes, network connections, and module loads are tagged with the current process's Storyline. When the rule engine verdicts any node malicious, the response orchestrator kills *every live PID sharing that Storyline ID* and quarantines every file written under it.

---

## 4. Concrete Detection Rules

These are the rules the agent ships with on day one. They are intentionally narrow and high-fidelity; broad rules get tuned in after baselining.

### 4.1 Linux — eBPF / Falco-style

```yaml
- rule: Raw packet socket from unexpected binary
  desc: Detects WaterShell / packet-sniffer implants
  condition: >
    evt.type = socket and evt.arg.domain = AF_PACKET
    and evt.arg.type contains SOCK_RAW
    and not proc.name in (dhclient, tcpdump, wireshark, dumpcap,
                          nmap, arping, containerd, dockerd)
  output: "Raw packet socket opened (proc=%proc.name pid=%proc.pid
           ppid=%proc.ppid cmdline=%proc.cmdline)"
  priority: CRITICAL
  tags: [T1040, watershell, sniffer]

- rule: Promiscuous mode enabled
  condition: evt.type = ioctl and evt.arg.request = SIOCSIFFLAGS
             and evt.arg.flags contains IFF_PROMISC
  output: "Interface set to promiscuous (proc=%proc.name)"
  priority: HIGH

- rule: Fileless execution via memfd
  condition: evt.type = execveat and fd.name startswith "memfd:"
  output: "memfd execve (proc=%proc.name parent=%proc.pname)"
  priority: CRITICAL
  tags: [T1620, fileless]

- rule: ELF written to tmp then executed
  condition: >
    evt.type = execve
    and proc.exepath startswith "/tmp/" or proc.exepath startswith "/dev/shm/"
    or proc.exepath startswith "/var/tmp/"
  output: "Exec from world-writable path (path=%proc.exepath
           parent=%proc.pname cmdline=%proc.cmdline)"
  priority: HIGH

- rule: RWX anonymous mapping (reflective loader)
  condition: >
    evt.type = mmap and evt.arg.prot contains PROT_EXEC
    and evt.arg.prot contains PROT_WRITE
    and evt.arg.fd = -1
  output: "Anonymous RWX mmap (proc=%proc.name)"
  priority: HIGH

- rule: Shell spawned with redirected sockets (reverse shell)
  condition: >
    spawned_process and proc.name in (bash, sh, dash, zsh, ash)
    and fd.typechar = 4 and fd.is_server = false
    and proc.stdin.type = ipv4
  output: "Reverse shell pattern (proc=%proc.name peer=%fd.rip:%fd.rport)"
  priority: CRITICAL
```

### 4.2 Linux — auditd

```
# CAP_NET_RAW socket creation
-a always,exit -F arch=b64 -S socket -F a0=17 -k packet_socket

# memfd_create — fileless staging
-a always,exit -F arch=b64 -S memfd_create -k memfd

# Writes to persistence-critical paths
-w /etc/cron.d           -p wa -k persist_cron
-w /etc/cron.hourly      -p wa -k persist_cron
-w /etc/systemd/system   -p wa -k persist_systemd
-w /etc/ld.so.preload    -p wa -k persist_preload
-w /root/.ssh            -p wa -k persist_sshkeys

# Promisc flag change
-a always,exit -F arch=b64 -S ioctl -F a1=0x8914 -k ifflags
```

### 4.3 Linux — osquery (scheduled, 30s interval)

```sql
-- Processes holding AF_PACKET sockets, not on allowlist
SELECT p.pid, p.name, p.path, p.cmdline, u.username
FROM process_open_sockets s
JOIN processes p USING (pid)
JOIN users u ON p.uid = u.uid
WHERE s.family = 17                                  -- AF_PACKET
  AND p.name NOT IN ('dhclient','tcpdump','wireshark',
                     'dumpcap','NetworkManager','systemd-networkd');

-- Listening services that don't match any package-owned binary
SELECT l.pid, l.port, l.protocol, p.name, p.path, h.sha256
FROM listening_ports l
JOIN processes p USING (pid)
LEFT JOIN hash h ON h.path = p.path
WHERE p.path NOT LIKE '/usr/%' AND p.path NOT LIKE '/lib/%';

-- Recently modified binaries in user/temp dirs
SELECT path, mtime, size, sha256
FROM file
WHERE (path LIKE '/tmp/%' OR path LIKE '/dev/shm/%'
       OR path LIKE '/var/tmp/%' OR path LIKE '/home/%/.cache/%')
  AND mode LIKE '%x%'
  AND mtime > (SELECT unix_time FROM time) - 3600;

-- Promisc interfaces
SELECT interface, flags FROM interface_details
WHERE flags LIKE '%PROMISC%';
```

### 4.4 Windows — Sysmon + ETW (rule IDs from MS-recommended config)

- **Event 1** (process create) where ParentImage is `winword.exe`/`outlook.exe`/`excel.exe` and Image is `powershell.exe`/`cmd.exe`/`wscript.exe`.
- **Event 8** (CreateRemoteThread) into `lsass.exe`, `explorer.exe`, `svchost.exe` from a non-system process.
- **Event 10** (ProcessAccess) requesting `0x1010` or `0x1410` (PROCESS_VM_READ | PROCESS_VM_WRITE) on `lsass.exe`.
- **Event 11** (FileCreate) of `.exe`/`.dll` in `%TEMP%`, `%APPDATA%`, `C:\ProgramData\`.
- **Event 22** (DNSEvent) where QueryName matches `^[a-f0-9]{16,}\.` (high-entropy subdomain).
- **Event 25** (ProcessTampering) — covers process hollowing.

ETW-TI providers we additionally subscribe to: `Microsoft-Windows-Threat-Intelligence` for `AllocateVirtualMemoryRemote`, `ProtectVirtualMemoryRemote`, `MapViewOfSectionRemote`, `ReadVirtualMemoryApiCall`.

### 4.5 YARA — static rules for binary scans

```yara
rule Watershell_Stock_Build
{
    meta:
        author = "BTDT"
        family = "watershell"
    strings:
        $bpf_port = { 15 0? 0? 00 00 30 39 }   // BPF k=12345 (default port)
        $cap1 = "SO_ATTACH_FILTER"
        $cap2 = "PF_PACKET"
        $promisc = "IFF_PROMISC"
        $run = "run:"
    condition:
        uint32(0) == 0x464C457F and 3 of them
}

rule Generic_Reflective_Loader_Linux
{
    strings:
        $s1 = "mprotect"
        $s2 = "memfd_create"
        $s3 = "ld-linux"
        $rwx_const = { 07 00 00 00 }            // PROT_READ|WRITE|EXEC
    condition:
        uint32(0) == 0x464C457F and all of them
}

rule Sliver_Default_Strings
{
    strings:
        $a = "github.com/bishopfox/sliver"
        $b = "sliverpb"
        $c = "{{.Hostname}}"
        $d = "registerExtension"
    condition:
        uint32(0) == 0x464C457F and 2 of them
}
```

YARA runs in three modes:
1. **At ingest** — every new file under `/tmp`, `/var/tmp`, `/dev/shm`, `%TEMP%` gets scanned within 2s of close.
2. **On exec** — scan the image before the rule engine emits a verdict.
3. **Memory sweep** — every 60s, scan RWX regions of every process. This is what catches in-memory Cobalt Strike beacons.

---

## 5. Stopping Implants: Active Response

Detection without response is a logbook. The agent supports four response tiers, gated by verdict confidence.

| Verdict | Triggered by | Action |
|---|---|---|
| `observe` | Single low-confidence signal | Log only, raise score on the Storyline |
| `quarantine` | Two correlated signals | `SIGSTOP` process, move binary to `/var/quarantine/`, drop ACL to root-only |
| `kill` | One high-confidence rule (e.g., raw-socket-from-non-allowlist, memfd execve, YARA hit) | `SIGKILL` every PID in the Storyline; remove file; sever any sockets via `ss -K` (Linux) / `Stop-NetTCPConnection` (Windows) |
| `isolate` | Multiple kill-grade verdicts in 60s, or rule engine says "C2 confirmed" | Host network isolation: keep agent gRPC channel open, drop everything else via nftables/WFP; trigger Ansible playbook to rotate creds, snapshot `/etc`, re-baseline cron/systemd |

Two design rules borrowed from SentinelOne:

- **Kill the tree, not the leaf.** When a verdict fires, every process sharing the Storyline UUID dies in one transaction. This stops watcher/restarter loops cold.
- **Rollback what you can.** Any file write tagged with a malicious Storyline is reverted from the T0 snapshot. Cron entries, systemd units, `authorized_keys` appends, `/etc/ld.so.preload` — all auto-revert.

The watershell-specific stop sequence:
1. Rule `Raw packet socket from unexpected binary` fires.
2. Storyline UUID resolved; PID + parent PID + image path captured.
3. `SIGKILL` the PID. Watershell forks-and-exits at startup, so the daemon PID is the *only* live one — no orphans.
4. YARA scan the image; if `Watershell_Stock_Build` hits, hash and quarantine.
5. If promisc was set by this PID, restore interface flags (`ip link set <iface> promisc off`).
6. Ansible playbook removes any cron/systemd persistence pointing at the quarantined hash.

---

## 6. What This Design Deliberately Does Not Do

- **No cloud ML training.** We use a small pre-trained gradient-boost model (optional) for fileless-loader scoring. The day-one detections are all rules-based, because rules are debuggable under time pressure and ML models are not.
- **No EPP-class file-system filter on Linux.** We hook via eBPF + auditd. Writing a kernel module mid-competition is a footgun.
- **No "AI-powered IOAs" branded layer.** Falcon's marketing aside, the underlying primitive is a graph rule over the event stream — which is exactly what the Storyline tracker enables. We get the same effect by writing good Sigma-style correlations.

---

## 7. Sources

EDR vendor and third-party detection writeups used to derive the above:

### CrowdStrike Falcon
- [Event Stream Processing & Indicators of Attack — CrowdStrike](https://www.crowdstrike.com/en-us/blog/understanding-indicators-attack-ioas-power-event-stream-processing-crowdstrike-falcon/)
- [What are Indicators of Attack (IOAs)? — CrowdStrike](https://www.crowdstrike.com/en-us/cybersecurity-101/threat-intelligence/indicators-of-attack-ioa/)
- [Falcon Prevent NGAV — CrowdStrike](https://www.crowdstrike.com/en-us/platform/endpoint-security/falcon-prevent-ngav/)
- [CrowdStrike Introduces AI-Powered Indicators of Attack — Business Wire](https://www.businesswire.com/news/home/20220810005192/en/CrowdStrike-Introduces-Industrys-First-AI-Powered-Indicators-of-Attack-for-CrowdStrike-Falcon-Platform-to-Uncover-the-Most-Advanced-Attacks)
- [CrowdStrike Detection Engineering Best Practices — Thinkcloudly](https://thinkcloudly.com/blog/cyber-security/crowdstrike-detection-engineering-best-practices/)

### SentinelOne
- [Decrypting SentinelOne's Detection: Static AI Engine](https://www.sentinelone.com/blog/decrypting-sentinelones-detection-an-in-depth-look-at-our-real-time-cwpp-static-ai-engine/)
- [Decrypting SentinelOne Detection: The Behavioral AI Engine](https://www.sentinelone.com/blog/decrypting-sentinelone-detection-the-behavioral-ai-engine-in-real-time-cwpp/)
- [Rapid Threat Hunting with Storylines — SentinelOne](https://www.sentinelone.com/blog/rapid-threat-hunting-with-deep-visibility-feature-spotlight/)
- [Machine Learning With a Little Magic on Top — SentinelOne](https://www.sentinelone.com/blog/machine-learning-little-magic-top/)
- [SentinelOne Agent: 2025 Deep Dive Guide — Solide](https://solideinfo.com/sentinel-one-agent-dfir-soc-guide-2026/)

### Linux detection primitives
- [Linux EDR Telemetry Analysis — edr-telemetry.com](https://www.edr-telemetry.com/linux)
- [Hunting for Persistence in Linux: Auditd, Sysmon, Osquery — pberba](https://pberba.github.io/security/2021/11/22/linux-threat-hunting-for-persistence-sysmon-auditd-webshell/)
- [Linux Detection Engineering: A Primer on Persistence — Elastic Security Labs](https://www.elastic.co/security-labs/primer-on-persistence-mechanisms)
- [Detect reverse shell with Falco and Sysdig Secure](https://www.sysdig.com/blog/reverse-shell-falco-sysdig-secure)
- [Tracing System Calls Using eBPF — Falco](https://falco.org/blog/tracing-syscalls-using-ebpf-part-1/)
- [Hunting Rootkits with eBPF: Detecting Syscall Hooking — Aqua](https://www.aquasec.com/blog/linux-syscall-hooking-using-tracee/)
- [eBPF: Block Linux Fileless Payload Execution — Djalal Harouni](https://djalal.opendz.org/post/ebpf-block-linux-fileless-payload-execution-with-bpf-lsm/)
- [Linux Reverse Shells with OSQuery — Medium](https://medium.com/@abhinahii/linux-reverse-shells-with-osquery-f5e0a2f2efd1)

### YARA & static analysis
- [Living off the Analyst: Harvesting Features from YARA Rules (arXiv:2411.18516)](https://arxiv.org/pdf/2411.18516)
- [YARA Rules: How to Detect Malware — Kraven Security](https://kravensecurity.com/yara-rules/)

### ICMP / sniff-shell background (watershell context)
- [wumb0/watershell — GitHub](https://github.com/wumb0/watershell)
- [ICMP Tunneling — A Pentester's Ramblings](https://sp00ks-git.github.io/posts/ICMP-Tunneling/)
- [What is ICMP Tunneling and How to Protect Against It — ExtraHop](https://www.extrahop.com/blog/detect-and-stop-icmp-tunneling)
- [packet(7) — man7.org](https://man7.org/linux/man-pages/man7/packet.7.html)
