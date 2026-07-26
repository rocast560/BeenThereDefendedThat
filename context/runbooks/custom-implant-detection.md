# Custom & Pre-Planted Implant Detection — Advanced Runbook

**Audience:** Blue team hunting implants that defeat signature/JA3/YARA — custom
beacons, sniff-shells like [watershell/watershell.c](../samples/watershell/watershell.c),
port-piggyback C2, and fileless/injected code that is *already on the box at T0*.
**Companion to** [implant-detection.md](implant-detection.md) (which covers stock
tooling) and [egress_bypass_edr_ccdc.md](../research/egress_bypass_edr_ccdc.md) (egress).

Every technique below is **verified** (3-vote adversarial fact-check, deep-research
2026-07-21) and mapped to a concrete, runnable check in the
[ccdc-audit](../../../Competition-Playbook/ccdc-audit/) toolkit. The through-line: **you cannot
signature a custom implant, so hunt the *mechanism* it cannot avoid** — reading
raw packets, running from memory, sharing a port, hiding a PID, or executing an
untrusted binary.

> Core reframing: a signature answers "is this a *known* implant?" The checks here
> answer "is any process doing something only an implant does?" — which survives
> recompilation, obfuscation, and never-before-seen code.

---

## 1. Raw-packet "sniff-shell" implants (watershell / BPFdoor class)

**The mechanism.** These implants have **no listening port**. They open a raw
`AF_PACKET`/`SOCK_RAW` socket, attach a classic BPF filter (`setsockopt` /
`SO_ATTACH_FILTER`), and wait. A "magic packet" — to *any* port, open or closed —
matches the filter and triggers command execution (`system()` in watershell).
Because the sniffer taps frames **before netfilter**, this is **invisible to port
scans and unstoppable by the local firewall**. (Elastic Security Labs — BPFdoor RE;
Fortinet; Sandfly Security.)

**Why the BTDT stock rules aren't enough.** The 2025 BPFdoor variants narrowed
their BPF filter to look like normal traffic (one keeps *only UDP/53* as cover);
Rapid7 documented ~7 distinct 2025 variants. Hunting a specific filter/port misses
them — hunt the **generic behavior** instead.

**Detect (→ `CHECK_RAWSOCK`):**
- `/proc/net/packet` lists **every** `AF_PACKET` socket on the host. Map its inode
  (last column) back to the owning PID via `/proc/*/fd`. **Any process holding a
  packet socket that is not an allowlisted sniffer** (`dhclient`, `tcpdump`,
  `NetworkManager`, …) is the primary indicator. (Sandfly.)
- `ss -0pb` additionally shows the **attached BPF filter** — a packet socket *with
  a BPF program* is the classic sniff-shell fingerprint.
- Watershell v2/BPFdoor v2 use `AF_PACKET`+**`SOCK_DGRAM`** to dodge naïve
  `SOCK_RAW` checks — `/proc/net/packet` still lists them, so the inode approach
  catches both. The sniffing thread also shows up blocking in `/proc/<pid>/stack`
  (`packet_recvmsg`/`wait_for_more_packets`). (Sandfly, Fortinet.)
- Promiscuous interfaces (`ip link … PROMISC`) — watershell's `-p` mode and most
  sniffers.

**Prevent (→ `CHECK_SYSTEMD_SANDBOX`, `CHECK_CAPABILITIES`):**
- `RestrictAddressFamilies=~AF_PACKET` on a service makes `socket(AF_PACKET,…)`
  return `EAFNOSUPPORT` — a sniff-shell **cannot be built** inside that daemon.
  (Poettering, "Avoiding CVE-2016-8655 with systemd"; Debian ServiceSandboxing.)
- Drop `CAP_NET_RAW` from daemons that don't sniff. Raw-packet sockets require it.

---

## 2. Port piggybacking — hiding on an already-used port

**The mechanism.** BPFdoor forwards attacker traffic from a **legitimate service
port** (nginx/sshd/443) to its own high listening socket via
`iptables -t nat -A PREROUTING … -j REDIRECT --to-ports <implant>`. Linux stateful
**conntrack keeps the flow alive even after the rule is removed**, so no traffic
is ever visibly addressed to the implant's port — this defeats flow/connection
mapping. (Elastic Security Labs, primary RE.) The Windows analog is
`netsh interface portproxy`.

**Detect (→ `CHECK_NAT_REDIRECT` Linux, `PortProxy` Windows):**
- `iptables -t nat -S PREROUTING` / `nft list ruleset` → flag any
  `REDIRECT`/`DNAT`. A redirect from a scored port to a high port is the tell.
- Windows: `netsh interface portproxy show all` → any rule is suspect.
- Nuance: `ss`/`netstat` **still shows the implant's high listening port while it
  runs** — so cross-reference "unexpected high listener" (`CHECK_LISTENERS`) with
  "PREROUTING redirect exists." Together they're decisive.

---

## 3. Custom eBPF / XDP covert channels

**The mechanism.** A kernel-loaded eBPF/XDP program runs at the **NIC driver layer,
before netfilter**, so it bypasses iptables entirely and does **not** appear in
`/proc/net/packet` (that only lists userland `AF_PACKET` sockets). It must be
hunted at the program layer. (windshock eBPF backdoor detection framework;
corroborated by Elastic's "BPF Program or Map Load via bpftool" rule, Synacktiv
LinkPro/XDP magic-packet analysis.)

**Detect (→ `CHECK_EBPF`):**
- `bpftool prog show` / `map show` / `link show`; inspect `/sys/fs/bpf` for pinned
  persistence. **Kprobe/tracepoint/LSM/fentry program types can hook syscalls** —
  those are the dangerous ones.
- `ip link show` (XDP attached per interface) and `tc filter show dev …` (TC BPF).
- **False-positive discipline:** Falco, Cilium, Tetragon and modern systemd load
  legitimate eBPF. This is a *confirm-each* check, not an auto-FAIL. Baseline the
  expected set at T0 and alert on additions.
- **Evasion limit:** an advanced eBPF rootkit can hook `sys_bpf` to hide itself
  from `bpftool` — pair with the ground-truth cross-checks in §5.

---

## 4. Fileless & injected code (in-memory beacons)

**The mechanism.** Custom beacons never touch disk: they run from `memfd`,
self-delete their dropper, or inject into a running process, leaving
**unbacked/private executable memory** (RWX on Linux; private+execute, non-image
on Windows). Meterpreter's reflective loader "leaves large RWX memory sections
even when the session is closed." (Elastic Security Labs — Hunting In Memory.)

**Detect — Linux (→ `CHECK_MEMEXEC`, `CHECK_PRELOAD_HOOK`, `CHECK_PTRACE`):**
- `/proc/<pid>/exe` ending in `(deleted)` or pointing at `memfd:` → self-deleting
  / fileless implant. High signal.
- `/proc/<pid>/maps` with an **`rwx` anonymous** region (no backing file) →
  reflective/injected code.
- `LD_PRELOAD` in a live process's `/proc/<pid>/environ` → userland hook of a
  running (often network-facing) daemon. Also `/etc/ld.so.preload`
  (see `CHECK_PERSISTENCE`).
- `/proc/<pid>/status` `TracerPid != 0` with a non-debugger tracer → live ptrace
  injection. Harden with `kernel.yama.ptrace_scope=1`.

**Detect — Windows (→ `MemoryScan`, `NamedPipes`):**
- Signature-independent memory scanners are the reliable catch:
  **pe-sieve** and **hollows_hunter** (hasherezade) detect Process Hollowing,
  Doppelgänging, Reflective DLL Injection, inline hooks, and unbacked executable
  memory system-wide. `hollows_hunter /loop` = continuous; `/etw` (64-bit) =
  ETW-triggered real-time. **Threads whose start address is unbacked+executable**
  = injected shellcode (Get-InjectedThread-style). Modern loaders evade RWX
  detection by allocating RW then flipping to RX — combine with ETW/Sysmon.
- Named-pipe IOCs: Cobalt Strike (`msagent_##`, `postex_####`, `status_##`,
  `MSSE-####`) and Mythic **agent-UUID pipes** are near-zero-FP; long hex pipe
  names are suspect. (WithSecure.)

---

## 5. Hidden processes & rootkits (LKM / eBPF)

**The mechanism.** LKM stealth rootkits (Diamorphine, Reptile) **hide but don't
remove** a process — it still responds to direct syscalls the rootkit forgot to
hook. eBPF rootkits hook `getdents64` to hide `/proc` entries.

**Detect (→ `CHECK_HIDDEN_PROC`):**
- **PID-space decloak:** brute-force `kill(pid,0)` across the PID range; a PID the
  kernel keeps alive but that is **absent from `/proc`** is hidden. (Sandfly
  processdecloak — a standalone binary immune to `LD_PRELOAD` tampering.)
- **Kernel taint:** `/proc/sys/kernel/tainted != 0` — out-of-tree/unsigned modules
  (LKM rootkits) taint the kernel and "frequently overlook hiding all evidence of
  taint." (Sandfly.)
- Known rootkit module names in `lsmod`.
- **Cross-layer (advanced):** compare `/proc` traversal against a `bpftrace`
  kprobe on `sys_getpid` — the kprobe bypasses `getdents64` hooks, exposing eBPF
  hiders. (systemshardening.com.)
- **Evasion limit:** `/proc`-based scripts assume `/proc` is not subverted; a
  kernel rootkit can lie. The `kill(pid,0)` ground-truth probe and taint check are
  the hedge.

---

## 6. Windows IIS-module backdoors

**The mechanism.** A malicious **native IIS module** is a memory-only backdoor on
`w3wp.exe` that registers `BeginRequest`/`EndRequest`/`Error` handlers to
proxy/intercept HTTP — **no on-disk web-shell footprint**. Production servers
rarely add modules, so installs are high-signal. (Microsoft Security.)

**Detect (→ `IISModules`):**
- Enumerate modules (`appcmd list modules` / `Get-WebGlobalModule`); flag native
  DLLs loaded from outside `System32\inetsrv\` and the .NET dirs.
- Enable and watch **`Microsoft-IIS-Configuration/Operational`**: **Event ID 29**
  (module add at `/system.webServer/modules/add`) and **Event ID 50** (config
  change). Enable with `wevtutil sl Microsoft-IIS-Configuration/Operational /e:true`.

---

## 7. Prevention — make command execution & shells hard even for an on-box foothold

**Execution control (→ `CHECK_EXEC_HARDENING`):**
- **`noexec`** on `/tmp`, `/var/tmp`, `/dev/shm`, `/run/shm` — dropped implants and
  reverse-shell binaries can't execute from the writable dirs attackers use.
- **fapolicyd** (RHEL/Fedora) — default-deny execution trusting only files in the
  RPM database. `cp /bin/ls /tmp; /tmp/ls` → *Operation not permitted*. Config
  under `/etc/fapolicyd/` (`trust.d/`, `rules.d/` → `compiled.rules` via
  `fagenrules`; numeric-prefix ordering: `90` deny-execute, `95` allow-open).
  (Red Hat.) Windows analogs: **WDAC / AppLocker**.

**Service sandboxing (→ `CHECK_SYSTEMD_SANDBOX`):** for each network daemon, set —
- `RestrictAddressFamilies=~AF_PACKET` (kills sniff-shells in that service),
- `SystemCallFilter=~@module ~@raw-io ~@privileged ~@debug` (blocks
  `init_module`/`delete_module`, `ptrace`, `perf_event_open`) with
  `SystemCallArchitectures=native` (no 32-bit ABI bypass),
- `NoNewPrivileges=yes`, `ProtectSystem=strict`, `PrivateTmp=yes`.
- Caveats: `RestrictAddressFamilies` only affects the `socket()` call, not inherited
  or socket-activated fds; the syscall groups above don't block `execve` (add an
  explicit `execve` deny or a `@system-service` allowlist). Pair with dropping
  `CAP_NET_RAW`.
- **Injection hardening:** `kernel.yama.ptrace_scope=1` (→ `CHECK_PTRACE`) so one
  process can't ptrace another.

---

## 8. What each finding maps to (quick index)

| Threat | Linux check | Windows check |
|---|---|---|
| Sniff-shell / watershell / BPFdoor | `CHECK_RAWSOCK` | — (raw-socket sniffers are a Linux vector) |
| Port piggyback (NAT redirect / portproxy) | `CHECK_NAT_REDIRECT` | `PortProxy` |
| eBPF/XDP covert channel | `CHECK_EBPF` | — |
| Fileless / deleted-exe / RWX memory | `CHECK_MEMEXEC` | `MemoryScan` |
| Library-injection hook | `CHECK_PRELOAD_HOOK` | (Sysmon EID 7 image-load) |
| Live ptrace injection | `CHECK_PTRACE` | (Sysmon EID 8/10) |
| Hidden PID / rootkit | `CHECK_HIDDEN_PROC` | — |
| Named-pipe C2 | (SMB pipe on Linux via Samba) | `NamedPipes` |
| IIS-module backdoor | — | `IISModules` |
| Execution control | `CHECK_EXEC_HARDENING` | (WDAC/AppLocker — manual) |
| Daemon sandboxing | `CHECK_SYSTEMD_SANDBOX` | (service ACL — `Check-Services`) |

---

## 9. Honest limits (do not over-trust)

- **`/proc`-based scripts assume `/proc` is truthful.** A kernel-level rootkit can
  subvert them — combine with `kill(pid,0)` ground truth, kernel-taint, and (ideal)
  a Sandfly-style agent that probes via direct syscalls.
- **RWX-memory detection is evadable** by RW→RX flipping (modern loaders) — pair
  with ETW-TI/Sysmon EID 8/10/25 and continuous `hollows_hunter /loop /etw`.
- **eBPF enumeration can be blinded** by a `sys_bpf`-hooking rootkit.
- **BPFdoor is a moving target** (~7 variants in 2025) — always hunt the generic
  mechanism (non-allowlisted process with an `AF_PACKET`+BPF socket), never one
  fixed port/filter.
- These are **point-in-time host checks**, not a live EDR. Run them at T0 to
  baseline, then on the 30–60 min sustain loop; a beacon that is sleeping between
  callbacks is caught by the memory/socket state, not by network timing.

---

## 10. Sources (verified)

- Elastic Security Labs — *A Peek Behind the BPFDoor* (port-piggyback RE) · *Hunting In Memory* (unbacked executable memory).
- Fortinet — *New eBPF Filters for Symbiote and BPFDoor* (SO_ATTACH_FILTER, SOCK_DGRAM v2, UDP/53 cover).
- Sandfly Security — *BPFDoor Detection & Hunting on Linux*, *Detecting Packet Sniffing Malware*, LKM taint/decloak; `sandfly-processdecloak`.
- Microsoft Security — *IIS Modules: the Evolution of Web Shells* (EID 29/50).
- hasherezade — `pe-sieve`, `hollows_hunter` (`/loop`, `/etw`).
- Red Hat — *Blocking and Allowing Applications Using fapolicyd*.
- systemd — Poettering, *Avoiding CVE-2016-8655 with systemd*; Debian *ServiceSandboxing*; ageis systemd-hardening gist.
- windshock — *eBPF Backdoor Detection Framework* (bpftool/XDP/TC enumeration).
