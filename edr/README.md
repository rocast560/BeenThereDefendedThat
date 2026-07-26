# BTDT Lightweight EDR

A small, self-contained **detect-and-respond sensor** you drop onto every box at
the start of a CCDC-style round. It is the runnable, host-local distillation of
the [BeenThereDefendedThat design docs](../context/) — stripped to the handful of
techniques that are *proven*, *near-zero-false-positive*, and *impossible for an
implant to avoid*, and packaged so it needs **no central server, no agent
install, and no dependencies** beyond what ships with the OS.

- **Linux:** [`linux/btdt-edr.sh`](linux/btdt-edr.sh) + [`linux/btdt-edr.conf`](linux/btdt-edr.conf) — pure bash, uses `/proc`, `ss`, `iptables`.
- **Windows / AD:** [`windows/btdt-edr.ps1`](windows/btdt-edr.ps1) + [`windows/btdt-edr.config.psd1`](windows/btdt-edr.config.psd1) — PowerShell 5.1, uses `Get-NetTCPConnection`, `Get-WinEvent`, the AD module.

---

## Why this exists (and what it is *not*)

The full BTDT design in [`context/design/detection-tool-design.md`](../context/design/detection-tool-design.md)
is a proper agent-based EDR with a gRPC control plane, a message bus, and a
storage tier. **That architecture needs a trusted host to run on.** In this
scenario every machine is assumed pre-compromised and there is *no safe box to
host a control plane*, so the heavyweight design is out of scope. This kit is the
opposite trade: put the sensor **on each host, answering only to itself**.

It sits between two things that already exist:

| Layer | Tool | When | What |
|---|---|---|---|
| **T0 triage** | `Competition-Playbook/ccdc-audit/` (`linux-audit.sh`, `ad-audit.ps1`) | Run **once** at the start | ~76 point-in-time misconfig / persistence / backdoor checks, **read-only** |
| **Continuous watch** | **this kit** (`btdt-edr.sh`, `btdt-edr.ps1`) | Leave **running** all round | The high-signal "you are compromised *right now*" detections, on a loop, with **optional active response** |
| **Full EDR** | BTDT design (`context/design/…`) | Out of scope here | Needs a central host we don't have |

The auditor tells you how the box was left. This kit tells you what is happening
to it *now*, and can contain it. Run **both**.

---

## Threat model it is built for

Straight from the docs in [`context/`](../context/):

- **Pre-planted C2 beacons** — Cobalt Strike, Sliver, Meterpreter, Havoc, Mythic, Empire — already on the box at `t=0`, rotating call-home IPs and protocols.
- **Custom / signature-defeating implants** — raw-packet "sniff-shells" like [`watershell`](../context/samples/watershell/), port-piggyback C2, fileless/injected code, hidden-PID rootkits.
- **Basic pentest tooling against AD** — Mimikatz, Rubeus, Impacket (`secretsdump`/`psexec`/`wmiexec`), BloodHound/SharpHound, Kerberoasting, DCSync.
- **Linux intrusion** — reverse shells, dropped binaries in `/tmp`, cron/systemd/SSH-key persistence, `LD_PRELOAD` hooks.
- **The constraints:** many hosts, none trusted, an air-gapped LAN, minutes to deploy, and a scoring engine that **rotates its own source IPs** to punish IP-allowlisting.

The through-line — **you cannot signature a custom implant, so hunt the
*mechanism* it cannot avoid**: reading raw packets, running from memory, sharing a
port, hiding a PID, or calling home from an untrusted binary. Those survive
recompilation and obfuscation.

---

## What it detects

Every check is a near-zero-FP mechanism hunt or a diff against a T0 baseline.
`ALERT` = high-confidence compromise (drives the exit code and, in `kill`/`quarantine`
mode, auto-response); `WARN` = worth a human look.

### Linux (`btdt-edr.sh`)

| Check | Catches | Mechanism |
|---|---|---|
| `rawsock` | watershell / BPFdoor sniff-shells | non-allowlisted process holding an `AF_PACKET` socket (`/proc/net/packet` → PID) + promiscuous NIC |
| `memexec` | Meterpreter, in-memory beacons, self-deleting droppers | `/proc/*/exe` → `memfd:` or `(deleted)`; RWX anonymous maps (JIT-excluded) |
| `revshell` | interactive reverse shells | a shell whose stdin/stdout/stderr is a socket |
| `writable_exec` | dropped implants | process image under `/tmp`, `/dev/shm`, `/var/tmp` |
| `egress` | **any beacon, IP-rotation-proof** | outbound/​SYN-SENT to a public IP from a temp-path or non-package binary |
| `lolbin_egress` | scripted C2 | `nc`/`socat`/`python`/`perl`/`bash`… holding an outbound socket |
| `hidden_proc` | LKM/eBPF rootkits | `kill -0` succeeds but `/proc/<pid>` is absent; kernel taint; known rootkit module names |
| `preload` | userland hooks | `/etc/ld.so.preload` + `LD_PRELOAD` in live process environments |
| `nat_redirect` | port-piggyback C2 | `PREROUTING` `REDIRECT`/`DNAT` rules |
| `persistence` | new backdoors since T0 | sha256 diff of cron, systemd units, `authorized_keys`, `rc.local`, `ld.so.preload`, sudoers |
| `listeners` | bind shells / tunnel servers | listening ports not in the allowlist |
| `ebpf` | XDP/eBPF covert channels | `bpftool`/`ip`/`tc` enumeration vs T0 (advisory — legit users exist) |
| `firewall` | T1562.004 egress-freeing | default policy flipped open / ruleset flushed since T0 |

### Windows (`btdt-edr.ps1`)

| Check | Catches | Mechanism |
|---|---|---|
| `NamedPipes` | Cobalt Strike / Mythic | C2 pipe names (`msagent_*`, `postex_*`, `status_*`, `MSSE-*`, agent-UUID) — near-zero FP |
| `Egress` | any beacon, IP-rotation-proof | outbound to a public IP from an **unsigned** or temp-path binary |
| `LolbinEgress` | scripted C2 | `powershell`/`rundll32`/`regsvr32`/`mshta`/`certutil`… holding an outbound socket |
| `Listeners` | bind shells / pivots | listening ports not in the allowlist |
| `Persistence` | new backdoors since T0 | diff of scheduled tasks, Run keys, services, **WMI event subscriptions** |
| `Firewall` | T1562.004 | a firewall profile disabled |
| `PortProxy` | pivot / piggyback | any `netsh interface portproxy` rule |
| `IISModules` | memory-only web-shell | native IIS module loaded from outside the system dirs |
| `LogClear` | anti-forensics | Security **1102** / System **104** (event log cleared) |
| `DnsTunnel` | DNS C2 | long / high-entropy labels in the DNS client cache |

### Active Directory — Domain Controller (`btdt-edr.ps1`, auto-skips without the AD module)

| Check | Catches | Mechanism |
|---|---|---|
| `DCSync` | Mimikatz `dcsync` / `secretsdump` | Security **4662** carrying the directory-replication GUIDs from a non-DC principal |
| `Kerberoast` | Rubeus / `GetUserSPNs` | **4769** RC4 (`0x17`) service-ticket requests |
| `AsrepRoast` | AS-REP roasting | **4768** with pre-auth not required + accounts flagged `DONT_REQ_PREAUTH` |
| `PrivGroups` | privilege escalation | membership diff of Domain/Enterprise/Schema Admins etc. vs T0 (auto-reverts in `kill` mode) |

Provenance: the raw-socket/memexec/hidden-proc/eBPF hunts come from
[`context/runbooks/custom-implant-detection.md`](../context/runbooks/custom-implant-detection.md),
the implant/beacon and named-pipe logic from
[`context/runbooks/implant-detection.md`](../context/runbooks/implant-detection.md),
the egress/firewall/DNS material from
[`context/research/egress_bypass_edr_ccdc.md`](../context/research/egress_bypass_edr_ccdc.md),
and the AD detections + the fail-open scoring rule from
[`context/design/detection-tool-design.md`](../context/design/detection-tool-design.md).

---

## Quick start (per host)

**Linux** (as root):
```bash
./btdt-edr.sh --baseline          # 1. capture T0 state — do this FIRST, on a box you believe is clean-ish
./btdt-edr.sh --watch             # 2. leave it running (observe-only): alerts to console + JSONL
./btdt-edr.sh --watch --respond kill   # 3. once tuned, let it auto-contain high-confidence hits
```

**Windows / DC** (elevated PowerShell):
```powershell
.\btdt-edr.ps1 -Baseline
.\btdt-edr.ps1 -Watch
.\btdt-edr.ps1 -Watch -Respond kill
```

Useful flags (both): `--once`/`-Once` (single sweep, exit 1 if any alert — good
for a cron/scheduled fan-out), `--respond MODE`/`-Respond MODE`, `--dry-run`/`-DryRun`
(print what response *would* do), `--only`/`--skip` (a,b,c list of checks),
`--no-color`/`-NoColor`, `-c`/`-Config`, `-o`/`-OutFile`.

## Deploying across many machines (no central host)

Each sensor is one self-contained file + its config, answers only to itself, and
**never phones home** — which is the point when no box is trusted. Push and run:

```bash
# Linux fan-out (adjust host list / auth to your environment)
for h in web1 db1 mail1; do
  scp btdt-edr.sh btdt-edr.conf root@$h:/opt/btdt/ &&
  ssh root@$h 'cd /opt/btdt && ./btdt-edr.sh --baseline && setsid ./btdt-edr.sh --watch >/var/log/btdt.log 2>&1 &'
done
```
```powershell
# Windows fan-out over WinRM
foreach ($h in 'dc1','app1') {
  Copy-Item .\btdt-edr.ps1,.\btdt-edr.config.psd1 "\\$h\C$\ProgramData\btdt\"
  Invoke-Command -ComputerName $h { Set-Location C:\ProgramData\btdt; .\btdt-edr.ps1 -Baseline;
     Start-Process powershell '-File .\btdt-edr.ps1 -Watch' -WindowStyle Hidden }
}
```

Collect the local `alerts.jsonl` from each host on your own schedule (`scp`, a
share, or just read it in place). Because output is JSONL, you can `cat`/`jq`
them together into one view without any server:

```bash
jq -r 'select(.level=="ALERT") | "\(.ts) \(.host) \(.check) \(.msg)"' /var/lib/btdt-edr/alerts.jsonl
```

---

## Response & safety model

Responses are **off by default** and always gated twice:

1. **Mode** (`observe` → `quarantine` → `kill`). `observe` changes nothing on the host.
2. **Confidence.** Auto-response fires **only** on `high`-confidence (near-zero-FP)
   detections — a raw-socket shell, a `memfd`/deleted-binary process, a reverse
   shell, a C2 named pipe, a DCSync, a new privileged-group member. Everything
   softer only ever alerts, whatever the mode.

**Fail-open on scored services.** The scoring engine rotates its source IPs on
purpose, and service availability is ~half your score — so blocking the scorer
costs as much as the service being down. This kit **never drops inbound on a
scored port**: its responses are process-kill, egress-socket-sever, file
quarantine, firewall *re-enable* (from your saved baseline), account lock, and
privileged-group revert — all on the attacker/egress side. `SCORED_PORTS` /
`ScoredPorts` are additionally hard-fenced so no sever can touch a flow serving
them. Use `--dry-run` first to see exactly what would happen.

## Output

- **Console:** colored `[ALERT]/[WARN]/[OK]/[INFO]` lines with a UTC timestamp and the check name.
- **`alerts.jsonl`** in the state dir (`/var/lib/btdt-edr` · `C:\ProgramData\btdt-edr`): one JSON object per line (`ts`, `host`, `level`, `check`, `confidence`, `msg`) — the machine-readable stream the existing auditor lacks.
- **Exit code** (single-sweep mode): `0` clean, `1` at least one ALERT.

## Tuning (do this in the first 10 minutes)

The first run on each host **will** flag your own software — that is expected.
Read the alerts, and for the legitimate ones edit the config:
`ALLOWED_SNIFFERS`, `ALLOWED_JIT`, `ALLOWED_LISTEN_PORTS`, `LOLBIN_EGRESS`,
`INTERNAL_RESOLVERS` (Linux) and `AllowedListenPorts`, `PrivilegedGroups`,
`InternalResolvers` (Windows). Ten minutes of per-role tuning buys near-zero-FP
detection for the rest of the round. Toggle whole checks off with the
`DET_*` / `Checks` switches or `--skip`.

## Limitations (know these going in)

- **Snapshot polling, not kernel eventing.** A beacon that only lives between
  sweeps can be missed; tighten `WATCH_INTERVAL` on critical hosts. For real-time
  process/LSASS/injection telemetry, add **Sysmon** (one binary, no compile) — the
  runbooks list the exact event IDs.
- **`/proc` and `bpftool` can be lied to** by a kernel rootkit. That is why the
  hidden-PID check corroborates `kill -0` with kernel taint and known module
  names — treat any single rootkit signal as "investigate," not gospel.
- **In-memory beacons on Windows** (sleep-obfuscated Cobalt Strike/Havoc) need a
  memory scanner (`pe-sieve`/`hollows_hunter`) that this kit does not bundle.
- **PowerShell 5.1** is assumed (Windows Server default). Smoke-test on a member
  server before the round; AD checks light up only on a DC / RSAT host.
- This kit is deliberately **narrow**. For the broad misconfig/backdoor sweep,
  run `Competition-Playbook/ccdc-audit/` at T0 — it is the companion, not a competitor.

---

## Keeping the sensor alive (anti-tamper checklist)

You cannot make the process truly unkillable: a root / SYSTEM attacker can always
`kill -9`, unload a module, or delete files, and SIGKILL can't be trapped. The
goal is to make removing it **self-healing, costly, and loud** — so a kill undoes
itself, every attempt trips your own detections, and a *successful* kill is
instantly visible. The durable fix is still taking the attacker's privilege away
(rotate creds, kill sessions, patch the privesc) — which this sensor helps you do.
Implement top-down; the first two lists carry most of the value.

### 1. Self-healing — make a kill undo itself (do these first)
- [ ] **Buddy watchdog (highest-value single trick).** Two mutual-respawn loops that each relaunch the other the instant it dies, so a single kill is reversed in <1s and they must kill *both at once*:
      `while :; do pgrep -f 'btdt-edr.sh --watch' >/dev/null || setsid /opt/btdt/btdt-edr.sh --watch & sleep 1; done`
- [ ] **Linux systemd unit** with `Restart=always`, `RestartSec=1`, `StartLimitIntervalSec=0` (never give up), `OOMScoreAdjust=-1000` (OOM killer never targets it).
- [ ] **Linux cron fallback** so a `systemctl stop` isn't the end: `* * * * * root pgrep -f btdt-edr >/dev/null || /opt/btdt/btdt-edr.sh --watch &` plus an `@reboot` line.
- [ ] **Windows service auto-restart:** `sc.exe failure BTDTEDR reset= 0 actions= restart/1000/restart/1000/restart/1000` (recovery fires on crash/kill).
- [ ] **Windows scheduled-task fallback** at boot + every minute (covers a deliberate `sc stop`, which service recovery does not): `schtasks /create /tn BTDTwd /sc minute /mo 1 /ru SYSTEM /tr "..."`.
- [ ] **Run 2–3 diverse launchers** (service/systemd + task/cron + watchdog). Removing the sensor then means finding and killing *all* of them — and deleting any launcher trips the kit's own `persistence` check.

### 2. Friction — add steps and noise to any removal
- [ ] **Immutable files:** `chattr +i /opt/btdt/*` (Linux) — root must `chattr -i` first, an extra auditable step. Windows: `icacls` lock the files.
- [ ] **Windows service DACL:** `sc.exe sdset BTDTEDR "..."` denying Stop/Delete to Administrators while keeping full control for `SY` (SYSTEM). ⚠️ Test on a throwaway service first — a wrong SDDL can lock the service so even you can't manage it.
- [ ] **Ignore polite kills:** add `trap '' TERM INT HUP` in the script so `systemctl stop` / Ctrl-C are ignored and the attacker is forced up to a loud `kill -9`.
- [ ] **Non-obvious name/path** so `pkill -f btdt` misses it (`exec -a <innocuous>` / copy to a bland name) — but keep it discoverable to teammates; don't over-hide your own tool.

### 3. Tamper-evidence — make a *successful* kill visible (dead-man's switch)
- [ ] **Peer heartbeat.** Each sensor writes a timestamp every few seconds; a peer host alerts when a host goes quiet — *absence of data is the alarm*. No central host needed: hosts watch each other's `alerts.jsonl`.
- [ ] **Watch the stop itself:** Windows SCM event **7036** (`BTDTEDR entered the stopped state`); Linux `auditctl -w /opt/btdt -p wa -k btdt_tamper` to log any write/delete of the sensor's files.
- [ ] **Baseline persistence *after* installing the launchers** (or allowlist them) so your own service/task/cron entries don't self-alert on the `persistence` check.

### 4. The real stopper (heavy, mostly out of scope)
- [ ] A **kernel module or eBPF-LSM** that denies `kill`/`unlink` for the sensor even to root — the only thing that actually beats root. On Windows, tamper-proofing is **Protected Process Light (PPL)**, which needs a Microsoft-signed ELAM driver. Both are out of reach for a script kit; noted for completeness.

**Minimum worth shipping:** buddy watchdog + one OS-native supervisor (systemd/service) + a peer heartbeat. That alone means disabling your visibility takes a sustained, multi-step fight that generates the very alerts you're watching for.
