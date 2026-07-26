# CCDC Audit Toolkit

Two **read-only** auditors that scan a competition box for misconfigurations and
persistence/backdoor indicators, print severity-tagged findings, and return a
non-zero exit code if anything critical is found. **Neither script changes the
system** — they only report. Use them to triage a box at drop flag and to
re-baseline every 30–60 minutes (the sustain loop in the main playbook).

| File | Runs on | Purpose |
|---|---|---|
| `linux-audit.sh` | Linux (bash 4+) | Users, sudo, SSH, listeners, cron, SUID, firewall, persistence, web shells |
| `linux-audit.conf` | — | Config for the Linux auditor (edit this) |
| `ad-audit.ps1` | Windows / DC (PowerShell 5.1+) | Local admins, AD privileged groups, krbtgt, Kerberoast/AS-REP, delegation, firewall, tasks, WMI/Run-key persistence |
| `ad-audit.config.psd1` | — | Config for the Windows/AD auditor (edit this) |

> These are **defensive** tools for your own authorized competition hosts. They
> read state only. Nothing here attacks anything.

---

## Severity legend (both tools)

| Tag | Meaning |
|---|---|
| `[FAIL]` | Almost certainly bad — fix now (backdoor account, empty password, SMBv1, open beacon path). Drives the exit code. |
| `[WARN]` | Suspicious or weak — verify (extra shell user, non-expiring password, recent account, outbound to a public IP). |
| `[PASS]` | Checked and healthy. |
| `[INFO]` | Context / manual-review pointer (lists tasks, timers, sessions). |

A run ends with `Summary: N FAIL  N WARN  N PASS  N INFO`. **Exit `0`** if no
FAILs, **`1`** if any FAIL (so you can wire it into a watch loop), **`2`** for a
usage error.

---

## 1. Linux — `linux-audit.sh`

### Setup
```bash
cd ccdc-audit
chmod +x linux-audit.sh
# EDIT the config to match this box before trusting the output:
nano linux-audit.conf          # set EXPECTED_ADMINS, ALLOWED_LISTEN_PORTS, WEB_ROOTS, etc.
```

### Run
```bash
sudo ./linux-audit.sh                       # full audit, default config in same dir
sudo ./linux-audit.sh -c /root/box.conf     # use a specific config
sudo ./linux-audit.sh -o /root/audit.txt    # also save a plain-text copy
sudo ./linux-audit.sh --no-color            # disable ANSI color (for logs/pipes)
```

Run as **root** — without it, `/etc/shadow`, some listeners, and other users'
`authorized_keys` can't be read and those checks degrade to `[INFO]`.

### Run only/skip specific checks
Check names are the `CHECK_*` toggles in the config:
```bash
sudo ./linux-audit.sh --only CHECK_SSH,CHECK_LISTENERS,CHECK_ADMINS
sudo ./linux-audit.sh --skip CHECK_SUID,CHECK_WEB
```

### Baseline & diff (catch changes over time)
Snapshot the box once it's clean, then diff on every re-check — new SUID
binaries, new listeners, or `/etc/passwd` edits jump out immediately.
```bash
sudo ./linux-audit.sh --snapshot     # saves SUID list, listeners, passwd, root cron to ./baseline
sudo ./linux-audit.sh --diff         # shows what changed since the snapshot
```

### Watch loop (re-audit every 5 min, alert on FAIL)
```bash
while true; do
  sudo ./linux-audit.sh --no-color -o /root/last-audit.txt >/dev/null
  [ $? -eq 1 ] && echo "$(date) FAIL detected — see /root/last-audit.txt"
  sleep 300
done
```

### What it checks
UID-0 backdoor accounts · empty password hashes · unexpected login shells ·
unexpected sudo/`wheel` members and `NOPASSWD` rules · `sshd_config` hardening ·
every user's `authorized_keys` · listening ports vs allowlist · established
outbound to public IPs (C2) · cron jobs + systemd timers (with reverse-shell
pattern matching) · running/enabled services + `nc`/`socat` processes ·
SUID/SGID (vs baseline) · world-writable system files · `ufw`/`iptables`
default-deny + egress posture · `ld.so.preload`/`rc.local`/shell-rc persistence ·
recently modified web files + code-exec markers · current sessions + auth
failures · `passwd`/`shadow`/`sudoers` modification times.

**Privilege-escalation vectors (added, mined from the offensive playbook):**
dangerous file **capabilities** (`getcap`: `cap_setuid`, `cap_dac_read_search`, …) ·
NFS **`no_root_squash`** exports (remote-root SUID drop) · **docker/lxd/disk/shadow**
group membership (root-equivalent) + exposed `docker.sock` · **kernel version** vs
Dirty Pipe (CVE-2022-0847) / Dirty COW ranges · **sudo version** vs CVE-2019-14287
and CVE-2021-3156 (Baron Samedit) · sudoers **`env_keep` LD_PRELOAD** / `SETENV` ·
world-writable **systemd unit files + `ExecStart` binaries** · extra **ACLs/symlinks**
on `passwd`/`shadow` · SSH **`TrustedUserCAKeys`** + `cert-authority` keys.

**Advanced implant hunt (added — custom / pre-planted / fileless C2; see the cited
runbook [`custom-implant-detection.md`](../../BeenThereDefendedThat/custom-implant-detection.md)):**
`CHECK_RAWSOCK` **AF_PACKET sniffer sockets** (`/proc/net/packet` → PID) + attached
BPF filter + promiscuous interfaces (**watershell / BPFdoor** class) ·
`CHECK_MEMEXEC` **deleted-exe / `memfd` / RWX-anonymous memory** (fileless & injected) ·
`CHECK_PRELOAD_HOOK` **`LD_PRELOAD` in live process environments** ·
`CHECK_EBPF` loaded **eBPF/XDP/TC programs** (kernel backdoor surface) ·
`CHECK_HIDDEN_PROC` **hidden-PID decloak** (`kill(pid,0)` vs `/proc`) + kernel taint ·
`CHECK_NAT_REDIRECT` **PREROUTING REDIRECT/DNAT** (port-piggyback C2) ·
`CHECK_PTRACE` live **ptrace** relationships + `yama ptrace_scope` ·
`CHECK_EXEC_HARDENING` **`noexec`** tmp dirs + **fapolicyd** ·
`CHECK_SYSTEMD_SANDBOX` network-daemon sandboxing (`RestrictAddressFamilies=~AF_PACKET`, etc.).

---

## 2. Windows / Active Directory — `ad-audit.ps1`

Run on each Windows host; the **domain** checks (privileged groups, krbtgt,
Kerberoast, delegation, etc.) only activate when the **ActiveDirectory module**
is present — i.e. on a Domain Controller, or a member with RSAT installed.
On a plain member/workstation the AD checks print `skipped (no AD module)` and
the local/host checks still run.

### Setup
Edit `ad-audit.config.psd1` first — especially `ExpectedPrivilegedMembers`,
`ExpectedLocalAdmins`, and `AllowedListenPorts`.

### Run (elevated PowerShell)
```powershell
# If scripts are blocked, launch a bypassed session (does not persist):
powershell -ExecutionPolicy Bypass -File .\ad-audit.ps1

# Normal use:
.\ad-audit.ps1
.\ad-audit.ps1 -ConfigPath .\ad-audit.config.psd1 -OutFile C:\audit.txt
.\ad-audit.ps1 -NoColor
```
**Run as Administrator** for firewall, service, WMI, and LSA checks.

### Run only/skip specific checks
Names are the keys under `Checks` in the config:
```powershell
.\ad-audit.ps1 -Only PrivilegedGroups,Krbtgt,Kerberoast,Firewall
.\ad-audit.ps1 -Skip WmiPersistence,Logging
```

### Watch loop (re-audit every 5 min)
```powershell
while ($true) {
  .\ad-audit.ps1 -NoColor -OutFile C:\last-audit.txt | Out-Null
  if ($LASTEXITCODE -eq 1) { Write-Host "$(Get-Date) FAIL detected — see C:\last-audit.txt" -Foreground Red }
  Start-Sleep -Seconds 300
}
```

### What it checks
**Local/host:** local Administrators membership · enabled local users + Guest ·
SMBv1 · Windows Firewall profiles (enabled + default in/out actions) · listening
ports vs allowlist · established outbound to public IPs (C2) · non-Microsoft
scheduled tasks · unquoted service paths + services running from user-writable
dirs · HKLM/HKCU Run keys · WMI event-subscription persistence · WDigest/RunAsPPL
credential protections · Sysmon/PowerShell-logging presence.
**Active Directory (DC/RSAT only):** privileged group membership vs expected ·
krbtgt password age · domain password/lockout policy · non-expiring passwords ·
`PASSWD_NOTREQD` · reversible encryption · Kerberoastable SPNs (privileged ones
flagged HIGH) · AS-REP roastable accounts · unconstrained/user delegation ·
stale `adminCount=1` accounts · accounts created/changed recently.

**Relay / poisoning / legacy-protocol + CVE hardening (added, mined from the
offensive playbook):** **LLMNR/NBT-NS** poisoning (Responder) · **SMB signing**
required (NTLM-relay defense) · **NTLMv1** (`LmCompatibilityLevel`) + `NoLmHash` ·
anonymous/**null-session** enumeration (`RestrictAnonymousSAM`/`RestrictRemoteSAM`) ·
**Print Spooler** + Point-and-Print (PrintNightmare / PrinterBug coercion) ·
**HiveNightmare** SAM-hive ACL (CVE-2021-36934) · **SMBGhost** compression
(CVE-2020-0796) · **WebDAV/WebClient** service (HTTP→LDAP relay) · **Credential
Guard** · **Zerologon** Netlogon enforcement (CVE-2020-1472).
**Added AD (DC/RSAT):** **`ms-DS-MachineAccountQuota`** (NoPAC / RBCD / KrbRelayUp) ·
**LDAP signing + channel binding** · **constrained + RBCD delegation** (on top of
unconstrained) · **DCSync** replication rights on the domain object · **ADCS**
ESC1/ESC2/ESC9 template flags + `StrongCertificateBindingEnforcement`.

**Advanced implant hunt (added — custom / pre-planted / in-memory C2; see
[`custom-implant-detection.md`](../../BeenThereDefendedThat/custom-implant-detection.md)):**
`NamedPipes` **Cobalt Strike / Mythic named-pipe** IOCs · `IISModules` malicious
**native IIS-module** backdoors on `w3wp.exe` + the `Microsoft-IIS-Configuration/Operational`
audit log (EID 29/50) · `PortProxy` **`netsh portproxy`** (port-piggyback / pivot) ·
`MemoryScan` staging of **pe-sieve / hollows_hunter / Moneta** + Sysmon EID 8/10/25
injection-telemetry coverage.

---

## 3. Configuration reference

### The rotating scorer, reflected in config
The scoring engine's **source IP rotates** (see the main playbook §0), so these
tools separate two ideas:
- **`ScoredPorts` / `SCORED_PORTS`** — ports that must stay **open by port** to
  any source. The auditors only *remind* you of these; they never tell you to
  restrict them to one IP.
- **`AllowedListenPorts` / `ALLOWED_LISTEN_PORTS`** — the full set of ports that
  are allowed to listen at all. Anything listening outside this list is a
  `[FAIL]` (shut it down or add it).
- **`AdminSubnet` / `ADMIN_SUBNET`** — your team's jump-box range; admin ports
  (SSH/RDP/WinRM) should be restricted here. This is the *one* place source-IP
  restriction is correct.

### Tuning to kill false positives
The **first run will be noisy** until you set the expected values. Populate:
- Linux: `EXPECTED_ADMINS`, `EXPECTED_SHELL_USERS`, `ALLOWED_LISTEN_PORTS`, `WEB_ROOTS`.
- Windows/AD: `ExpectedPrivilegedMembers`, `ExpectedLocalAdmins`, `ExpectedSpnAccounts`, `AllowedListenPorts`.

Everything the audit flags as `[WARN]`/`[FAIL]` that turns out to be legitimate
should be added to the relevant expected/allow list so real problems stand out
on the next pass. Toggle whole checks off in the `Checks` block / `CHECK_*`
flags if one is irrelevant on a given box.

---

## 4. How this fits the playbook

- **T+15–35 (triage):** run both auditors once per box to surface backdoor
  accounts, open listeners, and weak configs fast.
- **After hardening:** `--snapshot` each Linux box so you have a clean baseline.
- **T+60 onward (sustain):** run the watch loop, or re-run + `--diff` every
  30–60 min. New listeners, new SUID, new admins, new tasks = red team activity
  → capture evidence → file an incident report.

## 5. Safety & caveats

- **Read-only:** no script here modifies accounts, files, firewall, or services.
  They *report*; you remediate by hand (deliberate, per the playbook).
- Run with privilege (root/Administrator) for full coverage, but review the
  scripts first — never run something you haven't read on a competition box.
- Findings are **heuristics**. Timestamp-based web-shell and "recently modified"
  checks can miss timestomped files and can false-positive on your own edits —
  corroborate, don't trust blindly.
- These are **templates** — adapt allowlists/expected values to your actual
  environment before relying on the exit code.
- The Linux script targets bash 4+ and degrades gracefully if `ss`, `ufw`,
  `systemctl`, etc. are missing. The PowerShell script targets 5.1+ and skips
  AD checks where the module is absent.
