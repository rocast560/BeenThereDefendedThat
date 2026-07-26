#!/usr/bin/env bash
# =============================================================================
# linux-audit.sh  —  read-only CCDC blue-team misconfiguration auditor
# =============================================================================
# Reports security misconfigurations & persistence indicators. Makes NO changes.
# Config-driven: edit linux-audit.conf. Run as root for full coverage.
#
#   sudo ./linux-audit.sh                       # default config in same dir
#   sudo ./linux-audit.sh -c /path/audit.conf   # custom config
#   sudo ./linux-audit.sh -o report.txt         # also write a copy to file
#   sudo ./linux-audit.sh --only CHECK_SSH,CHECK_LISTENERS
#   sudo ./linux-audit.sh --snapshot            # save a baseline snapshot
#   sudo ./linux-audit.sh --diff                # diff current vs last snapshot
#
# Exit code: 0 = no FAILs, 1 = at least one FAIL, 2 = usage error.
# Requires bash 4+. Degrades gracefully if a tool (ss/ufw/etc.) is missing.
# =============================================================================

set -o pipefail

# ---------- defaults (overridden by config) ----------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG="$SCRIPT_DIR/linux-audit.conf"
OUTFILE=""
ONLY=""
SKIP=""
MODE="audit"        # audit | snapshot | diff
NO_COLOR=0

SCORED_PORTS=(80 443)
ALLOWED_LISTEN_PORTS=(22 80 443)
ADMIN_SUBNET=""
SCORING_CIDR=""
EXPECTED_SHELL_USERS=(root)
EXPECTED_ADMINS=(root)
KNOWN_UID0=(root)
EXCLUDE_USERS=(root)
WEB_ROOTS=(/var/www /var/www/html)
WEB_MODIFIED_DAYS=2
SYSDIR_MODIFIED_MINUTES=1440
BASELINE_DIR="$SCRIPT_DIR/baseline"
for v in UID0 EMPTY_PASSWD SHELL_USERS ADMINS SSH AUTHKEYS LISTENERS OUTBOUND \
         CRON SERVICES SUID WORLD_WRITABLE FIREWALL PERSISTENCE WEB SESSIONS \
         PASSWD_INTEGRITY CAPABILITIES NFS DANGER_GROUPS KERNEL SUDO_VERSION \
         SUDO_ENV SYSTEMD_WRITABLE ACL SSH_CA \
         RAWSOCK MEMEXEC PRELOAD_HOOK EBPF HIDDEN_PROC NAT_REDIRECT PTRACE \
         EXEC_HARDENING SYSTEMD_SANDBOX; do eval "CHECK_$v=1"; done

# Dangerous supplementary groups whose members are effectively root.
DANGEROUS_GROUPS=(docker lxd lxc disk shadow)

# Processes legitimately allowed to hold a raw/AF_PACKET (sniffer) socket.
# Anything ELSE sniffing raw packets is a BPFdoor/watershell-class indicator.
ALLOWED_SNIFFERS=(dhclient dhcpcd tcpdump wireshark dumpcap tshark NetworkManager \
                  systemd-networkd wpa_supplicant avahi-daemon arping)

# Upper bound for the hidden-PID brute-force decloak scan (see check_hidden_proc).
# pid_max can be 4M on some hosts; scanning all of it in bash is slow, so cap it.
HIDDEN_PID_SCAN_MAX=65536

# ---------- arg parsing ------------------------------------------------------
while [ $# -gt 0 ]; do
  case "$1" in
    -c|--config)   CONFIG="$2"; shift 2 ;;
    -o|--out)      OUTFILE="$2"; shift 2 ;;
    --only)        ONLY="$2"; shift 2 ;;
    --skip)        SKIP="$2"; shift 2 ;;
    --snapshot)    MODE="snapshot"; shift ;;
    --diff)        MODE="diff"; shift ;;
    --no-color)    NO_COLOR=1; shift ;;
    -h|--help)     grep '^#' "$0" | sed 's/^# \{0,1\}//' | head -n 22; exit 0 ;;
    *) echo "Unknown arg: $1" >&2; exit 2 ;;
  esac
done

[ -f "$CONFIG" ] && . "$CONFIG" || echo "WARN: config '$CONFIG' not found, using defaults" >&2

# ---------- output helpers ---------------------------------------------------
if [ -t 1 ] && [ "$NO_COLOR" -eq 0 ]; then
  C_RED=$'\033[31m'; C_YEL=$'\033[33m'; C_GRN=$'\033[32m'; C_BLU=$'\033[36m'
  C_BLD=$'\033[1m'; C_RST=$'\033[0m'
else C_RED=; C_YEL=; C_GRN=; C_BLU=; C_BLD=; C_RST=; fi

# Tallies are file-backed so counts survive `cmd | while` SUBSHELLS. With plain
# shell variables, a fail() called inside a piped-while loop increments a copy in
# the subshell and is lost — which silently undercounts FAILs and breaks the exit
# code the watch loop relies on. Appending to a file works from any subshell.
TALLY_DIR="$(mktemp -d 2>/dev/null || echo "/tmp/ccdc-audit.$$")"; mkdir -p "$TALLY_DIR"
trap 'rm -rf "$TALLY_DIR"' EXIT
tally()  { echo 1 >> "$TALLY_DIR/$1" 2>/dev/null; }
count()  { if [ -f "$TALLY_DIR/$1" ]; then wc -l < "$TALLY_DIR/$1" | tr -d ' '; else echo 0; fi; }
emit() { if [ -n "$OUTFILE" ]; then printf '%s\n' "$2" >> "$OUTFILE"; fi; printf '%b\n' "$1"; }
section() { emit "\n${C_BLD}${C_BLU}== $1 ==${C_RST}" "== $1 =="; }
fail() { tally fail; emit "  ${C_RED}[FAIL]${C_RST} $1" "  [FAIL] $1"; }
warn() { tally warn; emit "  ${C_YEL}[WARN]${C_RST} $1" "  [WARN] $1"; }
pass() { tally pass; emit "  ${C_GRN}[PASS]${C_RST} $1" "  [PASS] $1"; }
info() { tally info; emit "  ${C_BLU}[INFO]${C_RST} $1" "  [INFO] $1"; }

in_list() { local x="$1"; shift; for i in "$@"; do [ "$i" = "$x" ] && return 0; done; return 1; }
have() { command -v "$1" >/dev/null 2>&1; }
enabled() { # enabled CHECK_SSH
  local name="$1"
  if [ -n "$ONLY" ]; then case ",$ONLY," in *",$name,"*) : ;; *) return 1 ;; esac; fi
  if [ -n "$SKIP" ]; then case ",$SKIP," in *",$name,"*) return 1 ;; esac; fi
  [ "$(eval echo \$$name)" = "1" ]
}

[ -n "$OUTFILE" ] && : > "$OUTFILE"
[ "$(id -u)" -ne 0 ] && warn "Not running as root — several checks will be incomplete."

# =============================================================================
# CHECKS
# =============================================================================

check_uid0() {
  section "UID 0 accounts (backdoor root)"
  while IFS=: read -r user _ uid _; do
    [ "$uid" = "0" ] || continue
    if in_list "$user" "${KNOWN_UID0[@]}"; then pass "UID0 account expected: $user"
    else fail "Unexpected UID 0 account: $user  (potential backdoor — investigate/lock)"; fi
  done < /etc/passwd
}

check_empty_passwd() {
  section "Empty / disabled password hashes"
  [ -r /etc/shadow ] || { info "cannot read /etc/shadow (need root)"; return; }
  while IFS=: read -r user hash _; do
    case "$hash" in
      "") fail "Account '$user' has an EMPTY password (login with no password!)" ;;
    esac
  done < /etc/shadow
  [ "$(count fail)" -eq 0 ] && pass "No empty-password accounts found"
}

check_shell_users() {
  section "Login-shell accounts vs expected"
  while IFS=: read -r user _ uid _ _ _ shell; do
    case "$shell" in */nologin|*/false|"") continue ;; esac
    [ "$uid" -ge 1000 ] || [ "$uid" = "0" ] || continue
    if in_list "$user" "${EXPECTED_SHELL_USERS[@]}"; then pass "Shell user expected: $user ($shell)"
    else warn "Unexpected shell account: $user ($shell)  (red-team account? verify)"; fi
  done < /etc/passwd
}

check_admins() {
  section "sudo / root-equivalent grants"
  # sudo group members
  local sudo_grp members
  for grp in sudo wheel admin; do
    members="$(getent group "$grp" 2>/dev/null | awk -F: '{print $4}')"
    [ -n "$members" ] || continue
    IFS=',' read -ra arr <<< "$members"
    for m in "${arr[@]}"; do
      [ -z "$m" ] && continue
      if in_list "$m" "${EXPECTED_ADMINS[@]}"; then pass "Admin ($grp) expected: $m"
      else fail "Unexpected member of '$grp': $m  (privilege escalation / backdoor)"; fi
    done
  done
  # NOPASSWD sudoers
  if [ -r /etc/sudoers ]; then
    if grep -rEn 'NOPASSWD' /etc/sudoers /etc/sudoers.d/ 2>/dev/null | grep -qv '^\s*#'; then
      warn "NOPASSWD sudo rules present:"
      grep -rEn 'NOPASSWD' /etc/sudoers /etc/sudoers.d/ 2>/dev/null | grep -v '^\s*#' | while read -r l; do emit "        $l" "        $l"; done
    else pass "No NOPASSWD sudo rules"; fi
  fi
}

check_ssh() {
  section "SSH daemon hardening"
  local f=/etc/ssh/sshd_config
  [ -r "$f" ] || { info "no sshd_config"; return; }
  eff() { grep -Ei "^[[:space:]]*$1[[:space:]]" "$f" 2>/dev/null | tail -1 | awk '{print tolower($2)}'; }
  local root pw empty
  root="$(eff PermitRootLogin)";  pw="$(eff PasswordAuthentication)";  empty="$(eff PermitEmptyPasswords)"
  case "$root" in yes|prohibit-password|"") warn "PermitRootLogin=${root:-default(yes on some distros)} — set to 'no' if scored access allows" ;; *) pass "PermitRootLogin=$root" ;; esac
  case "$empty" in yes) fail "PermitEmptyPasswords=yes (critical)" ;; *) pass "PermitEmptyPasswords not enabled" ;; esac
  [ "$pw" = "no" ] && pass "PasswordAuthentication=no (key-only)" || info "PasswordAuthentication=${pw:-yes} (ok if scored, but weak)"
  grep -Eiq '^[[:space:]]*AllowUsers|^[[:space:]]*AllowGroups' "$f" && pass "SSH access restricted via AllowUsers/AllowGroups" || info "No AllowUsers/AllowGroups restriction"
}

check_authkeys() {
  section "SSH authorized_keys (persistence)"
  local found=0
  while IFS=: read -r user _ uid _ _ home _; do
    [ -d "$home" ] || continue
    for kf in "$home/.ssh/authorized_keys" "$home/.ssh/authorized_keys2"; do
      [ -f "$kf" ] || continue
      local n; n="$(grep -c '^[^#]' "$kf" 2>/dev/null)"
      [ "$n" -gt 0 ] && { warn "$user has $n SSH key(s) in $kf — confirm each is yours"; found=1
        grep '^[^#]' "$kf" 2>/dev/null | awk '{print "        ..."substr($0,length($0)-40)}' | while read -r l; do emit "$l" "$l"; done; }
    done
  done < /etc/passwd
  [ "$found" -eq 0 ] && pass "No authorized_keys files with entries found"
}

check_listeners() {
  section "Listening ports vs allowlist"
  local list
  if have ss; then list="$(ss -tulnH 2>/dev/null | awk '{print $5}')"
  elif have netstat; then list="$(netstat -tulnp 2>/dev/null | awk 'NR>2{print $4}')"
  else info "neither ss nor netstat available"; return; fi
  echo "$list" | grep -oE '[0-9]+$' | sort -un | while read -r port; do
    [ -z "$port" ] && continue
    if in_list "$port" "${ALLOWED_LISTEN_PORTS[@]}"; then pass "Listening port allowed: $port"
    else fail "Unexpected listening port: $port  (shut it down or add to allowlist)"; fi
  done
}

check_outbound() {
  section "Established outbound connections (possible C2)"
  have ss || { info "ss not available"; return; }
  # NOTE: with a 'state' filter ss omits the State column, so the peer
  # address is field 4 (Recv-Q Send-Q Local Peer [Process]).
  local rows
  rows="$(ss -tnH state established 2>/dev/null | awk '{print $4}' | sed 's/:[0-9]*$//' | sort -u)"
  local flagged=0
  while read -r ip; do
    [ -z "$ip" ] && continue
    case "$ip" in
      10.*|192.168.*|127.*|172.1[6-9].*|172.2[0-9].*|172.3[0-1].*|::1|fe80:*|"[::"* ) continue ;;
      *) warn "Outbound to PUBLIC IP: $ip  (baseline this — beacons hide here)"; flagged=1 ;;
    esac
  done <<< "$rows"
  [ "$flagged" -eq 0 ] && pass "No established outbound to public IPs right now"
}

check_cron() {
  section "Cron jobs & systemd timers"
  for d in /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly; do
    [ -e "$d" ] && info "Review: $d"
  done
  if [ -d /var/spool/cron ]; then
    find /var/spool/cron -type f 2>/dev/null | while read -r cf; do
      warn "User crontab present: $cf — inspect for reverse shells"; done
  fi
  # suspicious patterns
  if grep -rElP '(bash -i|nc |ncat|/dev/tcp/|python -c|curl .*\|.*sh|wget .*\|.*sh|base64 -d)' \
       /etc/cron* /var/spool/cron 2>/dev/null | head; then
    fail "Cron entries match reverse-shell / download-cradle patterns (see above files)"
  else pass "No obvious reverse-shell patterns in cron"; fi
  have systemctl && { info "Active timers:"; systemctl list-timers --no-pager --no-legend 2>/dev/null | awk '{print "        "$0}' | head -20 | while read -r l; do emit "$l" "$l"; done; }
}

check_services() {
  section "Running / enabled services"
  have systemctl || { info "systemctl not available"; return; }
  info "Enabled non-vendor services (review for anything unfamiliar):"
  systemctl list-unit-files --type=service --state=enabled --no-pager --no-legend 2>/dev/null \
    | awk '{print $1}' | grep -vE '^(systemd|ssh|sshd|cron|rsyslog|network|dbus|getty)' \
    | head -30 | while read -r s; do emit "        $s" "        $s"; done
  # netcat/socat listeners as services or processes
  if have ps && ps -eo comm= 2>/dev/null | grep -Eq '^(nc|ncat|socat)$'; then
    fail "netcat/socat process running — classic backdoor listener"
  else pass "No nc/ncat/socat processes running"; fi
}

check_suid() {
  section "SUID/SGID binaries"
  local cur base
  cur="$(find / -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null | sort)"
  base="$BASELINE_DIR/suid.txt"
  if [ -f "$base" ]; then
    local added; added="$(comm -13 "$base" <(echo "$cur"))"
    if [ -n "$added" ]; then fail "NEW SUID/SGID binaries since baseline:"; echo "$added" | while read -r l; do emit "        $l" "        $l"; done
    else pass "No new SUID/SGID binaries vs baseline"; fi
  else
    info "No baseline; current SUID/SGID count: $(echo "$cur" | grep -c . ). Run --snapshot to baseline."
    echo "$cur" | grep -E '/(tmp|home|dev/shm|var/tmp)/' | while read -r l; do fail "SUID in writable/odd path: $l"; done
  fi
}

check_world_writable() {
  section "World-writable files in sensitive paths"
  local hits
  hits="$(find /etc /bin /sbin /usr/bin /usr/sbin /usr/local -xdev -type f -perm -0002 2>/dev/null)"
  if [ -n "$hits" ]; then echo "$hits" | while read -r l; do fail "World-writable: $l"; done
  else pass "No world-writable files in system binary/config dirs"; fi
}

check_firewall() {
  section "Host firewall posture"
  if have ufw && ufw status 2>/dev/null | grep -qi 'Status: active'; then
    pass "ufw is active"
    ufw status verbose 2>/dev/null | grep -qi 'Default: deny (incoming)' && pass "ufw default-deny incoming" || warn "ufw incoming is not default-deny"
    ufw status verbose 2>/dev/null | grep -qiE 'Default:.*deny \(outgoing\)|deny \(routed\)' && pass "ufw default-deny outgoing (C2 containment)" || warn "ufw OUTGOING not default-deny — beacons can egress"
  elif have iptables; then
    local pin pout
    pin="$(iptables -S 2>/dev/null | grep -E '^-P INPUT' | awk '{print $3}')"
    pout="$(iptables -S 2>/dev/null | grep -E '^-P OUTPUT' | awk '{print $3}')"
    [ "$pin" = "DROP" ] && pass "iptables INPUT policy DROP" || warn "iptables INPUT policy is ${pin:-unknown} (want DROP)"
    [ "$pout" = "DROP" ] && pass "iptables OUTPUT policy DROP (C2 containment)" || warn "iptables OUTPUT policy is ${pout:-unknown} — beacons can egress"
  else warn "No ufw/iptables detected — host is unfiltered"; fi
  # Reminder tied to rotating scorer
  info "Scored ports ${SCORED_PORTS[*]} must be open by PORT (scorer IP rotates)."
  [ -n "$ADMIN_SUBNET" ] && info "Admin ports (22) should be limited to $ADMIN_SUBNET only."
}

check_persistence() {
  section "Persistence hooks"
  if [ -f /etc/ld.so.preload ] && [ -s /etc/ld.so.preload ]; then
    fail "/etc/ld.so.preload is non-empty (userland rootkit hook):"; sed 's/^/        /' /etc/ld.so.preload | while read -r l; do emit "$l" "$l"; done
  else pass "/etc/ld.so.preload empty/absent"; fi
  [ -f /etc/rc.local ] && grep -qvE '^\s*(#|exit|$)' /etc/rc.local && warn "/etc/rc.local has active commands — review" || pass "/etc/rc.local clean/absent"
  # shell rc backdoors
  local hit=0
  for rc in /etc/profile /etc/bash.bashrc /root/.bashrc /root/.profile; do
    [ -f "$rc" ] || continue
    grep -ElP '(/dev/tcp/|bash -i|nc |ncat|curl .*\|.*sh|base64 -d)' "$rc" >/dev/null 2>&1 && { fail "Suspicious command in $rc"; hit=1; }
  done
  [ "$hit" -eq 0 ] && pass "No reverse-shell patterns in common shell rc files"
  # new systemd services in /etc/systemd/system
  [ -d /etc/systemd/system ] && find /etc/systemd/system -maxdepth 1 -name '*.service' -mmin -"$SYSDIR_MODIFIED_MINUTES" 2>/dev/null | while read -r s; do warn "Recently created/modified service unit: $s"; done
}

check_web() {
  section "Recently modified web files (webshell indicator)"
  local any=0
  for wr in "${WEB_ROOTS[@]}"; do
    [ -d "$wr" ] || continue
    any=1
    find "$wr" -type f \( -name '*.php' -o -name '*.jsp' -o -name '*.asp' -o -name '*.aspx' \) -mtime -"$WEB_MODIFIED_DAYS" 2>/dev/null \
      | while read -r f; do warn "Recently modified web file: $f (check for webshell; don't trust mtime alone)"; done
    # eval/system markers
    grep -rElP '(eval\s*\(|system\s*\(|passthru|shell_exec|base64_decode\s*\(.*\)\s*\))' "$wr" 2>/dev/null | head \
      | while read -r f; do fail "Web file contains code-exec markers: $f"; done
  done
  [ "$any" -eq 0 ] && info "No configured web roots present on this host"
}

check_sessions() {
  section "Sessions & auth failures"
  have who && { info "Current logins:"; who 2>/dev/null | awk '{print "        "$0}' | while read -r l; do emit "$l" "$l"; done; }
  local authlog=/var/log/auth.log; [ -f /var/log/secure ] && authlog=/var/log/secure
  if [ -r "$authlog" ]; then
    local fails; fails="$(grep -c 'Failed password' "$authlog" 2>/dev/null)"
    [ "${fails:-0}" -gt 20 ] && warn "$fails 'Failed password' events in $authlog (brute force?)" || info "${fails:-0} failed-password events in $authlog"
    grep 'Accepted' "$authlog" 2>/dev/null | tail -5 | awk '{print "        "$0}' | while read -r l; do emit "$l" "$l"; done
  else info "auth log not readable"; fi
}

check_passwd_integrity() {
  section "Sensitive file modification times"
  for f in /etc/passwd /etc/shadow /etc/group /etc/sudoers; do
    [ -e "$f" ] || continue
    local mt; mt="$(stat -c '%y' "$f" 2>/dev/null | cut -d. -f1)"
    local recent; recent="$(find "$f" -mmin -"$SYSDIR_MODIFIED_MINUTES" 2>/dev/null)"
    [ -n "$recent" ] && warn "$f modified recently ($mt) — expected if YOU rotated creds; else investigate" || info "$f last modified $mt"
  done
}

check_capabilities() {
  section "File capabilities (getcap privesc)"
  have getcap || { info "getcap not available (install libcap) — skipping capability scan"; return; }
  # Scan only the local root filesystem's real binary/lib trees — never recurse
  # into mounts (/mnt, /media), pseudo-fs (/proc, /sys, /dev, /run), or virtual
  # overlays, which makes 'getcap -r /' hang and produces noise.
  local roots=() d
  for d in /usr /bin /sbin /lib /lib64 /opt /etc /home /srv /var /root; do
    [ -d "$d" ] && roots+=("$d")
  done
  local hits; hits="$(getcap -r "${roots[@]}" 2>/dev/null)"
  [ -z "$hits" ] && { pass "No files with capabilities set"; return; }
  local flagged=0
  # Dangerous caps that grant root-equivalent power on the right binary.
  echo "$hits" | while IFS= read -r line; do
    [ -z "$line" ] && continue
    case "$line" in
      *cap_setuid*|*cap_setgid*|*cap_dac_read_search*|*cap_dac_override*|*cap_sys_admin*|*cap_sys_ptrace*|*cap_sys_module*|*cap_chown*|*cap_fowner*)
        fail "Dangerous capability: $line  (potential privesc — verify it is legitimate)" ;;
      *)
        info "Capability set: $line" ;;
    esac
  done
}

check_nfs() {
  section "NFS exports (no_root_squash)"
  local f=/etc/exports
  [ -f "$f" ] || { info "no /etc/exports on this host"; return; }
  if grep -Ev '^\s*(#|$)' "$f" 2>/dev/null | grep -Eq 'no_root_squash|no_all_squash|insecure'; then
    grep -Env '^\s*(#|$)' "$f" 2>/dev/null | grep -E 'no_root_squash|no_all_squash|insecure' | while read -r l; do
      fail "Unsafe export (remote root can drop SUID binary): $l"; done
  else pass "No no_root_squash / no_all_squash exports"; fi
  # client side: mounts missing nosuid on NFS
  if grep -q ' nfs' /proc/mounts 2>/dev/null; then
    grep ' nfs' /proc/mounts 2>/dev/null | grep -qv 'nosuid' && warn "NFS mount(s) without 'nosuid' — SUID from server is honored" \
      || pass "NFS mounts use nosuid"
  fi
}

check_danger_groups() {
  section "Root-equivalent group membership (docker/lxd/disk/...)"
  local flagged=0
  for grp in "${DANGEROUS_GROUPS[@]}"; do
    local members; members="$(getent group "$grp" 2>/dev/null | awk -F: '{print $4}')"
    [ -n "$members" ] || continue
    IFS=',' read -ra arr <<< "$members"
    for m in "${arr[@]}"; do
      [ -z "$m" ] && continue
      in_list "$m" "${EXCLUDE_USERS[@]}" && continue
      fail "'$m' is in '$grp' group — root-equivalent (docker/lxd = trivial privesc)"; flagged=1
    done
  done
  # docker socket exposed to non-root
  if [ -S /var/run/docker.sock ]; then
    local perm; perm="$(stat -c '%a' /var/run/docker.sock 2>/dev/null)"
    case "$perm" in *[67]) warn "/var/run/docker.sock is group/other writable ($perm) — container-escape to root" ;; esac
  fi
  [ "$flagged" -eq 0 ] && pass "No unexpected members in dangerous groups"
}

# numeric-compare helper: ver_lt 1.2.3 1.3.0  -> true if first < second
ver_lt() { [ "$1" = "$2" ] && return 1; [ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -1)" = "$1" ]; }

check_kernel() {
  section "Kernel version vs known local-root exploits"
  local kv full; full="$(uname -r)"; kv="$(echo "$full" | grep -oE '^[0-9]+\.[0-9]+\.[0-9]+')"
  info "Running kernel: $full"
  [ -z "$kv" ] && { info "could not parse kernel version"; return; }
  local maj min pat; IFS='.' read -r maj min pat <<< "$kv"
  # Dirty Pipe (CVE-2022-0847): 5.8 <= v, fixed in 5.16.11 / 5.15.25 / 5.10.102
  if [ "$maj" -eq 5 ]; then
    local vuln=0
    if [ "$min" -ge 8 ]; then
      if   [ "$min" -eq 16 ] && [ "$pat" -lt 11 ];  then vuln=1
      elif [ "$min" -eq 15 ] && [ "$pat" -lt 25 ];  then vuln=1
      elif [ "$min" -eq 10 ] && [ "$pat" -lt 102 ]; then vuln=1
      elif [ "$min" -ne 16 ] && [ "$min" -ne 15 ] && [ "$min" -ne 10 ] && [ "$min" -le 16 ]; then vuln=1
      fi
    fi
    [ "$vuln" -eq 1 ] && fail "Kernel $kv is in Dirty Pipe range (CVE-2022-0847) — patch/reboot" \
                      || pass "Kernel $kv not in Dirty Pipe vulnerable range"
  else
    info "Kernel $kv outside Dirty Pipe 5.8–5.16 window (still verify against exploit-suggester)"
  fi
  # Dirty COW (CVE-2016-5195): fixed ~4.8.3; anything older is suspect
  if [ "$maj" -lt 4 ] || { [ "$maj" -eq 4 ] && [ "$min" -lt 9 ]; }; then
    warn "Kernel $kv predates common Dirty COW fixes — treat as vulnerable, patch"
  fi
}

check_sudo_version() {
  section "sudo version vs known CVEs"
  have sudo || { info "sudo not installed"; return; }
  local ver; ver="$(sudo -V 2>/dev/null | grep -oiE 'version [0-9][0-9a-z.p]*' | head -1 | awk '{print $2}')"
  [ -z "$ver" ] && { info "could not determine sudo version"; return; }
  info "sudo version: $ver"
  # normalize a leading numeric x.y.z for comparison (drop pN suffix)
  local core; core="$(echo "$ver" | grep -oE '^[0-9]+\.[0-9]+\.[0-9]+')"
  # CVE-2021-3156 (Baron Samedit): fixed in 1.9.5p2
  if [ -n "$core" ] && ver_lt "$core" "1.9.6"; then
    warn "sudo $ver may be vulnerable to CVE-2021-3156 (Baron Samedit) — need >= 1.9.5p2"
  fi
  # CVE-2019-14287 (-u#-1): fixed in 1.8.28
  if [ -n "$core" ] && ver_lt "$core" "1.8.28"; then
    fail "sudo $ver vulnerable to CVE-2019-14287 (sudo -u#-1 runas bypass) — upgrade"
  fi
  [ -n "$core" ] && ! ver_lt "$core" "1.9.6" && pass "sudo $ver above the flagged CVE thresholds"
}

check_sudo_env() {
  section "sudo env_keep / LD_PRELOAD injection"
  local files="/etc/sudoers"; [ -d /etc/sudoers.d ] && files="$files /etc/sudoers.d"
  local hit=0
  if grep -rEn 'env_keep' $files 2>/dev/null | grep -qiE 'LD_PRELOAD|LD_LIBRARY_PATH'; then
    grep -rEn 'env_keep' $files 2>/dev/null | grep -iE 'LD_PRELOAD|LD_LIBRARY_PATH' | while read -r l; do
      fail "sudoers preserves LD_* (library-injection privesc): $l"; done
    hit=1
  fi
  if grep -rEn 'SETENV|!env_reset' $files 2>/dev/null | grep -qv '^\s*#'; then
    grep -rEn 'SETENV|!env_reset' $files 2>/dev/null | grep -v '^\s*#' | while read -r l; do
      warn "sudoers allows caller-controlled env (SETENV/!env_reset): $l"; done
    hit=1
  fi
  [ "$hit" -eq 0 ] && pass "sudoers does not preserve LD_PRELOAD/LD_LIBRARY_PATH or allow SETENV"
}

check_systemd_writable() {
  section "Writable systemd units & ExecStart binaries"
  have systemctl || { info "systemctl not available"; return; }
  local flagged=0
  # world/group-writable unit files
  for d in /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system /run/systemd/system; do
    [ -d "$d" ] || continue
    find "$d" -maxdepth 2 -type f \( -name '*.service' -o -name '*.timer' -o -name '*.socket' \) -perm -0002 2>/dev/null \
      | while read -r u; do fail "World-writable unit file (attacker can hijack): $u"; done
    # unit files owned by / writable by a non-root user
    find "$d" -maxdepth 2 -type f \( -name '*.service' -o -name '*.timer' \) ! -user root 2>/dev/null \
      | while read -r u; do warn "Unit file not owned by root: $u"; done
  done
  # ExecStart binaries that are writable by non-owner
  local execs; execs="$(grep -rhoE '^ExecStart=[^ ]*' /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null \
      | sed 's/^ExecStart=//; s/^[@+!-]*//' | grep '^/' | sort -u)"
  echo "$execs" | while read -r bin; do
    [ -f "$bin" ] || continue
    # world-writable ExecStart target = anyone can replace what the unit runs as root
    if find "$bin" -perm -0002 2>/dev/null | grep -q .; then
      fail "ExecStart binary is world-writable: $bin  (anyone can hijack this service)"
    fi
    # a service binary not owned by root is also a hijack vector for that owner
    local owner; owner="$(stat -c '%U' "$bin" 2>/dev/null)"
    [ -n "$owner" ] && [ "$owner" != "root" ] && warn "ExecStart binary not owned by root ($owner): $bin"
  done
  pass "systemd unit/ExecStart scan complete (review any WARN/FAIL above)"
}

check_acl() {
  section "ACLs & symlinks on /etc/passwd & /etc/shadow"
  have getfacl || { info "getfacl not available (install acl) — skipping ACL check"; return; }
  for f in /etc/passwd /etc/shadow /etc/group /etc/sudoers; do
    [ -e "$f" ] || continue
    # any 'user:' or 'group:' ACE beyond the base owner/group grants extra access
    local extra; extra="$(getfacl -p "$f" 2>/dev/null | grep -E '^(user|group):[^:]+:' | grep -vE ':(r--|---)$')"
    [ -n "$extra" ] && { fail "$f has extra write ACL entries (backdoor to creds):"; echo "$extra" | while read -r l; do emit "        $l" "        $l"; done; }
  done
  # symlink attacks pointing at sensitive files
  find /home /tmp /var/tmp -maxdepth 3 -type l 2>/dev/null | while read -r l; do
    local tgt; tgt="$(readlink -f "$l" 2>/dev/null)"
    case "$tgt" in /etc/passwd|/etc/shadow|/etc/sudoers) warn "Symlink $l -> $tgt (possible symlink-race setup)" ;; esac
  done
  pass "ACL/symlink scan complete (review any WARN/FAIL above)"
}

check_ssh_ca() {
  section "SSH CA trust & cert-authority keys"
  local f=/etc/ssh/sshd_config
  if [ -r "$f" ]; then
    local ca; ca="$(grep -Ei '^\s*TrustedUserCAKeys' "$f" 2>/dev/null | awk '{print $2}')"
    if [ -n "$ca" ]; then
      warn "sshd trusts a User CA ($ca) — any cert it signs is accepted; verify the CA key and its private half are secured"
      [ -f "$ca" ] && { local p; p="$(stat -c '%a' "$ca" 2>/dev/null)"; case "$p" in *[2367]) fail "TrustedUserCAKeys file is writable ($p): $ca" ;; esac; }
    else info "No TrustedUserCAKeys directive (no SSH CA trust)"; fi
    grep -Ei '^\s*(AllowTcpForwarding|GatewayPorts)\s+yes' "$f" 2>/dev/null | while read -r l; do
      info "SSH forwarding enabled ($l) — fine if needed, but aids pivoting"; done
  fi
  # cert-authority lines in any authorized_keys = trusts a CA to sign logins
  while IFS=: read -r user _ uid _ _ home _; do
    [ -d "$home" ] || continue
    for kf in "$home/.ssh/authorized_keys" "$home/.ssh/authorized_keys2"; do
      [ -f "$kf" ] || continue
      grep -qi 'cert-authority' "$kf" 2>/dev/null && fail "$user authorized_keys has a 'cert-authority' entry ($kf) — trusts a CA to mint logins"
    done
  done < /etc/passwd
  [ -r "$f" ] || info "sshd_config not readable (run as root) — CA-trust check limited to authorized_keys"
}

# =============================================================================
# ADVANCED IMPLANT HUNT (custom / pre-planted / fileless C2)
# Sources: Elastic Security Labs (BPFdoor RE, Hunting In Memory), Fortinet,
# Sandfly Security, Microsoft, Red Hat, hasherezade (pe-sieve/hollows_hunter).
# These target implants that evade signature/JA3/YARA and standard SUID/cron
# audits: raw-packet sniff-shells, port-piggyback C2, fileless/injected code.
# =============================================================================

# Build a one-time socket-inode -> pid map from /proc/*/fd (bash 4 assoc array).
declare -A SOCK_PID
_sockmap_built=0
build_sock_map() {
  [ "$_sockmap_built" = "1" ] && return
  local l tgt ino pid
  for l in /proc/[0-9]*/fd/*; do
    [ -L "$l" ] || continue
    tgt="$(readlink "$l" 2>/dev/null)" || continue
    case "$tgt" in
      socket:\[*\]) ino="${tgt#socket:[}"; ino="${ino%]}" ;;
      *) continue ;;
    esac
    pid="${l#/proc/}"; pid="${pid%%/*}"
    [ -z "${SOCK_PID[$ino]:-}" ] && SOCK_PID[$ino]="$pid"
  done
  _sockmap_built=1
}

check_rawsock() {
  section "Raw / AF_PACKET sniffer sockets (BPFdoor / watershell class)"
  # A sniff-shell has NO listening port: it reads raw frames via an AF_PACKET
  # socket and a magic packet triggers command exec. /proc/net/packet lists
  # every such socket; map its inode back to the owning process. Any non-
  # allowlisted sniffer is a high-confidence backdoor indicator.
  local pkt=/proc/net/packet
  if [ -r "$pkt" ]; then
    build_sock_map
    local any=0
    # last column of /proc/net/packet is the socket inode
    awk 'NR>1{print $NF}' "$pkt" 2>/dev/null | sort -u | while read -r ino; do
      [ -z "$ino" ] && continue
      any=1
      local pid="${SOCK_PID[$ino]:-}" comm="?"
      [ -n "$pid" ] && comm="$(cat /proc/"$pid"/comm 2>/dev/null)"
      if [ -n "$comm" ] && in_list "$comm" "${ALLOWED_SNIFFERS[@]}"; then
        pass "AF_PACKET socket by allowlisted sniffer: $comm (pid ${pid:-?})"
      else
        fail "AF_PACKET/raw socket held by NON-allowlisted process: ${comm:-?} (pid ${pid:-unknown}, inode $ino) — sniff-shell/BPFdoor indicator; inspect /proc/${pid:-PID}/exe and /proc/${pid:-PID}/stack"
      fi
    done
    [ "$(awk 'NR>1' "$pkt" 2>/dev/null | grep -c .)" -eq 0 ] && pass "No AF_PACKET sockets open on this host"
  else info "/proc/net/packet not readable (need root) — raw-socket hunt degraded"; fi
  # ss -0pb additionally reveals the ATTACHED BPF FILTER (the sniff-shell trigger)
  if have ss; then
    ss -0pbH 2>/dev/null | grep -qi 'bpf' && warn "A packet socket has an ATTACHED BPF FILTER (ss -0pb) — classic BPFdoor/sniff-shell trigger; review the owning process"
  fi
  # Promiscuous interfaces (watershell -p, and many sniffers)
  if have ip; then
    ip -o link show 2>/dev/null | grep -i 'PROMISC' | sed -E 's/^[0-9]+: ([^:@]+).*/\1/' | while read -r ifc; do
      warn "Interface in PROMISCUOUS mode: $ifc — expected only while you run tcpdump; else a sniffer is active"
    done
    ip -o link show 2>/dev/null | grep -qi 'PROMISC' || pass "No interfaces in promiscuous mode"
  fi
}

check_memexec() {
  section "Fileless / injected code (deleted-exe, memfd, RWX memory)"
  local hits=0
  for p in /proc/[0-9]*; do
    local exe; exe="$(readlink "$p/exe" 2>/dev/null)" || continue
    [ -z "$exe" ] && continue
    local pid="${p#/proc/}" comm; comm="$(cat "$p/comm" 2>/dev/null)"
    case "$exe" in
      *memfd:*) fail "PID $pid ($comm) executes from MEMFD (fileless, never touched disk): $exe" ; hits=1 ;;
      *"(deleted)") warn "PID $pid ($comm) runs from a DELETED executable: $exe — self-deleting/dropped implant" ; hits=1 ;;
      /dev/shm/*|/tmp/*|/var/tmp/*|/run/shm/*) warn "PID $pid ($comm) runs from a world-writable path: $exe" ; hits=1 ;;
    esac
  done
  # RWX anonymous mappings = reflective/injected code (needs root to read maps)
  if [ "$(id -u)" -eq 0 ]; then
    for p in /proc/[0-9]*; do
      local m="$p/maps"; [ -r "$m" ] || continue
      # perms field contains rwx AND there is no pathname (anonymous => NF==5)
      if awk '$2 ~ /rwx/ && NF==5 {f=1} END{exit !f}' "$m" 2>/dev/null; then
        local pid="${p#/proc/}"; warn "PID $pid ($(cat "$p/comm" 2>/dev/null)) has RWX anonymous memory — reflective-loader / injected-shellcode indicator"; hits=1
      fi
    done
  else info "run as root to scan /proc/*/maps for RWX anonymous regions"; fi
  [ "$hits" -eq 0 ] && pass "No deleted-exe / memfd / RWX-memory processes found"
}

check_preload_hook() {
  section "Runtime library injection (LD_PRELOAD in live processes)"
  local hits=0
  for p in /proc/[0-9]*; do
    local env="$p/environ"; [ -r "$env" ] || continue
    # subshell-wrap so a denied open (readable bit set but ptrace-gated) stays quiet
    local val; val="$( (tr '\0' '\n' < "$env") 2>/dev/null | grep '^LD_PRELOAD=' | head -1)"
    if [ -n "$val" ]; then
      local pid="${p#/proc/}"; fail "PID $pid ($(cat "$p/comm" 2>/dev/null)) carries $val — library injection / userland hook of a running process"; hits=1
    fi
  done
  [ "$hits" -eq 0 ] && pass "No live process carries LD_PRELOAD in its environment"
  [ "$(id -u)" -ne 0 ] && info "(run as root to inspect other users' /proc/*/environ)"
}

check_ebpf() {
  section "Loaded eBPF / XDP / TC programs (kernel-level backdoor surface)"
  # XDP/TC BPF run BEFORE netfilter, so an eBPF backdoor is invisible to iptables.
  # Legit tools (Falco, Cilium, Tetragon, systemd) also load BPF — so this is
  # context to CONFIRM, not an automatic FAIL. Syscall-hooking types are worse.
  if have bpftool; then
    local n; n="$(bpftool prog show 2>/dev/null | grep -cE '^[0-9]+:')"
    if [ "${n:-0}" -gt 0 ]; then
      info "$n eBPF program(s) loaded — confirm each belongs to Falco/Cilium/Tetragon/systemd or your own tooling:"
      bpftool prog show 2>/dev/null | grep -E '^[0-9]+:' | head -40 | while read -r l; do emit "        $l" "        $l"; done
      bpftool prog show 2>/dev/null | grep -iE 'kprobe|tracepoint|lsm|fentry|fexit' | head | while read -r l; do
        warn "Syscall-hooking eBPF program (can hide processes/filter syscalls — verify origin): $l"; done
    else pass "No eBPF programs loaded"; fi
    [ -d /sys/fs/bpf ] && [ -n "$(ls -A /sys/fs/bpf 2>/dev/null)" ] && \
      info "Pinned BPF objects under /sys/fs/bpf (persistence surface): $(ls /sys/fs/bpf 2>/dev/null | tr '\n' ' ')"
  else info "bpftool not installed — cannot enumerate eBPF (install linux-tools/bpftool for full coverage)"; fi
  if have ip; then
    ip -o link show 2>/dev/null | grep -iE 'xdp' | sed -E 's/^[0-9]+: ([^:@]+).*/\1/' | sort -u | while read -r ifc; do
      warn "XDP program attached to interface $ifc — executes before netfilter; confirm it is yours"
    done
  fi
}

check_hidden_proc() {
  section "Hidden processes & LKM/eBPF rootkit indicators"
  # Kernel taint: out-of-tree/unsigned modules (LKM rootkits) set taint bits.
  if [ -r /proc/sys/kernel/tainted ]; then
    local t; t="$(cat /proc/sys/kernel/tainted 2>/dev/null)"
    if [ "${t:-0}" -ne 0 ]; then
      warn "Kernel is TAINTED (/proc/sys/kernel/tainted=$t) — out-of-tree/unsigned module present; LKM rootkits taint the kernel. Decode bits with the kernel docs."
    else pass "Kernel not tainted"; fi
  fi
  # Decloak: a PID the kernel keeps alive but /proc hides = LKM stealth rootkit
  # (Diamorphine/Reptile). Brute-force the PID space with the kill(pid,0) probe.
  local maxpid; maxpid="$(cat /proc/sys/kernel/pid_max 2>/dev/null || echo 32768)"
  local cap="$maxpid"; [ "$cap" -gt "$HIDDEN_PID_SCAN_MAX" ] && cap="$HIDDEN_PID_SCAN_MAX"
  local hidden=0 pid
  for ((pid=1; pid<=cap; pid++)); do
    if kill -0 "$pid" 2>/dev/null && [ ! -d "/proc/$pid" ]; then
      fail "HIDDEN process PID $pid — alive to the kernel but absent from /proc (LKM stealth rootkit: Diamorphine/Reptile class)"; hidden=1
    fi
  done
  [ "$hidden" -eq 0 ] && pass "No hidden PIDs in 1..$cap (kernel-alive but /proc-absent)"
  [ "$cap" -lt "$maxpid" ] && info "Decloak scan capped at $cap of pid_max=$maxpid (raise HIDDEN_PID_SCAN_MAX for full coverage)"
  # Named rootkit modules
  if have lsmod; then
    lsmod 2>/dev/null | awk '{print $1}' | grep -iE 'diamorphine|reptile|rootkit|kbeast|sutekh|azazel|jynx|beurk' | while read -r m; do
      fail "Suspicious kernel module loaded: $m (known rootkit name)"; done
  fi
}

check_nat_redirect() {
  section "NAT PREROUTING redirect (port-piggyback C2)"
  # BPFdoor hides by REDIRECTing a legit port (443/ssh) to its own high socket,
  # so traffic never appears addressed to the implant. Flag PREROUTING NAT.
  local shown=0
  if have iptables; then
    local rules; rules="$(iptables -t nat -S PREROUTING 2>/dev/null | grep -iE 'REDIRECT|DNAT')"
    if [ -n "$rules" ]; then shown=1; echo "$rules" | while read -r l; do
      warn "NAT PREROUTING REDIRECT/DNAT (verify — BPFdoor-style port hijack looks like this): $l"; done
    fi
  fi
  if have nft; then
    local nftr; nftr="$(nft list ruleset 2>/dev/null | grep -iE 'redirect|dnat')"
    if [ -n "$nftr" ]; then shown=1; echo "$nftr" | while read -r l; do
      warn "nftables redirect/dnat rule (verify): $l"; done
    fi
  fi
  [ "$shown" -eq 0 ] && pass "No PREROUTING REDIRECT/DNAT rules (no obvious port-piggyback)"
}

check_ptrace() {
  section "Live ptrace relationships (process injection)"
  local hits=0
  for p in /proc/[0-9]*; do
    local st="$p/status"; [ -r "$st" ] || continue
    local tracer; tracer="$(awk '/^TracerPid:/{print $2}' "$st" 2>/dev/null)"
    [ -n "$tracer" ] && [ "$tracer" != "0" ] || continue
    local pid="${p#/proc/}" tcomm; tcomm="$(cat /proc/"$tracer"/comm 2>/dev/null)"
    case "$tcomm" in
      gdb|strace|ltrace|lldb|gdbserver) info "PID $pid traced by $tcomm (pid $tracer) — likely legitimate debugging" ;;
      *) warn "PID $pid ($(cat "$p/comm" 2>/dev/null)) is PTRACE'd by '$tcomm' (pid $tracer) — process-injection indicator"; hits=1 ;;
    esac
  done
  [ "$hits" -eq 0 ] && pass "No unexpected ptrace relationships"
  if [ -r /proc/sys/kernel/yama/ptrace_scope ]; then
    local ps; ps="$(cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null)"
    [ "${ps:-0}" -ge 1 ] && pass "yama ptrace_scope=$ps (cross-process ptrace restricted)" \
                         || warn "yama ptrace_scope=0 — any process can ptrace another (injection easier); set kernel.yama.ptrace_scope=1"
  fi
}

check_exec_hardening() {
  section "Execution-control hardening (noexec, fapolicyd)"
  for mp in /tmp /var/tmp /dev/shm /run/shm /home; do
    local opt; opt="$(awk -v m="$mp" '$2==m{print $4}' /proc/mounts 2>/dev/null | head -1)"
    [ -z "$opt" ] && continue
    case ",$opt," in
      *,noexec,*) pass "$mp mounted noexec (dropped binaries cannot execute from here)" ;;
      *)          warn "$mp is NOT noexec — an attacker can run dropped implants here (remount noexec,nosuid,nodev)" ;;
    esac
  done
  if have fapolicyd || [ -d /etc/fapolicyd ]; then
    if have systemctl && systemctl is-active --quiet fapolicyd 2>/dev/null; then
      pass "fapolicyd active (default-deny execution: only trusted/packaged binaries run)"
    else info "fapolicyd present but not active — enable it to block untrusted/dropped binaries"; fi
  else info "No fapolicyd (RHEL/Fedora exec allowlisting) — consider it (or AppArmor 'ix'/noexec) to stop dropped payloads"; fi
}

check_systemd_sandbox() {
  section "Network-daemon sandboxing posture (systemd)"
  have systemctl || { info "systemctl not available"; return; }
  # Sandboxing directives blunt what an RCE inside a daemon can do — e.g.
  # RestrictAddressFamilies=~AF_PACKET makes a sniff-shell impossible in that
  # service, SystemCallFilter blocks module load / ptrace / raw-io.
  local daemons="sshd nginx httpd apache2 mysqld mariadb postgresql vsftpd named smbd php-fpm"
  local seen=0
  for d in $daemons; do
    systemctl list-unit-files "$d.service" >/dev/null 2>&1 || continue
    systemctl is-enabled "$d.service" >/dev/null 2>&1 || continue
    seen=1
    local raf nnp scf
    raf="$(systemctl show -p RestrictAddressFamilies --value "$d.service" 2>/dev/null)"
    nnp="$(systemctl show -p NoNewPrivileges --value "$d.service" 2>/dev/null)"
    scf="$(systemctl show -p SystemCallFilter --value "$d.service" 2>/dev/null)"
    if [ -z "$raf" ] && [ "$nnp" != "yes" ] && [ -z "$scf" ]; then
      warn "$d.service has NO sandboxing (NoNewPrivileges/SystemCallFilter/RestrictAddressFamilies all unset) — an RCE here can raw-socket, ptrace and exec freely"
    else
      case "$raf" in *AF_PACKET*) info "$d.service: RestrictAddressFamilies still allows AF_PACKET — tighten to '~AF_PACKET' to kill sniff-shells" ;; esac
      pass "$d.service partially sandboxed (NoNewPrivileges=$nnp; SystemCallFilter set=$([ -n "$scf" ] && echo yes || echo no); RestrictAddressFamilies=${raf:-unset})"
    fi
  done
  [ "$seen" -eq 0 ] && info "None of the common network daemons are enabled here"
}

# =============================================================================
# SNAPSHOT / DIFF
# =============================================================================
do_snapshot() {
  mkdir -p "$BASELINE_DIR"
  find / -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null | sort > "$BASELINE_DIR/suid.txt"
  (have ss && ss -tulnH || netstat -tuln) 2>/dev/null | sort > "$BASELINE_DIR/listeners.txt"
  cp /etc/passwd "$BASELINE_DIR/passwd.txt" 2>/dev/null
  crontab -l 2>/dev/null > "$BASELINE_DIR/root-cron.txt"
  echo "Snapshot written to $BASELINE_DIR"
  exit 0
}
do_diff() {
  [ -d "$BASELINE_DIR" ] || { echo "No baseline in $BASELINE_DIR — run --snapshot first"; exit 2; }
  echo "== SUID diff =="; diff <(sort "$BASELINE_DIR/suid.txt") <(find / -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null | sort) || true
  echo "== passwd diff =="; diff "$BASELINE_DIR/passwd.txt" /etc/passwd 2>/dev/null || true
  echo "== listeners diff =="; diff <(sort "$BASELINE_DIR/listeners.txt") <((have ss && ss -tulnH || netstat -tuln) 2>/dev/null | sort) || true
  exit 0
}
[ "$MODE" = "snapshot" ] && do_snapshot
[ "$MODE" = "diff" ] && do_diff

# =============================================================================
# RUN
# =============================================================================
emit "${C_BLD}CCDC Linux Audit — $(hostname) — $(date '+%F %T')${C_RST}" "CCDC Linux Audit — $(hostname) — $(date '+%F %T')"
enabled CHECK_UID0            && check_uid0
enabled CHECK_EMPTY_PASSWD    && check_empty_passwd
enabled CHECK_SHELL_USERS     && check_shell_users
enabled CHECK_ADMINS          && check_admins
enabled CHECK_SSH             && check_ssh
enabled CHECK_AUTHKEYS        && check_authkeys
enabled CHECK_LISTENERS       && check_listeners
enabled CHECK_OUTBOUND        && check_outbound
enabled CHECK_CRON            && check_cron
enabled CHECK_SERVICES        && check_services
enabled CHECK_SUID            && check_suid
enabled CHECK_WORLD_WRITABLE  && check_world_writable
enabled CHECK_FIREWALL        && check_firewall
enabled CHECK_PERSISTENCE     && check_persistence
enabled CHECK_WEB             && check_web
enabled CHECK_SESSIONS        && check_sessions
enabled CHECK_PASSWD_INTEGRITY && check_passwd_integrity
enabled CHECK_CAPABILITIES    && check_capabilities
enabled CHECK_NFS             && check_nfs
enabled CHECK_DANGER_GROUPS   && check_danger_groups
enabled CHECK_KERNEL          && check_kernel
enabled CHECK_SUDO_VERSION    && check_sudo_version
enabled CHECK_SUDO_ENV        && check_sudo_env
enabled CHECK_SYSTEMD_WRITABLE && check_systemd_writable
enabled CHECK_ACL             && check_acl
enabled CHECK_SSH_CA          && check_ssh_ca
enabled CHECK_RAWSOCK         && check_rawsock
enabled CHECK_MEMEXEC         && check_memexec
enabled CHECK_PRELOAD_HOOK    && check_preload_hook
enabled CHECK_EBPF            && check_ebpf
enabled CHECK_HIDDEN_PROC     && check_hidden_proc
enabled CHECK_NAT_REDIRECT    && check_nat_redirect
enabled CHECK_PTRACE          && check_ptrace
enabled CHECK_EXEC_HARDENING  && check_exec_hardening
enabled CHECK_SYSTEMD_SANDBOX && check_systemd_sandbox

n_fail="$(count fail)"; n_warn="$(count warn)"; n_pass="$(count pass)"; n_info="$(count info)"
emit "\n${C_BLD}Summary:${C_RST} ${C_RED}$n_fail FAIL${C_RST}  ${C_YEL}$n_warn WARN${C_RST}  ${C_GRN}$n_pass PASS${C_RST}  ${C_BLU}$n_info INFO${C_RST}" \
     "Summary: $n_fail FAIL  $n_warn WARN  $n_pass PASS  $n_info INFO"
[ "$n_fail" -gt 0 ] && exit 1 || exit 0
