#!/usr/bin/env bash
# btdt-edr.sh — BeenThereDefendedThat lightweight host-local EDR sensor (Linux)
#
# A single-file, zero-dependency detect-and-respond sensor for CCDC-style
# competitions where every box is assumed pre-compromised and there is no safe
# central host to run a control plane on. Copy this script + btdt-edr.conf to a
# box, run as root, and it hunts the mechanisms an implant cannot avoid — raw
# packet sockets, memory-only execution, socket-backed shells, outbound calls
# from untrusted binaries, hidden PIDs — rather than signatures it can change.
#
# It is the continuous sensor/responder companion to the point-in-time auditor
# Competition-Playbook/ccdc-audit/linux-audit.sh: run that once at T0 for the full 30+
# check triage; leave this running for the rest of the round.
#
#   sudo ./btdt-edr.sh --baseline        # capture T0 state (do this first)
#   sudo ./btdt-edr.sh --once            # one sweep, alert only
#   sudo ./btdt-edr.sh --watch           # loop forever every WATCH_INTERVAL s
#   sudo ./btdt-edr.sh --watch --respond kill   # loop + auto-contain high-conf hits
#
# Flags: -c FILE (config) · -o FILE (also tee console to FILE) · --only a,b ·
#        --skip a,b · --respond MODE · --no-color · --dry-run · -h
#
# Exit code: 0 = clean sweep, 1 = at least one ALERT this sweep (wire into loops).

set -uo pipefail

# --------------------------------------------------------------------------
# Defaults (overridden by config file, then by CLI flags)
# --------------------------------------------------------------------------
CONFIG=""
OUTFILE=""
COLOR=1
DRYRUN=0
MODE_ONCE=0
MODE_WATCH=0
MODE_BASELINE=0
ONLY=""
SKIP=""
RESPOND_OVERRIDE=""

RESPOND_MODE="observe"
SCORED_PORTS="22 25 53 80 110 143 443 3306 3389"
ALLOWED_SNIFFERS="dhclient dhcpcd tcpdump wireshark dumpcap tshark NetworkManager systemd-network wpa_supplicant"
ALLOWED_JIT="java node nodejs mysqld mariadbd mono dotnet python3"
ALLOWED_LISTEN_PORTS="22 80 443"
INTERNAL_RESOLVERS=""
LOLBIN_EGRESS="nc ncat socat perl python python3 ruby php bash sh dash zsh"
INTERNAL_EXTRA_CIDRS=""
BASELINE_DIR="/var/lib/btdt-edr"
ALERT_LOG=""
WATCH_INTERVAL=30
DET_RAWSOCK=1 DET_MEMEXEC=1 DET_REVSHELL=1 DET_WRITABLE_EXEC=1 DET_EGRESS=1
DET_LOLBIN_EGRESS=1 DET_HIDDEN_PROC=1 DET_PRELOAD=1 DET_NAT_REDIRECT=1
DET_PERSISTENCE=1 DET_LISTENERS=1 DET_EBPF=1 DET_FIREWALL=1

SELF="$(basename "$0")"
ALERTS_THIS_SWEEP=0
LOG_ENABLED=0

# --------------------------------------------------------------------------
# Arg parsing
# --------------------------------------------------------------------------
usage() { sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }
while [ $# -gt 0 ]; do
  case "$1" in
    -c|--config)   CONFIG="$2"; shift 2 ;;
    -o|--output)   OUTFILE="$2"; shift 2 ;;
    --only)        ONLY="$2"; shift 2 ;;
    --skip)        SKIP="$2"; shift 2 ;;
    --respond)     RESPOND_OVERRIDE="$2"; shift 2 ;;
    --baseline)    MODE_BASELINE=1; shift ;;
    --once)        MODE_ONCE=1; shift ;;
    --watch)       MODE_WATCH=1; shift ;;
    --no-color)    COLOR=0; shift ;;
    --dry-run)     DRYRUN=1; shift ;;
    -h|--help)     usage 0 ;;
    *) echo "unknown arg: $1" >&2; usage 2 ;;
  esac
done

# Load config if present next to the script or at the given path.
if [ -z "$CONFIG" ] && [ -f "$(dirname "$0")/btdt-edr.conf" ]; then
  CONFIG="$(dirname "$0")/btdt-edr.conf"
fi
if [ -n "$CONFIG" ] && [ -f "$CONFIG" ]; then
  # shellcheck disable=SC1090
  . "$CONFIG"
fi
[ -n "$RESPOND_OVERRIDE" ] && RESPOND_MODE="$RESPOND_OVERRIDE"
[ -z "$ALERT_LOG" ] && ALERT_LOG="${BASELINE_DIR}/alerts.jsonl"
# Enable JSONL logging only if we can actually create the dir + file, so we
# never spew redirection errors on a host where /var/lib isn't writable.
if mkdir -p "$BASELINE_DIR" 2>/dev/null && : >>"$ALERT_LOG" 2>/dev/null; then LOG_ENABLED=1; fi
# Default action when no mode flag is given: a single sweep.
[ $MODE_BASELINE -eq 0 ] && [ $MODE_WATCH -eq 0 ] && MODE_ONCE=1

# --------------------------------------------------------------------------
# Output helpers
# --------------------------------------------------------------------------
if [ "$COLOR" = 1 ] && [ -t 1 ]; then
  C_RED=$'\033[1;31m'; C_YEL=$'\033[1;33m'; C_GRN=$'\033[1;32m'
  C_CYN=$'\033[36m'; C_DIM=$'\033[2m'; C_RST=$'\033[0m'
else
  C_RED=""; C_YEL=""; C_GRN=""; C_CYN=""; C_DIM=""; C_RST=""
fi

_ts() { date -u +%Y-%m-%dT%H:%M:%SZ; }
_tee() { [ -n "$OUTFILE" ] && printf '%s\n' "$1" >>"$OUTFILE"; printf '%s\n' "$1"; }

# JSON-escape a string (quotes, backslashes, control chars stripped to spaces).
_json() { printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g' | tr -d '\000-\037'; }

# emit LEVEL CHECK CONFIDENCE MESSAGE  -> colored console line + JSONL record.
emit() {
  local level="$1" check="$2" conf="$3" msg="$4" color="" tag=""
  case "$level" in
    ALERT) color="$C_RED"; tag="ALERT"; ALERTS_THIS_SWEEP=$((ALERTS_THIS_SWEEP+1)) ;;
    WARN)  color="$C_YEL"; tag="WARN " ;;
    OK)    color="$C_GRN"; tag="OK   " ;;
    *)     color="$C_CYN"; tag="INFO " ;;
  esac
  _tee "${color}[${tag}]${C_RST} ${C_DIM}$(_ts)${C_RST} ${C_CYN}${check}${C_RST} ${msg}"
  if [ "$LOG_ENABLED" = 1 ]; then
    printf '{"ts":"%s","host":"%s","level":"%s","check":"%s","confidence":"%s","msg":"%s"}\n' \
      "$(_ts)" "$(hostname 2>/dev/null)" "$level" "$check" "$conf" "$(_json "$msg")" \
      >>"$ALERT_LOG" 2>/dev/null
  fi
}
alert() { emit ALERT "$1" "$2" "$3"; }   # check confidence msg
warn()  { emit WARN  "$1" "$2" "$3"; }
info()  { emit INFO  "$1" low "$2"; }     # check msg

have() { command -v "$1" >/dev/null 2>&1; }
in_list() { local n="$1"; shift; local x; for x in $*; do [ "$x" = "$n" ] && return 0; done; return 1; }

# Is an IPv4/IPv6 address "public" (i.e. worth flagging as egress)?
is_public_ip() {
  local ip="$1"
  case "$ip" in
    127.*|10.*|192.168.*|169.254.*|::1|fe80:*|fc??:*|fd??:*|"") return 1 ;;
    172.1[6-9].*|172.2[0-9].*|172.3[01].*) return 1 ;;
  esac
  local r
  for r in $INTERNAL_RESOLVERS $INTERNAL_EXTRA_CIDRS; do
    case "$ip" in "${r%%/*}"*) return 1 ;; esac
  done
  return 0
}

# --------------------------------------------------------------------------
# Response layer — gated by RESPOND_MODE + confidence. Fail-open on scored ports.
# --------------------------------------------------------------------------
# should_respond CONFIDENCE NEED_MODE -> 0 if we are allowed to act.
should_respond() {
  local conf="$1" need="$2"
  [ "$conf" = "high" ] || return 1          # only ever auto-act on near-zero-FP hits
  case "$RESPOND_MODE:$need" in
    kill:*)                 return 0 ;;
    quarantine:quarantine)  return 0 ;;
    *)                      return 1 ;;
  esac
}
_act() {  # echo intent; run it unless --dry-run
  info respond "would ${DRYRUN:+(dry-run) }$*"
  [ "$DRYRUN" = 1 ] && return 0
  "$@" >/dev/null 2>&1
}
# Confirmation that an action actually happened — silent in dry-run so we never
# claim to have contained something we only simulated.
contained() { [ "$DRYRUN" = 1 ] || emit WARN respond high "$1"; }
resp_kill() {  # pid comm
  should_respond high kill || return 0
  _act kill -9 "$1"; _act pkill -9 -P "$1"
  contained "contained: killed pid $1 ($2)"
}
resp_quarantine_file() {  # path
  should_respond high quarantine || return 0
  local q="${BASELINE_DIR}/quarantine"; mkdir -p "$q" 2>/dev/null
  _act chattr -i "$1"; _act mv "$1" "$q/"; _act chmod 000 "$q/$(basename "$1")"
  contained "contained: quarantined $1 -> $q/"
}
resp_sever() {  # ip port  (never severs a flow serving a scored port)
  should_respond high quarantine || return 0
  in_list "$2" "$SCORED_PORTS" && { info respond "refusing to sever scored port $2 (fail-open)"; return 0; }
  have ss && _act ss -K dst "$1" dport = "$2"
  contained "contained: severed socket to $1:$2"
}

# --------------------------------------------------------------------------
# Baseline capture (T0). Cheap, deterministic snapshots for the diff checks.
# --------------------------------------------------------------------------
_persist_fileset() {
  find /etc/crontab /etc/anacrontab /etc/rc.local /etc/ld.so.preload \
       /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly \
       /var/spool/cron /etc/systemd/system \
       /root/.ssh /home/*/.ssh /etc/passwd /etc/shadow /etc/sudoers /etc/sudoers.d \
       -type f \( -name '*.service' -o -name 'authorized_keys*' -o -path '*/cron*' \
       -o -name crontab -o -name anacrontab -o -name rc.local -o -name ld.so.preload \
       -o -name passwd -o -name shadow -o -name sudoers -o -path '*/sudoers.d/*' \) \
       2>/dev/null | sort -u
}
do_baseline() {
  mkdir -p "$BASELINE_DIR" 2>/dev/null || { echo "cannot create $BASELINE_DIR" >&2; exit 1; }
  info baseline "capturing T0 baseline into $BASELINE_DIR"
  # Persistence: hash every file in the fileset.
  _persist_fileset | xargs -r sha256sum 2>/dev/null | sort -k2 > "$BASELINE_DIR/persist.sha"
  # Listeners.
  ( have ss && ss -tulnpH || netstat -tulnp 2>/dev/null ) 2>/dev/null \
      | awk '{print $5}' | sort -u > "$BASELINE_DIR/listeners.txt"
  # eBPF/XDP programs.
  ( have bpftool && bpftool prog show 2>/dev/null ) | sort > "$BASELINE_DIR/ebpf.txt"
  # Firewall ruleset (for tamper detection + restore).
  ( have iptables-save && iptables-save || iptables -S 2>/dev/null ) > "$BASELINE_DIR/fw.rules" 2>/dev/null
  iptables -S 2>/dev/null | grep -E '^-P ' | sort > "$BASELINE_DIR/fw.policy" 2>/dev/null
  emit OK baseline low "baseline captured ($(wc -l <"$BASELINE_DIR/persist.sha" 2>/dev/null || echo 0) persistence files tracked)"
}

# --------------------------------------------------------------------------
# Detections
# --------------------------------------------------------------------------

# Map socket inode -> pid once per sweep for the socket-based checks.
declare -A SOCK2PID
build_sock_map() {
  SOCK2PID=()
  local fd tgt ino pid
  for fd in /proc/[0-9]*/fd/*; do
    tgt=$(readlink "$fd" 2>/dev/null) || continue
    case "$tgt" in socket:\[*\]) ino=${tgt#socket:[}; ino=${ino%]} ;; *) continue ;; esac
    pid=${fd#/proc/}; pid=${pid%%/fd/*}
    SOCK2PID[$ino]="$pid"
  done
}

det_rawsock() {   # AF_PACKET sniff-shell (watershell / BPFdoor class)
  ip -o link 2>/dev/null | grep -iq promisc && \
    warn rawsock med "promiscuous interface active: $(ip -o link | grep -i promisc | awk -F': ' '{print $2}' | tr '\n' ' ')"
  [ -r /proc/net/packet ] || { info rawsock "/proc/net/packet unreadable (need root)"; return; }
  local ino pid comm
  while read -r ino; do
    pid="${SOCK2PID[$ino]:-}"; [ -n "$pid" ] || continue
    comm=$(cat "/proc/$pid/comm" 2>/dev/null)
    if ! in_list "$comm" "$ALLOWED_SNIFFERS"; then
      alert rawsock high "raw AF_PACKET socket held by non-allowlisted process pid=$pid comm=$comm (sniff-shell / packet-triggered C2)"
      resp_kill "$pid" "$comm"
    fi
  done < <(awk 'NR>1{print $NF}' /proc/net/packet 2>/dev/null | sort -u)
}

det_memexec() {   # fileless execution + reflective/injected code
  local p e
  for p in /proc/[0-9]*; do
    e=$(readlink "$p/exe" 2>/dev/null) || continue
    case "$e" in
      *memfd:*)   alert memexec high "process running from anonymous memory (memfd) ${p##*/} -> $e"; resp_kill "${p##*/}" memfd ;;
      *"(deleted)") alert memexec high "process running a deleted binary (self-delete dropper) ${p##*/} -> $e"; resp_kill "${p##*/}" deleted ;;
    esac
  done
  # RWX anonymous mappings (reflective loaders / injected shellcode), JIT-excluded.
  for p in /proc/[0-9]*; do
    comm=$(cat "$p/comm" 2>/dev/null); in_list "$comm" "$ALLOWED_JIT" && continue
    if awk '$2 ~ /rwx/ && NF==5{f=1} END{exit !f}' "$p/maps" 2>/dev/null; then
      warn memexec med "RWX anonymous memory in pid ${p##*/} ($comm) — possible reflective/injected code"
    fi
  done
}

det_revshell() {  # a shell whose stdio is a socket == reverse shell
  local p comm fd tgt
  for p in /proc/[0-9]*; do
    comm=$(cat "$p/comm" 2>/dev/null)
    case "$comm" in bash|sh|dash|zsh|ash|ksh) ;; *) continue ;; esac
    for fd in 0 1 2; do
      tgt=$(readlink "$p/fd/$fd" 2>/dev/null) || continue
      case "$tgt" in socket:\[*\])
        alert revshell high "interactive shell with a socket on fd$fd (reverse shell) pid=${p##*/} comm=$comm"
        resp_kill "${p##*/}" "$comm"; break ;;
      esac
    done
  done
}

det_writable_exec() {  # process image living in a world-writable dir
  local p e
  for p in /proc/[0-9]*; do
    e=$(readlink "$p/exe" 2>/dev/null) || continue
    case "$e" in
      /tmp/*|/dev/shm/*|/var/tmp/*|/run/shm/*)
        warn writable_exec med "process running from writable path ${p##*/} -> $e" ;;
    esac
  done
}

# Shared egress walker: for each outbound socket, hand (pid,comm,exe,ip,port) to cb.
_walk_egress() {
  local cb="$1" line peer ip port procf pid comm exe
  have ss || { info egress "ss missing"; return; }
  while read -r line; do
    peer=$(awk '{print $5}' <<<"$line")
    port=${peer##*:}; ip=${peer%:*}; ip=${ip#[}; ip=${ip%]}
    is_public_ip "$ip" || continue
    procf=$(grep -oE 'pid=[0-9]+' <<<"$line" | head -1); pid=${procf#pid=}
    [ -n "$pid" ] || continue
    comm=$(cat "/proc/$pid/comm" 2>/dev/null)
    exe=$(readlink "/proc/$pid/exe" 2>/dev/null)
    "$cb" "$pid" "$comm" "$exe" "$ip" "$port"
  done < <(ss -tnpH state established state syn-sent 2>/dev/null)
}

det_egress() {    # outbound by a temp-path / non-package binary (beats IP rotation)
  _cb() {
    local pid="$1" comm="$2" exe="$3" ip="$4" port="$5" owned=""
    case "$exe" in
      /tmp/*|/dev/shm/*|/var/tmp/*|/run/shm/*)
        alert egress high "outbound to $ip:$port from binary in a writable path: pid=$pid comm=$comm exe=$exe"
        resp_sever "$ip" "$port"; return ;;
    esac
    if have dpkg && ! dpkg -S "$exe" >/dev/null 2>&1 && [ -n "$exe" ]; then owned=1; fi
    if have rpm && ! rpm -qf "$exe" >/dev/null 2>&1 && [ -n "$exe" ]; then owned=1; fi
    [ -n "$owned" ] && warn egress med "outbound to $ip:$port from non-package binary pid=$pid comm=$comm exe=$exe"
  }
  _walk_egress _cb
}

det_lolbin_egress() {   # interpreter / LOLBin holding an outbound socket
  _cb() {
    local pid="$1" comm="$2" exe="$3" ip="$4" port="$5"
    in_list "$comm" "$LOLBIN_EGRESS" && {
      alert lolbin_egress high "LOLBin/interpreter with outbound connection: $comm -> $ip:$port (pid=$pid)"
      resp_sever "$ip" "$port"; }
  }
  _walk_egress _cb
}

det_hidden_proc() {   # LKM/eBPF rootkit hiding a PID from /proc
  local t; t=$(cat /proc/sys/kernel/tainted 2>/dev/null || echo 0)
  [ "${t:-0}" -gt 0 ] 2>/dev/null && warn hidden_proc med "kernel taint flag = $t (out-of-tree/unsigned module loaded — corroborating, not proof)"
  lsmod 2>/dev/null | grep -iE 'diamorphine|reptile|kbeast|azazel|jynx|beurk|sutekh|rootkit' \
    && alert hidden_proc high "known rootkit LKM name present in lsmod"
  local pid max=65536
  for ((pid=1; pid<=max; pid++)); do
    if kill -0 "$pid" 2>/dev/null && [ ! -d "/proc/$pid" ]; then
      # Re-verify to avoid a process-exit race.
      sleep 0 2>/dev/null
      kill -0 "$pid" 2>/dev/null && [ ! -d "/proc/$pid" ] && \
        alert hidden_proc high "hidden PID $pid: alive to the kernel but absent from /proc (rootkit)"
    fi
  done
}

det_preload() {   # LD_PRELOAD userland hooks
  if [ -s /etc/ld.so.preload ]; then
    alert preload high "/etc/ld.so.preload is non-empty: $(tr '\n' ' ' </etc/ld.so.preload)"
  fi
  local p ev
  # Use `cat ... 2>/dev/null` (not `<"$p"`): /proc/PID/environ can pass a -r test
  # yet still be denied by the kernel ptrace check, and a shell redirection error
  # would leak to stderr. Letting cat own the failed open keeps output clean.
  for p in /proc/[0-9]*/environ; do
    ev=$(cat "$p" 2>/dev/null | tr '\0' '\n' | grep '^LD_PRELOAD=') || continue
    [ -n "$ev" ] && warn preload med "${p%/environ} has $ev in its environment"
  done
}

det_nat_redirect() {   # BPFdoor-style port piggyback
  have iptables || { info nat_redirect "iptables missing"; return; }
  local r
  while read -r r; do
    [ -n "$r" ] && warn nat_redirect med "PREROUTING redirect/DNAT rule (port-piggyback C2 if this host is not a NAT gateway): $r"
  done < <(iptables -t nat -S PREROUTING 2>/dev/null | grep -iE 'REDIRECT|DNAT')
  have nft && nft list ruleset 2>/dev/null | grep -iqE 'redirect|dnat' && \
    warn nat_redirect med "nftables ruleset contains redirect/dnat — verify this host should be doing NAT"
}

det_persistence() {   # diff cron/systemd/ssh-keys/preload vs T0 baseline
  local base="$BASELINE_DIR/persist.sha"
  [ -f "$base" ] || { info persistence "no baseline yet — run --baseline at T0"; return; }
  local cur kind path; cur=$(mktemp)
  _persist_fileset | xargs -r sha256sum 2>/dev/null | sort -k2 > "$cur"
  # Compare (hash path) sets by path.
  while read -r kind path; do
    case "$kind" in
      NEW) alert persistence high "new persistence file since T0: $path" ;;
      MOD) alert persistence high "persistence file modified since T0: $path" ;;
      DEL) warn  persistence med  "tracked file removed since T0: $path" ;;
    esac
  done < <(awk 'NR==FNR{b[$2]=$1; next}
       { if(!($2 in b)) print "NEW " $2;
         else if(b[$2]!=$1) print "MOD " $2;
         seen[$2]=1 }
       END{ for(p in b) if(!(p in seen)) print "DEL " p }' "$base" "$cur")
  rm -f "$cur"
}

det_listeners() {   # unexpected listening ports
  have ss || return
  local line laddr port pid comm
  while read -r line; do
    laddr=$(awk '{print $4}' <<<"$line"); port=${laddr##*:}
    in_list "$port" "$ALLOWED_LISTEN_PORTS" && continue
    pid=$(grep -oE 'pid=[0-9]+' <<<"$line" | head -1); pid=${pid#pid=}
    comm=$(cat "/proc/$pid/comm" 2>/dev/null)
    warn listeners med "unexpected listener on port $port (pid=$pid comm=$comm)"
  done < <(ss -tlnpH 2>/dev/null)
}

det_ebpf() {   # enumerate loaded eBPF/XDP vs baseline (advisory — legit users exist)
  have bpftool || { info ebpf "bpftool missing (install linux-tools for eBPF visibility)"; return; }
  local base="$BASELINE_DIR/ebpf.txt" cur; cur=$(mktemp)
  bpftool prog show 2>/dev/null | sort > "$cur"
  bpftool prog show 2>/dev/null | grep -iE 'kprobe|tracepoint|lsm|fentry|fexit' \
    && warn ebpf med "syscall-hooking eBPF program loaded (kprobe/tracepoint/lsm/fentry) — confirm it is yours"
  if [ -f "$base" ] && ! diff -q "$base" "$cur" >/dev/null 2>&1; then
    warn ebpf med "loaded eBPF program set changed since T0 baseline"
  fi
  ip -o link show 2>/dev/null | grep -iq xdp && warn ebpf med "XDP program attached to an interface — confirm it is yours"
  rm -f "$cur"
}

det_firewall() {   # egress firewall flushed / policy flipped open
  have iptables || return
  local basep="$BASELINE_DIR/fw.policy"
  [ -f "$basep" ] || { info firewall "no firewall baseline — run --baseline after you set your ruleset"; return; }
  local nowp; nowp=$(iptables -S 2>/dev/null | grep -E '^-P ' | sort)
  if [ "$nowp" != "$(cat "$basep")" ]; then
    alert firewall high "firewall default policy changed since T0 (possible T1562.004 egress-freeing tamper)"
    if should_respond high kill && [ -f "$BASELINE_DIR/fw.rules" ]; then
      have iptables-restore && _act sh -c "iptables-restore < '$BASELINE_DIR/fw.rules'"
      contained "contained: restored firewall from baseline"
    fi
  fi
}

# --------------------------------------------------------------------------
# Sweep driver
# --------------------------------------------------------------------------
enabled() {  # name toggle
  local name="$1" toggle="$2"
  [ "$toggle" = 1 ] || return 1
  [ -n "$ONLY" ] && { in_list "$name" "$(echo "$ONLY" | tr ',' ' ')" || return 1; }
  [ -n "$SKIP" ] && { in_list "$name" "$(echo "$SKIP" | tr ',' ' ')" && return 1; }
  return 0
}

sweep() {
  ALERTS_THIS_SWEEP=0
  build_sock_map
  enabled rawsock        "$DET_RAWSOCK"        && det_rawsock
  enabled memexec        "$DET_MEMEXEC"        && det_memexec
  enabled revshell       "$DET_REVSHELL"       && det_revshell
  enabled writable_exec  "$DET_WRITABLE_EXEC"  && det_writable_exec
  enabled egress         "$DET_EGRESS"         && det_egress
  enabled lolbin_egress  "$DET_LOLBIN_EGRESS"  && det_lolbin_egress
  enabled hidden_proc    "$DET_HIDDEN_PROC"    && det_hidden_proc
  enabled preload        "$DET_PRELOAD"        && det_preload
  enabled nat_redirect   "$DET_NAT_REDIRECT"   && det_nat_redirect
  enabled persistence    "$DET_PERSISTENCE"    && det_persistence
  enabled listeners      "$DET_LISTENERS"      && det_listeners
  enabled ebpf           "$DET_EBPF"           && det_ebpf
  enabled firewall       "$DET_FIREWALL"       && det_firewall
}

main() {
  if [ "$(id -u)" != 0 ]; then
    warn init low "not running as root — /proc, socket-owner and firewall checks will be degraded"
  fi
  info init "btdt-edr $SELF | mode=$([ $MODE_WATCH = 1 ] && echo watch || echo once) respond=$RESPOND_MODE dry-run=$DRYRUN"

  if [ $MODE_BASELINE -eq 1 ]; then do_baseline; [ $MODE_WATCH -eq 0 ] && [ $MODE_ONCE -eq 0 ] && exit 0; fi

  if [ $MODE_WATCH -eq 1 ]; then
    trap 'echo; info init "stopped"; exit 0' INT TERM
    while :; do
      sweep
      [ $ALERTS_THIS_SWEEP -gt 0 ] && emit WARN sweep low "sweep complete: $ALERTS_THIS_SWEEP alert(s)" \
                                   || emit OK   sweep low "sweep complete: clean"
      sleep "$WATCH_INTERVAL"
    done
  else
    sweep
    if [ $ALERTS_THIS_SWEEP -gt 0 ]; then
      _tee "Summary: ${C_RED}${ALERTS_THIS_SWEEP} ALERT${C_RST}"
      exit 1
    fi
    _tee "Summary: ${C_GRN}clean${C_RST}"
    exit 0
  fi
}
main
