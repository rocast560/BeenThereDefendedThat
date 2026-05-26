# agent-linux

Linux endpoint agent — **Go + eBPF** (single static binary, no runtime deps).

**Responsibilities** (see root `README.md` §5.1):
- Telemetry: eBPF tracepoints/kprobes (`sched_process_exec`, `tcp_connect`, module load, ptrace) + LSM file-integrity hooks; embedded `osquery` for periodic state; `auditd` fallback for old kernels.
- On-agent correlation: tag every event in a process subtree with a `lineage_id` (UUIDv7).
- Active response: in-kernel `bpf_send_signal(SIGKILL)`, binary-bound egress enforcement at `socket_connect`.

**Status:** scaffold only — no code yet.
