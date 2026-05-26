# ansible

Pre-emptive hardening + response playbooks — the "don't let them call home" layer. See root `README.md` §9.

**Planned roles/plays:**
- First-15-minutes hardening (every host): rotate local creds, disable non-allowlisted services, snapshot `/etc` + registry/GPO, strip SUID, lock cron/systemd dirs.
- **Default-deny egress:** nftables (Linux) + WFP `-Program` rules (Windows) — egress keyed by `(binary, dst port, proto)`, not IP. This is the IP-rotation killshot and is achievable here **without** the custom agent.
- Persistence sweep timer (60s diff vs T0 baseline).
- Auto-revert privileged AD group membership to baseline.

**Base roles:** `konstruktoid.hardening` + `devsec.hardening` + our custom role.

**Guardrail (review finding):** egress allowlist MUST include scored-service inbound + the scoring engine's checks. Gate destructive plays behind confirmation until baselines are validated.

**Status:** scaffold only — no playbooks yet.
