# Lean v0 Plan — Competition-Ready Fallback

**Problem.** The full custom build in root `README.md` §12 is a realistic ~9-week effort (Go + eBPF + ETW + gRPC + Redpanda + OpenSearch + MinIO). Tryouts / the competition may land **before** that's done. A half-built custom agent defends nothing.

**Strategy.** Stand up a **competition-ready defensive capability now** using proven open-source tooling, and build the custom stack **in parallel**. v0 is not throwaway — most of it (Sigma rules, YARA packs, the Ansible hardening, network detection, the C2 catalog) is reused verbatim by the custom build. Only the *agent* and *central server* get replaced.

> **Decision rule:** if the next scored event is **< ~6 weeks out**, freeze custom-agent scope and ship v0 first. Cut over component-by-component as the custom pieces pass a mock engagement.

---

## v0 = off-the-shelf OSS mapped onto the README's goals

| README goal | v0 (ship now) | Custom build adds later |
|---|---|---|
| Endpoint telemetry | **Wazuh agent** (Linux+Windows) + **Sysmon** (`sysmon-modular`) + **osquery** | Go+eBPF / ETW agent: in-kernel filtering, `lineage_id` correlation, tamper-resistance |
| Central ingest/store/search | **Wazuh manager** (XDR+SIEM out of the box) — ingest, storage, dashboards, alerting | Custom gRPC server + Redpanda + OpenSearch + MinIO (replay, own alert→action path) |
| IR / live hunt | **Velociraptor** (hunt + collect across all hosts; can deploy osquery) | Folded into the custom agent's collect command |
| Network detection | **Zeek + Suricata + RITA** on a choke; abuse.ch SSLBL JA3 ruleset | Same — reused as-is |
| Detection content | **SigmaHQ** rules + **YARA** packs + README §7 Tier-S/A C2 signatures | Same content, compiled to custom ES|QL runtime + stateful IOAs |
| Active response | **Wazuh Active Response** (scripted kill/quarantine/firewall) | In-kernel `SIGKILL`, signed command channel, VSS rollback, sub-second |
| Binary-bound egress | **Ansible**-pushed nftables + WFP `-Program` rules (achievable today!) | eBPF LSM `socket_connect` enforcement (faster, harder to revert) |
| Hardening | **Ansible** `konstruktoid.hardening` + `devsec.hardening` + README §9 plays | Same — reused as-is |

**Key insight:** the IP-rotation killshot — egress keyed by binary, not IP — does **not** require the custom agent. Ansible can push WFP `-Program` allow rules (Windows) and nftables default-deny (Linux) on day one. The custom eBPF LSM version is faster and harder for an admin-level attacker to revert, but v0 already gets the core behavior.

---

## v0 First-15-Minutes Runbook (OSS only)

1. **Push telemetry:** Wazuh agents already enrolled; deploy Sysmon (`sysmon-modular` balanced) + enable PowerShell 4104 + WFP 5156 via the Ansible play.
2. **Sweep:** Velociraptor hunt + YARA (Elastic + Neo23x0 + GCTI) against memory and disk on every host.
3. **Harden (Ansible, all hosts at once):** default-deny egress (nftables + WFP `-Program`), rotate creds, disable non-allowlisted services, snapshot `/etc` + registry/GPO baseline, lock cron/systemd, strip SUID.
4. **Network:** stand up Zeek+Suricata on the choke if available; load JA3 + `application/grpc` rules; point RITA at Zeek logs for beacon scoring.
5. **Kill existing connections:** when default-deny lands, drop ESTABLISHED/RELATED to non-allowlisted dests + flush conntrack (a new rule alone won't sever a live beacon).

---

## v0 Gaps vs. custom build (know what you're trading)

- **Response speed/granularity:** Wazuh Active Response (script-driven) is slower and coarser than in-kernel `bpf_send_signal(SIGKILL)`.
- **Tamper-resistance:** Wazuh/Sysmon agents are easier for an admin-level attacker to stop than the planned `sc sdset`-protected custom service.
- **Correlation:** no on-agent `lineage_id`; you lean on Wazuh's server-side correlation + manual pivoting.
- **Unified channel:** multiple tools instead of one gRPC stream → more to manage, more moving parts to keep alive.

These gaps are exactly what the custom build closes — which is why v0 and the 9-week plan are complementary, not either/or.

---

## Carry-over guardrails (from the review)

- **Do no harm to scored services.** Every auto-response (egress flip, isolate, kill, persistence delete) must respect a hard scored-service allowlist and must never block the scoring engine's checks. Gate destructive actions behind human confirmation until baselines are validated.
- **Single-box risk.** Don't co-locate the Ansible control node with the detection server; keep management out-of-band.
- **Validate signatures.** Treat JA3/default-config IOCs as the cheap Day-1 layer; re-validate against current tool versions and prefer JA4+. Behavioral detection (beacon timing, process-network, named-pipe anomaly) is the durable layer.

---

## Migration path (v0 → custom)

1. Custom **proto + gRPC server** stands up beside Wazuh; agents dual-ship during transition.
2. Custom **Linux agent** replaces Wazuh+Sysmon-for-Linux once it passes a mock engagement (Sliver/Havoc in a lab).
3. Custom **Windows agent** replaces the Wazuh agent (Sysmon stays as a telemetry source either way).
4. Detection content (Sigma/YARA) and Ansible hardening **never change** — they're the stable core across both.
