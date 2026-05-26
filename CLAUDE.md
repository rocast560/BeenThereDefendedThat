# BeenThereDefendedThat — Agent Instructions

Shared context for everyone working this repo with Claude Code. **Two people are developing here in parallel, both using Claude** — so the coordination rules below are not optional.

## What this is

An opinionated, **agent-based EDR for the Collegiate Cyber Defense Competition (CCDC)** and CCDC-style tryouts. Defensive blue-team tooling only. Not a general-purpose XDR. The design is shaped by three CCDC realities: pre-compromise is assumed, the wire rotates IPs, and the scored window is short.

## Read first (before proposing changes)

1. `README.md` — full system design (architecture, agents, server, C2 catalog, response, Ansible, AD detections, phased build plan).
2. `docs/lean-v0-plan.md` — the competition-ready OSS fallback (Wazuh+Sysmon+Velociraptor+Sigma+Ansible) and the migration path to the custom build.
3. `egress_bypass_edr_ccdc.md` — egress-evasion threat model + tiered detection stack.

## Repo layout

| Dir | Contents |
|---|---|
| `agent-linux/` | Go + eBPF endpoint agent (Linux) |
| `agent-windows/` | Go + ETW + Sysmon endpoint agent (Windows, incl. DC) |
| `server/` | Central server: gRPC ingest, detection runtime, response orchestrator |
| `proto/` | Shared Protobuf schema (ECS-shaped events) |
| `ansible/` | Hardening + response playbooks (default-deny egress, persistence sweep) |
| `rules/sigma/`, `rules/yara/` | Detection content (`vendor/` upstream, `custom/` ours) |
| `deploy/` | docker-compose stack, cert generator, install scripts |
| `docs/` | Plans and design notes |

**Status:** design phase — scaffold only, no application code yet.

## Conventions

- **Language:** Go for agents and server (single static binary, no runtime deps — no Python/JRE on hosts).
- **Wire:** gRPC bidi over mTLS (pinned CA); Protobuf events use **Elastic Common Schema (ECS)** field names so detection content ports to Sigma/Elastic.
- **Detection content:** keep upstream rules unmodified under `vendor/`; our edits/new rules under `custom/`.
- **Docs:** UTF-8, LF line endings. (The README was originally saved as UTF-16 from PowerShell — use `Set-Content -Encoding utf8` / `Out-File -Encoding utf8`.)

## Guardrails (do not violate)

- **Authorized-use only.** This is for CCDC / sanctioned tryouts / your own lab. Detection signatures reference C2 frameworks as *things to detect*, never to deploy.
- **Never auto-respond into a scored-service outage.** Every destructive action (egress flip, isolate, kill, persistence delete, group revert) must respect a hard scored-service allowlist and must never block the scoring engine's checks. Gate destructive actions behind human confirmation until baselines are validated.
- **Keep management out-of-band.** Don't co-locate the Ansible control node with anything the red team can reach from a scored host.

## Workflow — REQUIRED for two-Claude coordination

- **One issue = one task.** Before starting work, **claim the GitHub issue** (assign yourself / comment) so the other person's Claude doesn't grab the same thing. `gh issue view <n>` to load context.
- **Branch per task**, namespaced per person: `anderson/<short-desc>`, `<partner>/<short-desc>`. Branch off `main`.
- **Never commit directly to `main`.** Open a **PR** and get a review (or the agreed owner merges). Keep PRs small and single-purpose.
- **Don't edit the same files in parallel.** If two tasks touch the same file, sequence them or coordinate in the issue.
- End commit messages with: `Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>`

## Build / test

None yet (scaffold stage). Add commands here as `deploy/`, agents, and server get real code.
