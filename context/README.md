# BTDT Context

Reference material for **BeenThereDefendedThat (BTDT)** — an agent-based blue-team
EDR built for CCDC-style competitions. This directory holds the research, design,
and detection knowledge the tool is built from. The runnable checks that these
docs reference live in the [`ccdc-audit`](../../Competition-Playbook/ccdc-audit/) toolkit.

## Layout

### `design/`
- [detection-tool-design.md](design/detection-tool-design.md) — the core
  architecture and design spec for BTDT: goals/non-goals, telemetry pipeline,
  detections, and automated active response. *(Encoded UTF-16.)*

### `research/`
- [egress_bypass_edr_ccdc.md](research/egress_bypass_edr_ccdc.md) — threat model of
  how CCDC red teams push traffic out of a locked-down network, mapped to MITRE
  ATT&CK and to concrete EDR detection opportunities.
- [deep-research-2026-07-18-btdt-gaps.md](research/deep-research-2026-07-18-btdt-gaps.md)
  — adversarially-verified research report closing six BTDT design gaps
  (control-plane HA/failover, and more).

### `runbooks/`
- [implant-detection.md](runbooks/implant-detection.md) — detecting implant
  binaries (Sliver, Meterpreter, Havoc, Mythic, Cobalt Strike, custom droppers)
  with the primitives commercial EDRs use.
- [custom-implant-detection.md](runbooks/custom-implant-detection.md) — advanced
  runbook for implants that defeat signatures/JA3/YARA: raw-packet sniff-shells,
  port-piggyback C2, eBPF/XDP covert channels, fileless/injected code, and
  hidden-PID rootkits.

### `samples/`
- [watershell/](samples/watershell/) — sample raw-packet "sniff-shell" C2 implant,
  used as a detection target throughout the runbooks.
