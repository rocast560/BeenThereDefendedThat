# rules/sigma

Sigma detection rules (SigmaHQ upstream + our custom rules), compiled to OpenSearch ES|QL by the detection runtime. See root `README.md` §6.2 and the C2 catalog in §7.

**Sourcing:**
- Vendored SigmaHQ packs for the Tier-S / Tier-A C2 families (Cobalt Strike named pipes, Sliver, Meterpreter, Empire, Mythic).
- Custom stateful IOAs that can't be expressed in stock Sigma (e.g., `winword→powershell→net` within 30s; `application/grpc` egress from a non-dev host).
- AD detection pack (§10): DCSync 4662, Kerberoasting 4769 RC4, AS-REP 4768, GPO tamper 5136.

**Convention:** keep upstream rules unmodified under `vendor/`; put our edits/new rules under `custom/`.

**Status:** scaffold only — no rules vendored yet.
