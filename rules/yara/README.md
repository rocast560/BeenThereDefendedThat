# rules/yara

YARA rules for C2 family detection — run against in-memory dumps and file events by the server's YARA worker and on scheduled host sweeps. See root `README.md` §7.

**Sourcing:**
- Elastic `protections-artifacts` (Windows_Trojan_CobaltStrike, _Havoc, _Mythic, Linux_Trojan_Poseidon).
- Neo23x0 `signature-base` (Meterpreter, Empire).
- Chronicle GCTI (Sliver `Sliver__Implant_64bit.yara`).
- Our own packs for families with no public coverage yet (AdaptixC2, Realm/Spellshift imix).

**Convention:** upstream packs under `vendor/`, our rules under `custom/`.

**Status:** scaffold only — no rules vendored yet.
