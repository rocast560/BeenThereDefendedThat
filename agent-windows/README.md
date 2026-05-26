# agent-windows

Windows endpoint agent — **Go + ETW + Sysmon** (incl. Domain Controller role).

**Responsibilities** (see root `README.md` §5.2):
- Telemetry: Sysmon (olafhartong `sysmon-modular` balanced base) via ETW real-time consumer; ETW providers for DNS-Client, WinINet/WinHTTP, PowerShell 4104, WMI-Activity; AMSI provider DLL.
- DC pipeline: WEC/WEF (Palantir cookbook) forwarding Security log (4662/4769/4768/5136/4624/5145).
- Active response: `taskkill`, `Stop-Service`, `Disable-LocalUser`, WFP `-Program` egress rules, VSS snapshot revert.
- Tamper protection: `LocalSystem` service + `sc sdset` deny Stop/Delete to non-SYSTEM.

**Status:** scaffold only — no code yet.
