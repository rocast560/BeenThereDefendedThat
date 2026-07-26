# BTDT Deep-Research Report — Closing the Six Design Gaps

**Date:** 2026-07-18
**Project:** BeenThereDefendedThat (BTDT) — agent-based blue-team EDR for CCDC 2026
**Method:** Fan-out web search across 6 angles → 25 sources → 113 extracted claims → 3-vote adversarial verification → 20 confirmed claims. Vote margins shown as `[N-M]` (refute votes; a claim needs 2/3 refutes to be killed).

> Two layers below: **Verified** = survived adversarial fact-checking, with source. **Recommendation** = my engineering judgment applied to your BTDT baseline (Go agents, gRPC/mTLS, eBPF+Sysmon, Redpanda/OpenSearch/Postgres/MinIO, Sigma+YARA, Ansible, identity-by-process-lineage). Where verified evidence was thin, I say so.

---

## Gap 1 — Control-plane HA / failover on assumed-compromised hosts

**Verified:**
- `hashicorp/raft` is a production Go library implementing Raft consensus for Consistent-Partition-tolerant (CP) systems — a reusable building block, so you don't write consensus yourself. `[3-0]` — https://github.com/hashicorp/raft
- A **3-node Raft cluster tolerates 1 failure; 5-node tolerates 2**. Recommended sizes are 3 or 5. `[3-0]` — https://github.com/hashicorp/raft
- **Standard Raft is only crash-fault-tolerant (CFT), NOT Byzantine-fault-tolerant** — a malicious/compromised node breaks its guarantees. Research proposes adding a trust/reputation layer for hostile environments. `[3-0]` — https://arxiv.org/html/2607.08666v1
- HashiCorp Consul **separates gossip (Serf/memberlist/SWIM) from Raft**: the gossip layer keeps working (membership + failure detection) even when Raft can't form quorum. `[3-0]` — https://www.hashicorp.com/en/resources/everybody-talks-gossip-serf-memberlist-raft-swim-hashicorp-consul
- Raft **prevents split-brain** by treating the log as source of truth: it refuses to elect a leader whose log is inconsistent. `[2-1]` — same source
- Serf gossip **tolerates partitions** by distinguishing transient failures (`EventMemberFailed` after failed direct+indirect probes) from confirmed departures (`EventMemberReap` after timeout) — no immediate ejection. `[3-0]` — https://cefboud.com/posts/distributed-system-kafka-raft-serf/
- Gossip propagation lets a node learn membership **indirectly** (A learns of C via B even if A can't reach C), so partial connectivity doesn't blind the cluster. `[3-0]` — same source

**Recommendation for BTDT:**
- Embed `hashicorp/raft` **directly in your Go agent binary**. Every agent ships the server code; 3–5 designated agents form the control-plane quorum. If the leader host is shut down or owned, Raft auto-elects a new leader from the remaining nodes — this *is* your "pop the server up on another machine" story, with no manual intervention.
- Run **gossip (memberlist/SWIM) as a separate plane** from Raft, exactly as Consul does. Fleet liveness and "who's alive" survives even when quorum is lost — so you keep situational awareness during the worst moments.
- **Confront the Byzantine gap head-on.** Your threat model says hosts are pre-compromised, and Raft trusts its leader. A compromised leader can push false state or malicious commands. Mitigations: (1) **sign every operator command** with an offline key held by the human blue-teamer — agents execute only signed commands, so a rogue leader can't forge actions; (2) keep mTLS identity per node so a wiped/reinstalled host can't silently rejoin; (3) treat Raft as availability infrastructure, not as a trust root. Don't rely on a reputation layer you'd have to build under time pressure — the signed-command approach is simpler and stronger for a competition.
- Store durable state (detections, evidence) in your existing Postgres/OpenSearch; use Raft only for small, fast control state (fleet config, active response policy, leader identity).

---

## Gap 2 — Keeping scored services reachable when scorer AND attacker rotate IPs

This is the highest-value finding set — it overturns the naive approach.

**Verified:**
- **You cannot whitelist the scorer by IP.** The Locked Shields scoring server *deliberately randomizes its own public IPs every 5–10 minutes* precisely to defeat blue-team firewall whitelisting. `[3-0]` — https://ccdcoe.org/uploads/2020/02/M_Pihelgas_-_Design_and_Implementation_of_an_Availability_Scoring_System_for_Cyber_Defence_Exercises.pdf
- **Why they do it:** the whitelisting attack — if defenders identify the scorer's source IPs, they can allow only the scorer and block everyone else; the scoreboard shows "up" while no real user can reach the service. Scoring engines rotate to detect/punish exactly this. `[3-0]` — same source
- In CCDC, **a firewall that blocks the scoring engine costs the same as the service being down** — so rules must be verified against scoring-engine reachability *before* switching to default-deny. `[3-0]` — https://howtowinccdc.com/
- **Service Availability is ~50% of the total score**, polled by an automated engine over HTTP, HTTPS, DNS, SMTP, POP3, and OT protocols like Modbus. `[2-1]` — https://howtowinccdc.com/

**Recommendation for BTDT:**
- **Discriminate at the application/protocol layer, not by IP.** Since both scorer and attacker rotate IPs on the same ports, source IP carries no signal. Front each scored service with a reverse proxy / L7 filter (nginx/Envoy/HAProxy or your own Go proxy) that admits **protocol-conformant, well-formed requests** and drops malformed/exploit-shaped traffic. A scorer's HTTP GET to `/` looks like a normal request; a webshell POST or SQLi payload does not.
- **Fail open, never fail closed, on the scored path.** Given that blocking the scorer = losing the points anyway, BTDT's automated response must be *incapable* of dropping a legitimate service check. Default posture on scored ports: allow protocol-valid traffic; quarantine only on high-confidence malicious signatures. Put the aggressive default-deny on *non-scored* management surfaces instead.
- **Behavioral heuristics that survive IP rotation:** rate/volume anomalies, request-shape entropy, session/state conformance (does this "client" complete a real protocol handshake or just spray?), and correlation with host-side telemetry (did this connection spawn a shell? that's the eBPF/Sysmon signal, and it's IP-independent — consistent with your identity-by-process-lineage design).
- **Instrument the scoring path.** Log every request to scored services and tag which ones you dropped. If your availability score dips, you can instantly tell whether *you* blocked the scorer. Consider a canary: an internal poller hitting your own services the same way the scorer does, so you detect self-inflicted downtime in seconds.

---

## Gap 3 — Wazuh vs Velociraptor vs osquery/Fleet vs in-house

*Re-researched 2026-07-18 with six finer-grained angles; 24 confirmed claims, auto-synthesis merged them. This section is now fact-checked, not judgment.*

**Verified — Velociraptor (the standout):**
- **Velociraptor is the strongest integrate-not-build choice for a small team**: open-source **AGPLv3, no license cost**, maintained by Rapid7 since 2021, an endpoint-focused DFIR/threat-hunting platform for IR, forensics, and investigation. `[unanimous]` — https://www.rapid7.com/products/velociraptor/, https://github.com/Velocidex/velociraptor, https://docs.velociraptor.app/docs/overview
- **VQL lets you build custom artifacts** to collect/query/monitor almost any endpoint aspect (filesystems, registry, process tables, event logs) on individual hosts, groups, or the whole deployment, with event queries for continuous monitoring — dynamic investigation, not precompiled signatures. `[unanimous]` — https://docs.velociraptor.app/docs/vql/
- **A single server handles ~10k–15k clients** (150k+ via multi-frontend) and returns artifact results across the estate **in minutes** — at CCDC's dozens-of-hosts scale, minutes is conservative. `[unanimous]` — https://docs.velociraptor.app/docs/deployment/resources/, https://www.pentestpartners.com/security-blog/using-velociraptor-for-large-scale-endpoint-visibility-and-rapid-threat-hunting/
- **Velociraptor runs Sigma rules locally on the endpoint** (native since v0.7.1, Dec 2023) and returns only matches — big network/storage savings vs centralized log forwarding. `[3-0]` — https://sigma.velocidex.com/docs/models/windows_base_vql/
- **Caveat (refuted claim):** the "under 1% idle CPU" footprint claim **failed verification 0-3** — single blog, no primary source. Footprint under active hunts (esp. full-disk YARA) is materially higher. **Measure agent resource use yourself** before broad deployment. `[refuted]`
- **Key limitation:** Velociraptor is **DFIR/detection-oriented, NOT inline prevention** — it hunts and collects, it doesn't enforce/block. Pair it with an enforcement tool.

**Verified — Wazuh (the enforcement complement):**
- **Wazuh Active Response** auto-runs response scripts when an alert matches a rule ID/level/group, shipping **out-of-the-box actions across Linux/macOS/Unix/Windows**: block IPs (firewall-drop/firewalld-drop/host-deny/netsh/route-null), delete files (remove-threat.sh on rule 87105), disable accounts, restart agents. `[3-0]` — https://documentation.wazuh.com/current/user-manual/capabilities/active-response/index.html
- **Caveats:** Wazuh itself warns that **poor rule/response config can *increase* endpoint vulnerability** (directly relevant to not breaking scored services), and its **Windows** out-of-the-box file-deletion/FIM is weaker than Linux.

**Verified — osquery/Fleet (state + light response):**
- Fleet extends beyond read-only telemetry: **cross-platform remote script execution** (macOS/Windows/Linux; shell/Python/PowerShell — added 4.37.0, disabled by default), a Linux script library, and **remote lock** (4.45.0); self-hostable on-prem/air-gapped/Docker/K8s. `[3-0]` — https://fleetdm.com/releases/fleet-4-37-0, https://fleetdm.com/releases/fleet-4-45-0
- **Important caveat:** Fleet's "lock" is a **device login-lock, NOT EDR network quarantine** — don't treat it as true host isolation.

**Recommendation for BTDT (now evidence-backed):**
- **Integrate, don't build the DFIR layer.** Use **Velociraptor as your live-response + hunt backbone** (VQL, endpoint-local Sigma, minute-scale fleet triage, web GUI + CLI — this also answers Gap 6). It's free, cross-platform, and purpose-built for exactly the "triage already-compromised hosts fast" problem.
- **Add Wazuh Active Response as the enforcement arm** Velociraptor lacks — but wire it carefully (audit rules first; a bad response rule can self-inflict downtime, per Wazuh's own warning).
- **osquery/Fleet for continuous state** (what's installed/listening, scheduled tasks, AD objects). Don't rely on Fleet "lock" for isolation.
- **Where the custom Go/BTDT agent still earns its place:** (1) real-time eBPF/Sysmon behavioral telemetry with process-lineage identity — neither Fleet nor Velociraptor streams eBPF detection like Tetragon; (2) the fail-open scored-service proxy (Gap 2); (3) the Raft/gossip HA control plane (Gap 1). **Hybrid boundary:** integrate Velociraptor + Wazuh-AR + osquery + your eBPF stream; build in-house only the competition-specific pieces (scored-path protection, HA control plane, signed-command response).

---

## Gap 4 — Full OSS defensive + AV/prevention stack

*Re-researched 2026-07-18. Network-layer and Windows-prevention findings are now fact-checked; Falco/Tetragon and CrowdSec specifics remained under-covered (flagged below).*

**Verified — use pre-integrated bundles instead of hand-wiring:**
- **Security Onion** bundles **Zeek + Suricata (NIDS) + Strelka (file analysis) + honeypots + Elastic Agent** (2.4/3.1 also ships osquery+Fleet for host visibility). `[3-0]` — https://docs.securityonion.net
- **CISA's Malcolm** bundles **Zeek + Arkime (PCAP) + Suricata (IDS) + YARA/ClamAV**, containerized from Raspberry Pi to cloud, CISA-maintained. `[3-0]` — https://github.com/cisagov/Malcolm
- For a small team these **sharply cut the integration burden** vs hand-wiring Suricata/Zeek/etc. `[unanimous]` — https://zeek.org/2026/01/3-ways-to-integrate-zeek-with-your-security-stack/

**Verified — Windows ASR/WDAC/AppLocker rollout (this is the part that breaks scored services):**
- **Deploy Audit-mode-first in phased rings**; remediate false positives with **file/folder exclusions, NOT by disabling rules** ("Rule exclusions are better than turning off rules or switching them back to Audit mode"). Warn mode limits disruption without disabling. `[3-0, Microsoft Learn, updated Jul 2026]` — https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-deployment-test
- **ASR depends on Microsoft Defender AV** (nearly every rule lists it as a dependency; obfuscated-script/prevalence/ransomware/macro rules also need cloud protection or AMSI). `[3-0]` — https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference
- **Specific ASR rules collide with legitimate management tooling:** the **WMI-persistence** and **PSExec/WMI** rules interfere with WMI-heavy management (e.g. ConfigMgr) — test extensively; the **LSASS** rule generates large but mostly-safe audit noise. `[3-0]` — same source

**Recommendation for BTDT:**
- **Stand up the network layer via Security Onion or Malcolm** rather than wiring Zeek/Suricata/Arkime yourself — the time saved in an 8–24h window is decisive. Forward the alerts you care about into your existing OpenSearch.
- **Linux runtime layer:** keep Falco/eBPF for detection and Tetragon for enforcement — split by role (see Gap 4a below for the verified details). Tetragon fits your process-lineage model and can kill/override syscalls in-kernel.
- **Windows prevention, staged:** WDAC/AppLocker allow-listing + **ASR** for offensive primitives (LSASS theft, Office child processes, obfuscated scripts), plus **LAPS** to kill lateral movement via shared local-admin passwords (highest-ROI AD hardening in CCDC). **But: enable ASR in Audit mode across all rules first, confirm the scoring engine stays green, fix with exclusions not rule-disabling, then flip to enforce — tie the flip to Gap-2's canary poller.** Skip/carefully-test the WMI and PSExec rules if you use WMI-based management.
- **File/memory AV:** ClamAV for known-bad files + YARA memory scanning (see Gap 5).

### Gap 4a — Linux runtime enforcement: Falco vs Tetragon vs CrowdSec

*Re-researched 2026-07-18 (third run); all 25 claims verified 3-0 against primary docs. The three tools split cleanly by role — don't treat them as interchangeable.*

**Verified — Falco is detection/alert-only:**
- Falco parses kernel syscalls against a rules engine and its response is a **configurable downstream alert (stdout/HTTP) — never in-line block or kill**; the rules reference has condition/output fields only, no enforcement action. `[3-0]` — https://falco.org/docs/
- Enforcement is bolted on via **Falco Talon** (official, "Incubating", v0.3.0), but its actionners (pod terminate/delete, Calico/Cilium NetworkPolicy) are **Kubernetes-scoped — they do NOT apply to bare-metal Linux or Windows AD hosts.** `[3-0]` — https://github.com/falcosecurity/falco-talon
- **Implication for BTDT:** on non-Kubernetes CCDC hosts, Falco gives you *detection only*. Don't count on it to block anything.

**Verified — Tetragon is the host-level in-kernel enforcer:**
- Tetragon enforces **in-kernel via eBPF, inline with the operation**, through TracingPolicy: **Signal** (SIGKILL the matching process synchronously from BPF) and **Override** (modify a kprobed function's return so the syscall never executes). A blocked syscall doesn't return; the process exits 137. `[3-0]` — https://tetragon.io/docs/concepts/enforcement/
- **Critical gotcha: SIGKILL alone is unreliable** — it's asynchronous to the in-flight syscall (a `write()` may still commit). Tetragon's own docs say **combine Signal WITH Override** to actually block an operation. `[3-0]` — same source
- **Override needs kernel support** (`CONFIG_BPF_KPROBE_OVERRIDE`) and error-injectable target functions; overriding `security_` hooks works from kernel 5.7+. **Verify this flag on the competition images before relying on Override.** `[3-0]` — https://tetragon.io/docs/concepts/tracing-policy/selectors/
- **Safe staging built-in:** TracingPolicies have three modes — **monitoring** (enforcement elided — a true dry-run of an enforcing policy), **enforcement** (actions performed), and **monitor_only** (no enforcement actions). Load and observe an enforcing policy *before* activating the kill/override. `[3-0]` — https://tetragon.io/docs/concepts/tracing-policy/mode/

**Verified — CrowdSec cleanly decouples detection from enforcement (ideal for the fail-open constraint):**
- The **Security Engine** parses logs, applies scenarios, and makes ban **decisions**; the **Local API (LAPI)** stores alerts/decisions and applies **Profiles** (rules deciding whether an alert becomes a decision, a notification, or is just logged). `[3-0]` — https://docs.crowdsec.net/docs/getting_started/concepts/
- **Bouncers are separate packages** that fetch decisions from LAPI (API key via `cscli bouncers add`) and enforce: **L3/4 firewall-bouncer** (iptables/nftables/ipset/pf — protects SSH/DB/SMTP at kernel level) and **L7 bouncers** (nginx/Traefik/HAProxy — protect web apps). `[3-0]` — https://docs.crowdsec.net/u/bouncers/firewall/
- **This is the natural staging seam:** run the Security Engine and *watch decisions accumulate with no bouncer attached* — nothing is blocked until you deliberately attach a bouncer. Exactly the fail-open posture Gap 2 demands.

**Recommendation for BTDT (Linux enforcement layer):**
- **Detection:** Falco and/or your existing eBPF stream. **Enforcement:** **Tetragon** for process/syscall-level kill+override; **CrowdSec** for IP-level banning of noisy attackers — but with bouncers **detached first** so you can confirm the scorer isn't among the decisions before enforcing.
- **Stage everything in observe mode:** Tetragon `monitoring` mode and CrowdSec decisions-without-bouncer both let you see exactly what *would* be blocked before it is. Given that blocking a scored probe = lost points, load enforcing policies in dry-run, diff against your canary poller, then promote.
- **Don't use Falco Talon on bare-metal hosts** — its response is Kubernetes-only.

**Still not settled (honest gaps):** no Falco-vs-Tetragon *performance/overhead* benchmark survived verification (only the architectural split is proven); and **CrowdSec Windows enforcement was not substantiated** — only Linux L3/4 and L7 bouncers appeared. Treat CrowdSec as a Linux-side control and confirm any Windows bouncer story yourself.

---

## Gap 5 — Current (2025–2026) C2 & in-memory beacon detection

This is where your JA3-era design most needs updating.

**Verified — network fingerprinting (JA4+):**
- **JA4X fingerprints the *method* by which TLS certificates are generated (not the field values)** — so it identifies C2 frameworks like **Sliver, Havoc, Cobalt Strike, and SoftEther VPN even when they randomize certificate values.** `[3-0]` — https://blog.foxio.io/ja4+-network-fingerprinting
- **JA4+ works on encrypted traffic**: the TLS Client Hello is sent in cleartext before encryption, and JA4L works on Layer-3 data visible regardless of encryption. `[3-0]` — same source
- **JA4/JA4+ supersedes JA3** — a modular, multi-protocol, more interpretable fingerprint suite (not just TLS). `[3-0]` — https://hunt.io/glossary/ja4-fingerprinting
- **Deviation in a specific JA4+ segment can signal a change in attack vector/objective** — usable for behavioral C2 detection. `[2-1]` — same source

**Verified — in-memory / sleep-obfuscated beacon detection:**
- **In-memory YARA works against Cobalt Strike Beacon** because the final payload is decrypted and executed in memory, so memory scanning succeeds even when file detection fails. `[3-0]` — https://www.elastic.co/blog/detecting-cobalt-strike-with-memory-signatures
- **Sleep obfuscation still leaves IOCs**: encrypting whole PEs in memory and flipping memory permissions during sleep produces strong indicators despite the evasion intent. `[2-0]` — https://binarydefense.com/resources/blog/understanding-sleep-obfuscation
- **Moneta detects sleep-obfuscated beacons** via a **modified PE header** and **inconsistent executable (+x) permissions between the on-disk image and the in-memory image.** `[3-0]` — same source

**Recommendation for BTDT:**
- **Migrate JA3 → JA4+ now.** Add JA4/JA4S/JA4X/JA4L extraction to your network layer (Suricata supports JA4; Zeek plugins exist). JA4X is the standout: it catches Sliver/Havoc/CS/SoftEther *even with randomized certs*, which defeats the usual evasion. Build a JA4+ allow-list of your own legit clients and alert on the rest.
- **Add periodic in-memory scanning** to your agent: schedule memory YARA sweeps (YARA-X for speed) plus a Moneta/PE-sieve-style check for (a) private RX regions with no backing file, (b) modified PE headers, (c) disk-vs-memory permission/section mismatches. These catch sleeping beacons *between* beacons, when network fingerprinting sees nothing.
- **Combine the two axes:** JA4+ catches the beacon on the wire; memory scan catches it at rest during long sleeps; your eBPF/Sysmon process-lineage catches the injection/spawn. A beacon has to evade all three simultaneously — that's the layered win.
- Frameworks to profile signatures for: Cobalt Strike, Sliver, Mythic, Havoc, Brute Ratel, Metasploit. Add named-pipe naming anomalies and classic injection patterns (CreateRemoteThread, APC, process hollowing) to your Sysmon/eBPF rules.

---

## Gap 6 — Blue-team fleet control-plane UX

**Verified (Fleet as the reference model):**
- A single console spanning all your OSes with **remote actions run directly from the console, no user interruption, full success/failure output** is a proven pattern. `[3-0]` — https://fleetdm.com/orchestration?purpose=security

**Recommendation for BTDT:**
- **Adopt Velociraptor's console model** (web GUI + `pyvelociraptor`/CLI) as your reference for the "command the fleet, take action" UX: a hunt/flow abstraction (fan a query or action across N hosts, watch results stream back), per-host live shell, artifact collection. TheHive/Cortex is the reference for *case management + automated responders* if you want alert→action workflows.
- **Give operators both web and CLI**, backed by the same signed-command API from Gap 1 — the human signs an action once, the control plane fans it to the fleet, and every agent verifies the signature before executing. This makes the console tamper-resistant even if a control-plane host is compromised.
- **Redundancy:** the console is just a client of the Raft-backed control state, so any surviving quorum node can serve it. Don't pin the UI to one host.

---

## Highest-leverage moves (priority order)

1. **Fix the scored-service model (Gap 2):** never IP-whitelist the scorer, fail-open on scored ports, add a canary poller. This protects ~50% of your score and prevents the most common self-inflicted loss.
2. **Migrate JA3 → JA4+ and add memory scanning (Gap 5):** the single biggest detection upgrade over your current design.
3. **Embed Raft + gossip for HA, with signed operator commands (Gap 1 + 6):** makes the control plane survive host loss *and* host compromise.
4. **Integrate Velociraptor + osquery rather than building DFIR in-house (Gap 3):** save your build time for the competition-specific pieces.
5. **Stage every prevention layer audit-first, enforce-second (Gap 4):** tied to the Gap-2 canary so you never blind the scorer.

---

## Research quality notes

- **Run 1 (all six gaps):** 20/25 verified claims confirmed. Strongest: Gaps 1, 2, 5. The auto-synthesis and 3 sleep-obfuscation verify votes were blocked by a cyber-safety classifier, so Gaps 1/2/5/6 were synthesized manually from the verified claim set — no verified content lost.
- **Run 2 (Gaps 3 & 4 only, six finer angles, 2026-07-18):** 24 confirmed claims, auto-synthesis completed, 10 merged findings. Gaps 3 and 4 above are now fact-checked and replace the earlier judgment-only text. Corpus was Velociraptor-heavy.
- **Run 3 (Falco/Tetragon/CrowdSec enforcement, 2026-07-18):** all 25 claims verified 3-0 against primary docs, 8 merged findings — now in Gap 4a. Remaining gaps: no Falco-vs-Tetragon overhead benchmark surfaced; CrowdSec Windows enforcement unsubstantiated (Linux-only bouncers found).
- **Source caveat:** several capability claims come from vendor/maintainer material (Rapid7 product page, Fleet release notes, Wazuh docs, Microsoft Learn) — appropriate for non-extraordinary capability descriptions and corroborated by primary docs, but not neutral third-party benchmarks. arXiv 2606.28812 is a preprint. ASR guidance is current as of July 2026 Microsoft docs but time-sensitive.
- **All sources are 2020–2026; primary CCDC/exercise sources** (CCDCOE Locked Shields paper, howtowinccdc.com) carried the scoring findings.
