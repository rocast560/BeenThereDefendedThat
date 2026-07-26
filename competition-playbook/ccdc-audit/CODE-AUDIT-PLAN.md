# Code Audit Tool — Design & Build Plan (`code-audit.py`)

A third read-only auditor for the toolkit, alongside `linux-audit.sh` and
`ad-audit.ps1`. Where those two scan the **host** (users, services, persistence),
this one scans **application source code and web roots**: the directory you're
handed on a Linux or Windows box.

> Read-only, same as the other two. It reports; you remediate by hand.

---

## 0. Reframe — this tool has TWO missions, not one

The generic "wrap Semgrep + Bandit" architecture only does mission B. In CCDC,
mission A is usually the one that saves points, and it's the one nobody's tool does.

| | Mission A — **Hunt implanted evil** | Mission B — **Harden our code** |
|---|---|---|
| Question | "Did red team already backdoor this app?" | "What weaknesses will they exploit?" |
| Finds | Webshells, PHP/JSP/ASPX backdoors, added admin routes, obfuscated `eval(base64())`, tampered vendor files, cron/task droppers in the tree | Hardcoded creds, private keys, SQLi/command-injection sinks, vulnerable dependencies, debug endpoints |
| Wins by | **Removing attacker access before/while they use it** | Closing the hole before they find it |
| Priority | **Do this first.** A live webshell = active compromise. | Do this second, continuously. |
| Core tech | YARA + entropy + **diff-against-known-good** + newest-file triage | Semgrep/Bandit/gitleaks/Trivy |

**The single highest-value technique** is not in the pasted architecture:
**diff the deployed app against a pristine copy.** If you can obtain the vendor
tarball, upstream git tag, or the original image, any file that differs is
suspect — this catches backdoors that *no signature will ever match*. Make this a
first-class mode of the tool (`--baseline <dir>` / hash-manifest compare).

---

## 1. Hard constraints that shape every decision

These are the CCDC realities the generic plan ignores. They drive tool choice more than features do.

1. **Assume no internet.** Competition segments are frequently isolated or
   egress-filtered. Any tool that phones home for rules/DBs (Semgrep registry,
   Trivy vuln DB, OSV, ClamAV freshclam, trufflehog verification) must have its
   data **pre-staged offline**. Design for air-gap; treat online as a bonus.
2. **Time-boxed.** Output must be *triaged*, not a 4,000-line dump. Top-of-report
   = "malicious/critical, look now"; everything else below. Fast first pass.
3. **Cross-platform, one operator.** Runs on Windows and Linux targets. The
   orchestrator is Python (portable); the *scanner binaries* differ per OS and
   must be bundled for both. Prefer **single static binaries** (Go tools) that
   need no runtime or install — you won't have time to `pip install` on a box,
   and you may not have network to do it.
4. **Read-only / non-destructive** — matches the toolkit ethos. Never quarantine
   or delete; report paths + evidence, operator acts.
5. **Portable + self-contained** — drop one folder on the box (or scan from your
   own jump box over a mount/copy) and run. No global installs.
6. **Match the existing toolkit** — `FAIL/WARN/PASS/INFO` + `Summary:` line,
   exit `0/1/2`, `-c/-o/--only/--skip/--no-color`, co-located config, `-h` prints
   the header. An operator who knows the other two tools knows this one instantly.

---

## 2. Tool selection — curated, offline-first, single-binary-first

Don't wrap everything. Wrap a **small, reliable, pre-stageable** set. Two tiers:
**Tier 1** = always bundle, core of the tool. **Tier 2** = language-specific, run
only when that stack is detected.

### Tier 1 — always run (bundle binaries for win + linux)

| Job | Tool | Why it makes the cut | Invocation (JSON) | Offline story |
|---|---|---|---|---|
| Malware / webshell sigs | **YARA** + curated rules | The core of mission A. Rules are just files — perfectly air-gapped. Bundle Neo23x0 `signature-base`, `YARA-Rules/rules`, webshell packs. | `yara -r -w -s rules/index.yar <dir>` | 100% offline (rules are static) |
| Webshell/backdoor scanner | **Loki** (Neo23x0) or **Fenrir** (bash, zero-dep) | Loki bundles YARA + hash IOCs + filename IOCs in one runner; Fenrir is pure bash for locked-down Linux with no Python. | `loki.py -p <dir> --noprocscan --csv ...` | Offline (ships its own sigs) |
| Secrets / keys / creds | **gitleaks** (single Go binary) | Fast, regex + entropy, works on non-git dirs. Exactly your "hardcoded creds / keys" ask. | `gitleaks dir <dir> -f json -r out.json` | 100% offline (rules embedded/TOML) |
| SAST (polyglot) | **Semgrep** *or* **Opengrep** | Multi-language taint/pattern engine. **Opengrep** = the OSS fork (LGPL) if Semgrep's licensing/telemetry is a concern; identical CLI. Bundle rules locally, run `--config <local-rules-dir>` (never `--config auto`, that's online). | `semgrep scan --config rules/ --json -o out.json <dir>` | Offline **if** rules pre-downloaded |
| SCA + secrets + IaC + misconfig | **Trivy** (single Go binary) | One binary covers vulnerable dependencies, embedded secrets, Dockerfile/K8s misconfig. Huge coverage-per-effort. | `trivy fs --scanners vuln,secret,misconfig -f json -o out.json <dir>` | Vuln DB must be **pre-pulled** (`trivy fs --download-db-only`, copy `~/.cache/trivy`) |
| Obfuscation / entropy triage | **NeoPI** (or built-in) | Flags high-entropy / low-index-of-coincidence files = packed/encoded webshells that dodge signatures. Small; can reimplement in the orchestrator to drop the dep. | `neopi.py -a -A <dir>` | 100% offline (pure math) |

### Tier 2 — run when the stack is detected (bundle what your bracket uses)

| Stack (detected by extensions/manifests) | Tool | Invocation |
|---|---|---|
| Python (`*.py`, `requirements.txt`) | **Bandit** + **pip-audit** | `bandit -r <dir> -f json -o out.json` |
| Node/JS (`*.js/ts`, `package.json`) | **njsscan** + `npm audit --json` (offline: OSV-Scanner) | `njsscan --json -o out.json <dir>` |
| PHP (`*.php`) — the classic CCDC LAMP/WordPress target | **progpilot** + **php-malware-finder** (PMF is *the* PHP webshell hunter) | `phpmalwarefinder <dir>` |
| Java (`*.java/jar`, `pom.xml`) | **find-sec-bugs** (SpotBugs plugin) | via spotbugs CLI |
| Go (`*.go`) | **gosec** | `gosec -fmt=json -out=out.json ./...` |
| Ruby/Rails (`Gemfile`) | **brakeman** | `brakeman -f json -o out.json` |
| .NET (`*.cs`, `*.csproj`) | **security-code-scan** / `dotnet list package --vulnerable` | roslyn analyzer |
| Compiled binaries in tree | **capa** (Mandiant) + YARA | `capa <bin> -j` |
| Dependency vulns, any lang, offline | **OSV-Scanner** (Go binary) | `osv-scanner --offline --format json -r <dir>` (needs pre-downloaded OSV DB) |

### Deliberately optional / de-prioritized
- **ClamAV** — good webshell coverage but heavy, needs freshclam DB, slow. Bundle
  only if you have room; YARA + PMF cover most of the same ground lighter.
- **trufflehog** — its superpower is *live verification* of secrets, which needs
  network. Offline it overlaps gitleaks. Keep as Tier 2 for when egress exists.

> **Bracket-tune the bundle.** Find out (from past years / the invite) whether
> your division's apps are PHP/LAMP, Node, Java, or .NET, and pre-stage that
> stack's Tier-2 tools heavily. A generic bundle wastes time; a bracket-tuned one
> wins.

---

## 3. Architecture

```
code-audit.py  (orchestrator, stdlib-only, py3.8+)
     │
     ├─ 1. DISCOVER   walk <dir>: detect stacks, web roots, binaries,
     │                newest files, git presence, size/entropy stats
     │
     ├─ 2. PLAN       pick which tools to run (Tier1 always + detected Tier2,
     │                minus --skip, honoring --only and config toggles)
     │
     ├─ 3. EXECUTE    run tools in parallel (subprocess + concurrent.futures),
     │                each emitting JSON to a temp dir; per-tool timeouts;
     │                degrade gracefully if a binary is missing (like have()/
     │                Get-Command in the other two scripts)
     │
     ├─ 4. NORMALIZE  parse every JSON into one Finding schema; map each tool's
     │                severity → FAIL/WARN/PASS/INFO; attach CWE where present
     │
     ├─ 5. DEDUPE     collapse findings on (file, line, ~rule-class); merge the
     │                tools that agree (raises confidence)
     │
     ├─ 6. FILTER     drop known false positives (config allowlist: test dirs,
     │                vendor/, node_modules/, example creds, fixture keys)
     │
     ├─ 7. PRIORITIZE malice-first sort: webshell/backdoor > secret/key >
     │                injection sink > vuln dep > hygiene. Boost multi-tool
     │                agreement + newest-file + web-root location.
     │
     └─ 8. REPORT     console (FAIL/WARN/PASS/INFO + Summary:), optional -o text,
                      --json full findings, --sarif for tooling. Exit 0/1/2.
```

### Unified Finding schema (the normalization target)
```python
Finding = {
  "id":        "sha1(file:line:rule)",  # stable, for dedupe + baseline diff
  "file":      "webroot/inc/config.php",
  "line":      42,
  "tool":      "gitleaks",              # who found it
  "rule":      "aws-access-key",        # tool's rule id
  "category":  "secret",               # webshell|backdoor|secret|injection|
                                       #   vuln-dep|misconfig|obfuscation|hygiene
  "severity":  "FAIL",                 # FAIL|WARN|PASS|INFO (mapped)
  "cwe":       "CWE-798",
  "confidence":"high",                 # bumped when >1 tool agrees
  "evidence":  "define('DB_PASS','hunter2')",  # short, redact secret value
  "why":       "Hardcoded DB password in web-readable file",
  "corroborated_by": ["semgrep"],       # other tools that flagged same locus
}
```

### Severity mapping (every tool → your 4 levels)
- **FAIL** — YARA webshell/backdoor hit; verified/high-entropy secret; known
  RCE/SQLi sink reachable; critical CVE in a used dependency; file differs from
  known-good baseline in a web root.
- **WARN** — medium SAST finding; secret-shaped string needing eyeballs;
  high-entropy file without a signature hit; outdated dep, no known critical CVE.
- **PASS** — a tool ran clean on a component (so a silent tool ≠ assumed clean).
- **INFO** — inventory: stacks detected, newest N files, largest files, files
  with exec bits in web root, git status — manual-review pointers.

### The two modes that matter most (build these, not just the wrappers)
- **`--baseline <dir|manifest>`** — diff the tree against a pristine copy or a
  saved SHA-256 manifest. Report added/modified/deleted files, *then* run
  signature scans on the changed set first. This is your best backdoor-catcher.
  Pairs with a `--snapshot` that writes the manifest (mirrors `linux-audit.sh`).
- **`--newest N` triage** — sort every code/web file by mtime, surface the newest
  N with a signature + entropy verdict each. Red team's dropper is usually recent.
  (Note the timestomp caveat — corroborate, like the other tools' README says.)

---

## 4. CLI & config (match the toolkit)

```
code-audit.py <target-dir> [options]

  -c, --config PATH     config file (default: ./code-audit.conf next to script)
  -o, --out PATH        also write a color-stripped text report
      --json PATH       write full findings as JSON
      --sarif PATH      write SARIF (for VS Code / CI, optional)
      --only  a,b,c     run only these checks/tools
      --skip  a,b,c     skip these checks/tools
      --baseline PATH   diff target against known-good dir or manifest
      --snapshot PATH   write a SHA-256 manifest of target for later --baseline
      --newest N        triage the N most-recently-modified files (default 25)
      --stack LIST      force stack set (php,node,python,...) skip autodetect
      --no-color        disable ANSI (auto-off when not a TTY)
      --timeout SECS    per-tool timeout (default 300)
  -h, --help            print header/usage

Exit: 0 = no FAIL, 1 = >=1 FAIL, 2 = usage/config error   (same contract)
```

**Config** (`code-audit.conf`) — since there's no Python precedent in the repo,
use plain **JSON** (stdlib, no py3.11 dependency) with heavy comment keys, or a
tiny INI via `configparser`. Keys to expose:
- `TOOLS` — enable/disable + path-to-binary per tool (so you can point at the
  bundled `./bin/` copies).
- `IGNORE_PATHS` — `vendor/`, `node_modules/`, `test/`, `fixtures/`, `.git/`.
- `ALLOW_SECRETS` — regexes/hashes of known-legit example creds to suppress.
- `WEB_ROOTS` — dirs to treat as web-served (raises severity of hits there).
- `STACK_HINTS`, `SEVERITY_OVERRIDES`, `PER_TOOL_TIMEOUT`, `RULES_DIR`.

Like the other two: **first run is noisy**; tune allowlists so real hits stand out.

---

## 5. Offline staging kit (do this at home, before the competition)

A `./bin/` + `./rules/` + `./db/` bundle you carry in. This is the make-or-break
prep step the generic plan omits.

```
ccdc-audit/
  code-audit.py
  code-audit.conf
  bin/
    linux/   { yara, gitleaks, trivy, semgrep|opengrep, osv-scanner, gosec }
    windows/ { yara.exe, gitleaks.exe, trivy.exe, ... }
    py/      { loki/, bandit (vendored), njsscan, neopi.py, phpmalwarefinder }
  rules/
    yara/    { signature-base/, yara-rules/, webshells/ }   # git-cloned offline
    semgrep/ { p-security-audit, p-owasp-top-ten, custom-ccdc/ }
    gitleaks/ gitleaks.toml
  db/
    trivy/   ( pre-pulled trivy-db, trivy fs --download-db-only )
    osv/     ( pre-downloaded OSV database )
```

Staging checklist:
- [ ] Pull single-binary Go tools for **both** linux/amd64 and windows/amd64.
- [ ] `git clone` YARA rule repos; build an `index.yar` include file.
- [ ] `semgrep --config p/security-audit ... ` once online to warm the rule
      cache, then copy the rules dir; or use Opengrep with a local rule pack.
- [ ] `trivy fs --download-db-only` and copy `~/.cache/trivy` → `db/trivy`.
- [ ] `osv-scanner` offline DB download.
- [ ] Test the **whole bundle on an air-gapped VM** (pull the network cable) so
      you find the "it wants to phone home" surprises at home, not at T+20.
- [ ] Zip it. Also keep a **pristine-copy stash** of likely target apps
      (WordPress, common CMSes, sample stacks) for `--baseline` diffing.

---

## 6. Build roadmap (MVP-first, each step independently useful)

**Phase 0 — skeleton (½ day).** Arg parsing, config load, discovery walk +
stack detection, the `FAIL/WARN/PASS/INFO` emit/tally helpers copied from the
other tools, `Summary:` line, exit codes. Ship it printing only the INFO
inventory. *Already useful as a recon tool.*

**Phase 1 — mission A core (1 day).** Wire **YARA + gitleaks** (both single
binary, both offline, both high-signal). Add `--baseline`/`--snapshot` diff and
`--newest`. Normalize → dedupe → prioritized report. **This is the MVP that wins
points** — webshells and planted creds, offline, fast.

**Phase 2 — mission B breadth (1 day).** Add **Semgrep/Opengrep + Trivy**.
Add stack autodetect → Tier-2 dispatch (Bandit/njsscan/PMF/gosec…). Full
normalization + CWE mapping. `--json`/`--sarif`.

**Phase 3 — polish (½ day).** FP filtering/allowlists, multi-tool corroboration
confidence boost, entropy triage, per-tool timeouts + graceful missing-binary
degradation, `-o` text mirror. Tune against a real sample app.

**Phase 4 — custom CCDC rules (ongoing).** The pasted plan's real edge. Write:
- Semgrep/YARA rules for **your** environment's expected-bad patterns.
- Rules for common CCDC injects: added admin users in app config, altered
  `.htaccess`, appended PHP to legit files, `<?php ... eval($_(...` one-liners,
  `system($_GET`, base64→`eval` chains, JSP/ASPX runtime exec.
- An allowlist of your own team's legit patterns to kill FPs pre-emptively.

**Total: ~3 focused days** to a competition-ready tool; the Phase-1 MVP is usable
after day one.

---

## 7. Where it plugs into the playbook

- **T+15–35 (triage):** run `code-audit.py <webroot> --newest 25` on every app
  box right after the host auditors — surface planted webshells *before* hardening.
- **After you have a clean tree:** `--snapshot` each app dir.
- **T+60+ (sustain):** watch-loop it like the others; `--baseline` diff every
  30–60 min. A new/modified file in a web root mid-game = red team → evidence →
  incident report. Same muscle memory as `linux-audit.sh --diff`.

---

## 8. Open decisions (flag before building)

1. **Semgrep vs Opengrep** — Opengrep if you want pure-OSS/no-telemetry; Semgrep
   if you want the richer community rule registry. CLI is ~identical either way.
2. **Config format** — JSON (zero dep, ugly comments) vs INI/`configparser`
   (clean, stdlib) vs TOML (`tomllib`, but py3.11+). Leaning INI for readability.
3. **How much to vendor vs. shell-out** — reimplementing NeoPI-style entropy and
   the baseline-diff in-orchestrator removes deps and is trivial; keep YARA/
   Semgrep/Trivy/gitleaks as external binaries (don't reinvent engines).
4. **Bracket stack** — *decided (2026-07-21): build polyglot.* Stage all Tier-2
   stacks, but prioritize **PHP/LAMP/WordPress, Node/JS, and Python** in the
   bundle and custom-rule effort (these are the likely CCDC app targets). Java/
   .NET/Go stay in Tier-2 but lower staging priority until the bracket is known.
