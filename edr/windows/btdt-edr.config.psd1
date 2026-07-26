@{
    # btdt-edr.config.psd1 - Windows/AD sensor configuration.
    # Loaded with Import-PowerShellDataFile. Everything here is an allowlist or a
    # toggle. The first run on a host is meant to be noisy: read the ALERTs,
    # decide which are your own software, add them here, re-run.

    # ------------------------------------------------------------------
    # Response posture: 'observe' | 'quarantine' | 'kill'
    #   observe    = detect + log only, nothing changed (default).
    #   quarantine = observe + sever the C2 socket + quarantine dropped files.
    #   kill       = quarantine + stop the process + disable the account +
    #                re-enable a tampered firewall + revert priv-group changes.
    # Auto-response fires ONLY on high-confidence (near-zero-FP) detections.
    # Override per run with -Respond.
    # ------------------------------------------------------------------
    RespondMode = 'observe'

    # Fail-open: never let a response drop inbound on a scored service port.
    ScoredPorts = @(22, 25, 53, 80, 110, 143, 443, 3389, 3306, 636, 88, 389)

    # Ports you EXPECT to be listening on this host. Tune per role.
    AllowedListenPorts = @(22, 80, 443, 3389, 53, 88, 135, 139, 389, 445, 464, 636, 3268, 3269, 5985, 9389)

    # Interpreters / LOLBins that should essentially never hold an outbound socket.
    LolbinEgress = @('powershell', 'pwsh', 'cmd', 'wscript', 'cscript', 'mshta',
                     'rundll32', 'regsvr32', 'certutil', 'bitsadmin', 'msiexec',
                     'installutil', 'msbuild', 'wmic')

    # Internal DNS resolver(s). Outbound :53 elsewhere is suspicious.
    InternalResolvers = @()          # e.g. @('10.0.0.53')
    InternalExtra     = @()          # extra CIDRs/prefixes to treat as internal

    # ------------------------------------------------------------------
    # #1 Launch-time process telemetry (ProcCreate)
    # Reads Security 4688 AND Sysmon EID 1. To feed it, on the host enable:
    #   auditpol /set /subcategory:"Process Creation" /success:enable
    #   + GPO "Include command line in process creation events" (or deploy Sysmon).
    # Fires only on beacon-drop patterns; never auto-kills (a bad kill on an
    # interpreter is worse than a WARN).
    # ------------------------------------------------------------------
    ProcCreate = @{
        # Office/script hosts that spawning an interpreter is a classic maldoc drop.
        SuspectParents  = @('winword','excel','powerpnt','outlook','onenote',
                            'mshta','wscript','cscript','acrord32','eqnedt32','hh')
        # Interpreters/LOLBins a beacon stager launches.
        SuspectChildren = @('powershell','pwsh','cmd','rundll32','regsvr32','mshta',
                            'wscript','cscript','certutil','bitsadmin','installutil',
                            'msbuild','wmic','cmstp','msiexec')
        SuspectPaths    = 'Temp|AppData|ProgramData|\\Users\\Public|\\Downloads|\\Windows\\Tasks|\\PerfLogs'
        MaxPerSweep     = 500     # cap XML parses per sweep on busy hosts
    }

    # ------------------------------------------------------------------
    # #2 In-memory injection scan (MemScan)
    # Native scan for private+committed executable memory (RWX / exec-writecopy)
    # not backed by a file on disk -- the tell of reflectively-loaded shellcode,
    # regardless of sleep/jitter or C2 address. Heavy: runs on a slow cadence.
    # Optional: drop pe-sieve64.exe (or hollows_hunter64.exe) in
    # <BaselineDir>\tools and flagged PIDs get a second-opinion scan.
    # ------------------------------------------------------------------
    MemScan = @{
        EveryNSweeps = 10        # scan on sweep 1, then every Nth (0 = every sweep)
        MinRegionKB  = 12        # ignore tiny RWX crumbs (hotpatch/trampolines)
        # Heavy-JIT processes that legitimately hold RWX -- skip to stay quiet.
        AllowProc    = @('powershell','pwsh','MsMpEng','SearchIndexer','devenv','code',
                         'chrome','msedge','firefox','iexplore','java','javaw','jp2launcher',
                         'w3wp','dotnet','Teams','ms-teams','OfficeClickToRun','SearchApp')
    }

    # ------------------------------------------------------------------
    # #1 Raw-socket / sniff-shell detection (RawSocket)
    # The Windows analog of the Linux 'rawsock' check. A passive sniff-shell
    # (watershell-style) opens NO socket and NO listener -- it reads packets off
    # the wire in promiscuous mode or via a packet-interception driver, so the
    # firewall and every connection-layer check see nothing. This hunts the
    # mechanism it cannot hide: a promiscuous NIC, or a WinDivert/pcap driver.
    # ------------------------------------------------------------------
    RawSocket = @{
        # Capture drivers that are legitimately present (e.g. you run Wireshark).
        # WinDivert is never allowlisted by name here -- it is a strong C2 signal.
        AllowCaptureDrivers  = @()          # e.g. @('npcap','npf')
        # Adapter descriptions that are legitimately promiscuous (monitor NIC, some
        # Hyper-V/VM switches, a capture box). Substring match on InstanceName.
        AllowPromiscAdapters = @()          # e.g. @('Hyper-V','Npcap Loopback')
    }

    # ------------------------------------------------------------------
    # #3 Egress hardening (InternalBeacon + FirewallLog)
    # ------------------------------------------------------------------
    # Internal peers this host legitimately talks to (exact IP or dotted prefix,
    # e.g. '10.0.0.' for a subnet). A *suspicious* process (unsigned / temp-path /
    # LOLBin) connecting to any OTHER internal peer is surfaced -- this is the fix
    # for the RFC1918 blind spot where an internal C2/redirector is invisible.
    TrustedInternalPeers = @()       # e.g. @('10.0.0.10','10.0.0.', '192.168.1.5')

    # Windows Firewall dropped-packet log. Turn on default-deny outbound + logging:
    #   Set-NetFirewallProfile -All -DefaultOutboundAction Block -LogBlocked True
    # Then every blocked call-home is logged, not just sampled mid-call.
    FirewallLog = 'C:\Windows\System32\LogFiles\Firewall\pfirewall.log'

    # NetworkConnect: read Sysmon EID 3 (network-connect) EVENTS instead of polling
    # live sockets, so a brief, periodic beacon check-in is caught the moment it
    # happens -- the point-in-time poll behind Egress/InternalBeacon misses a
    # sub-second mtls/https check-in almost every sweep. Needs Sysmon with network
    # logging on. Alerts once per unique image+destination per run to stay quiet.
    NetConnect = @{ MaxPerSweep = 1000 }

    # Privileged AD groups whose membership is baselined and (in kill mode) reverted.
    PrivilegedGroups = @('Domain Admins', 'Enterprise Admins', 'Schema Admins',
                         'Administrators', 'Account Operators', 'Backup Operators')

    # State / output
    BaselineDir          = 'C:\ProgramData\btdt-edr'
    WatchInterval        = 30        # seconds between sweeps in -Watch mode
    EventLookbackMinutes = 10        # how far back event-log checks look each sweep

    # Per-detection toggles
    Checks = @{
        NamedPipes    = $true    # Cobalt Strike / Mythic C2 named pipes
        ProcCreate    = $true    # #1 beacon-drop process launches (4688 / Sysmon 1)
        Egress        = $true    # outbound by unsigned / temp-path binary
        LolbinEgress  = $true    # interpreter/LOLBin holding an outbound socket
        InternalBeacon= $true    # #3 suspicious process -> non-trusted internal peer
        NetworkConnect= $true    # #3 event-driven egress (Sysmon EID 3) - catches brief beacons
        MemScan       = $true    # #2 injected/RWX-private shellcode in memory
        RawSocket     = $true    # #1 sniff-shell: promiscuous NIC / WinDivert/pcap driver
        Listeners     = $true    # unexpected listening ports
        Persistence   = $true    # tasks/services/Run keys/WMI diff vs T0
        Firewall      = $true    # firewall profile disabled / outbound un-blocked
        FirewallLog   = $true    # #3 blocked outbound call-home in the firewall log
        PortProxy     = $true    # netsh portproxy piggyback
        IISModules    = $true    # malicious native IIS module (if IIS present)
        LogClear      = $true    # Security 1102 / System 104 (anti-forensics)
        DnsTunnel     = $true    # high-entropy / long-label DNS in client cache
        # --- AD / Domain Controller checks (auto-skip if no AD module) ---
        DCSync        = $true    # replication rights abused (Mimikatz/secretsdump)
        Kerberoast    = $true    # 4769 RC4 ticket requests
        AsrepRoast    = $true    # 4768 preauth-not-required + DONT_REQ_PREAUTH accts
        PrivGroups    = $true    # privileged-group membership diff + revert
    }
}
