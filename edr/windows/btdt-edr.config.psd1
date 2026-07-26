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
        Egress        = $true    # outbound by unsigned / temp-path binary
        LolbinEgress  = $true    # interpreter/LOLBin holding an outbound socket
        Listeners     = $true    # unexpected listening ports
        Persistence   = $true    # tasks/services/Run keys/WMI diff vs T0
        Firewall      = $true    # firewall profile disabled / tampered
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
