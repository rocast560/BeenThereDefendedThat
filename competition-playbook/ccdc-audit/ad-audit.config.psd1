@{
    # =========================================================================
    # ad-audit.config.psd1  —  configuration for ad-audit.ps1
    # =========================================================================
    # PowerShell data file (hashtable). Edit values to match YOUR box/domain.
    # Load order: this file overrides the script's built-in defaults.
    # =========================================================================

    # --- Scoring / firewall --------------------------------------------------
    # Scored service ports on THIS host (kept OPEN by port — scorer IP rotates).
    ScoredPorts            = @(80, 443, 3389)

    # Ports allowed to LISTEN on this host. Extra listeners are flagged.
    AllowedListenPorts     = @(53, 88, 135, 139, 389, 445, 464, 636, 3268, 3269, 3389, 80, 443)

    # Your team admin/jump subnet. Admin ports (RDP/WinRM) should be limited here.
    AdminSubnet            = "10.0.99.0/24"

    # Documented scoring CIDR if your packet gives one; else "" (open to all).
    ScoringCidr            = ""

    # --- Accounts (local) ----------------------------------------------------
    # Accounts you EXPECT in the local Administrators group. Extras flagged.
    ExpectedLocalAdmins    = @("Administrator")

    # --- Accounts (Active Directory) -----------------------------------------
    # Expected members of each privileged AD group. Extras are flagged HIGH.
    ExpectedPrivilegedMembers = @{
        "Domain Admins"     = @("Administrator")
        "Enterprise Admins" = @("Administrator")
        "Schema Admins"     = @("Administrator")
        "Administrators"    = @("Administrator")
        "Account Operators" = @()
        "Backup Operators"  = @()
        "Server Operators"  = @()
    }

    # Accounts that are allowed to have a Service Principal Name (kerberoastable
    # if privileged). List known service accounts to suppress noise.
    ExpectedSpnAccounts    = @()

    # --- Thresholds ----------------------------------------------------------
    MaxKrbtgtAgeDays       = 180   # krbtgt older than this = warn (rotate it)
    RecentAccountHours     = 24    # accounts created/changed within = flag
    MinPasswordLength      = 12    # domain policy minimum you expect

    # --- Check toggles (1 = run, 0 = skip) ----------------------------------
    Checks = @{
        LocalAdmins        = 1   # local Administrators group membership
        LocalUsers         = 1   # enabled local users, Guest account
        PrivilegedGroups   = 1   # AD privileged group membership vs expected
        Krbtgt             = 1   # krbtgt password age (golden ticket)
        PasswordPolicy     = 1   # domain password/lockout policy
        PwdNeverExpires    = 1   # users with non-expiring passwords
        PwdNotRequired     = 1   # users with PASSWD_NOTREQD
        ReversibleEncrypt  = 1   # users storing reversible-encrypted passwords
        Kerberoast         = 1   # user accounts with SPNs
        AsrepRoast         = 1   # accounts w/ 'do not require preauth'
        Delegation         = 1   # unconstrained/constrained delegation
        AdminCountStale    = 1   # adminCount=1 users no longer privileged
        RecentAccounts     = 1   # recently created/modified accounts
        Smbv1              = 1   # SMBv1 feature enabled (EternalBlue)
        Firewall           = 1   # Windows Firewall profile + scored-port posture
        Listeners          = 1   # listening TCP ports vs allowlist
        Outbound           = 1   # established outbound to public IPs (C2)
        ScheduledTasks     = 1   # non-Microsoft scheduled tasks (persistence)
        Services           = 1   # unquoted paths / suspicious service binaries
        RunKeys            = 1   # HKLM/HKCU Run keys (persistence)
        WmiPersistence     = 1   # WMI event-consumer subscriptions
        LsaProtections     = 1   # WDigest, RunAsPPL, LSA protection
        Logging            = 1   # Sysmon / PowerShell logging presence (info)
        # --- added: relay / poisoning / legacy-protocol hardening ------------
        Llmnr              = 1   # LLMNR + NBT-NS poisoning (Responder)
        SmbSigning         = 1   # SMB signing required (NTLM relay defense)
        NtlmHardening      = 1   # LmCompatibilityLevel (NTLMv1) + NoLmHash
        AnonymousAccess    = 1   # RestrictAnonymous(SAM)/RestrictRemoteSAM/null sessions
        Spooler            = 1   # Print Spooler + Point-and-Print (PrintNightmare/PrinterBug)
        HiveNightmare      = 1   # SAM hive ACL readable by Users (CVE-2021-36934)
        SmbGhost           = 1   # SMBv3 compression on 1903/1909 (CVE-2020-0796)
        WebClient          = 1   # WebDAV service (HTTP->LDAP relay coercion)
        CredentialGuard    = 1   # Credential Guard / VBS running
        Zerologon          = 1   # Netlogon FullSecureChannelProtection (CVE-2020-1472)
        MachineAccountQuota = 1  # ms-DS-MachineAccountQuota (NoPAC/RBCD/KrbRelayUp)
        LdapSigning        = 1   # LDAP signing + channel binding (relay defense)
        DcsyncRights       = 1   # DS-Replication rights on domain object (DCSync)
        AdcsTemplates      = 1   # ESC1/2/9 vulnerable certificate templates
        # --- advanced implant hunt (custom / pre-planted / in-memory C2) -----
        NamedPipes         = 1   # named-pipe C2 patterns (Cobalt Strike / Mythic)
        IISModules         = 1   # malicious native IIS modules + config audit log
        PortProxy          = 1   # netsh portproxy (port-piggyback / pivot)
        MemoryScan         = 1   # pe-sieve/hollows_hunter staging + injection telemetry
    }
}
