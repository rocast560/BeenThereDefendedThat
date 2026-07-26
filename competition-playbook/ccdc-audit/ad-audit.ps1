<#
.SYNOPSIS
    Read-only CCDC blue-team misconfiguration auditor for Windows / Active Directory.
.DESCRIPTION
    Reports security misconfigurations & persistence indicators on a Windows host
    and (if the ActiveDirectory module is present, e.g. on a DC) across the domain.
    Makes NO changes. Config-driven via ad-audit.config.psd1.
.EXAMPLE
    .\ad-audit.ps1
    .\ad-audit.ps1 -ConfigPath .\ad-audit.config.psd1 -OutFile report.txt
    .\ad-audit.ps1 -Only PrivilegedGroups,Krbtgt,Firewall
    .\ad-audit.ps1 -Skip WmiPersistence
.NOTES
    Run in an elevated PowerShell for full coverage. Requires PowerShell 5.1+.
    Exit code: 0 = no FAILs, 1 = one or more FAILs.
#>
[CmdletBinding()]
param(
    [string]   $ConfigPath = (Join-Path $PSScriptRoot 'ad-audit.config.psd1'),
    [string]   $OutFile    = '',
    [string[]] $Only       = @(),
    [string[]] $Skip       = @(),
    [switch]   $NoColor
)

# ---------- load config (with defaults) --------------------------------------
$default = @{
    ScoredPorts = @(80,443,3389); AllowedListenPorts = @(53,88,135,139,389,445,464,636,3268,3269,3389,80,443)
    AdminSubnet = ''; ScoringCidr = ''; ExpectedLocalAdmins = @('Administrator')
    ExpectedPrivilegedMembers = @{ 'Domain Admins'=@('Administrator'); 'Enterprise Admins'=@('Administrator'); 'Administrators'=@('Administrator') }
    ExpectedSpnAccounts = @(); MaxKrbtgtAgeDays = 180; RecentAccountHours = 24; MinPasswordLength = 12
    Checks = @{}
}
$cfg = $default.Clone()
if (Test-Path $ConfigPath) {
    try {
        $loaded = Import-PowerShellDataFile -Path $ConfigPath
        foreach ($k in $loaded.Keys) { $cfg[$k] = $loaded[$k] }
    } catch { Write-Warning "Could not parse config '$ConfigPath': $_. Using defaults." }
} else { Write-Warning "Config '$ConfigPath' not found; using defaults." }

# Default all checks to ON if not specified
$allChecks = @('LocalAdmins','LocalUsers','PrivilegedGroups','Krbtgt','PasswordPolicy',
    'PwdNeverExpires','PwdNotRequired','ReversibleEncrypt','Kerberoast','AsrepRoast','Delegation',
    'AdminCountStale','RecentAccounts','Smbv1','Firewall','Listeners','Outbound','ScheduledTasks',
    'Services','RunKeys','WmiPersistence','LsaProtections','Logging',
    'Llmnr','SmbSigning','NtlmHardening','AnonymousAccess','Spooler','HiveNightmare','SmbGhost',
    'WebClient','CredentialGuard','Zerologon','MachineAccountQuota','LdapSigning','DcsyncRights',
    'AdcsTemplates','NamedPipes','IISModules','PortProxy','MemoryScan')
foreach ($c in $allChecks) { if (-not $cfg.Checks.ContainsKey($c)) { $cfg.Checks[$c] = 1 } }

# ---------- output helpers ---------------------------------------------------
$script:nFail=0; $script:nWarn=0; $script:nPass=0; $script:nInfo=0
$useColor = -not $NoColor -and $Host.UI.RawUI
if ($OutFile) { '' | Set-Content -Path $OutFile }
function Out-Line($text,$plain,$color) {
    if ($useColor) { Write-Host $text -ForegroundColor $color } else { Write-Host $plain }
    if ($OutFile) { Add-Content -Path $OutFile -Value $plain }
}
function Section($t){ Out-Line "`n== $t ==" "== $t ==" 'Cyan' }
function Fail($m){ $script:nFail++; Out-Line "  [FAIL] $m" "  [FAIL] $m" 'Red' }
function Warn($m){ $script:nWarn++; Out-Line "  [WARN] $m" "  [WARN] $m" 'Yellow' }
function Pass($m){ $script:nPass++; Out-Line "  [PASS] $m" "  [PASS] $m" 'Green' }
function Info($m){ $script:nInfo++; Out-Line "  [INFO] $m" "  [INFO] $m" 'Gray' }

function Test-Enabled([string]$name){
    if ($Only.Count -gt 0 -and $Only -notcontains $name) { return $false }
    if ($Skip -contains $name) { return $false }
    return ($cfg.Checks[$name] -eq 1)
}
function Test-PublicIP([string]$ip){
    if ($ip -match '^(10\.|127\.|169\.254\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|::1|fe80|224\.|239\.|255\.)') { return $false }
    if ($ip -eq '0.0.0.0' -or $ip -eq '::' -or [string]::IsNullOrWhiteSpace($ip)) { return $false }
    return $true
}

$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { Warn 'Not elevated — several checks will be incomplete. Re-run as Administrator.' }

Import-Module ActiveDirectory -ErrorAction SilentlyContinue
$hasAD = $null -ne (Get-Command Get-ADUser -ErrorAction SilentlyContinue)

Out-Line ("CCDC Windows/AD Audit — {0} — {1}" -f $env:COMPUTERNAME,(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')) `
         ("CCDC Windows/AD Audit — {0} — {1}" -f $env:COMPUTERNAME,(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')) 'White'
if (-not $hasAD) { Info 'ActiveDirectory module not available — domain checks skipped (run on a DC or RSAT host for those).' }

# =============================================================================
# LOCAL CHECKS
# =============================================================================
function Check-LocalAdmins {
    Section 'Local Administrators group'
    try {
        $members = Get-LocalGroupMember -Group 'Administrators' -ErrorAction Stop
        foreach ($m in $members) {
            $short = ($m.Name -split '\\')[-1]
            if ($cfg.ExpectedLocalAdmins -contains $short -or $cfg.ExpectedLocalAdmins -contains $m.Name) {
                Pass "Local admin expected: $($m.Name)"
            } else { Fail "Unexpected local Administrator: $($m.Name)  (backdoor / privesc)" }
        }
    } catch { Info "Get-LocalGroupMember failed ($_); try 'net localgroup Administrators'." }
}
function Check-LocalUsers {
    Section 'Local users & Guest account'
    try {
        Get-LocalUser | ForEach-Object {
            if ($_.Name -eq 'Guest' -and $_.Enabled) { Fail 'Guest account is ENABLED' }
            elseif ($_.Enabled) { Info "Enabled local user: $($_.Name)" }
        }
    } catch { Info "Get-LocalUser not available ($_)." }
}

# =============================================================================
# ACTIVE DIRECTORY CHECKS
# =============================================================================
function Check-PrivilegedGroups {
    Section 'AD privileged group membership'
    if (-not $hasAD) { Info 'skipped (no AD module)'; return }
    foreach ($grp in $cfg.ExpectedPrivilegedMembers.Keys) {
        $expected = $cfg.ExpectedPrivilegedMembers[$grp]
        try {
            $members = Get-ADGroupMember -Identity $grp -Recursive -ErrorAction Stop | Select-Object -Expand SamAccountName
        } catch { Info "Group '$grp' not found or unreadable"; continue }
        if (-not $members) { Pass "$grp is empty"; continue }
        foreach ($mem in $members) {
            if ($expected -contains $mem) { Pass "$grp member expected: $mem" }
            else { Fail "UNEXPECTED $grp member: $mem  (remove if not authorized)" }
        }
    }
}
function Check-Krbtgt {
    Section 'krbtgt password age (Golden Ticket)'
    if (-not $hasAD) { Info 'skipped (no AD module)'; return }
    try {
        $k = Get-ADUser krbtgt -Properties PasswordLastSet
        $age = (New-TimeSpan -Start $k.PasswordLastSet -End (Get-Date)).Days
        if ($age -gt $cfg.MaxKrbtgtAgeDays) { Warn "krbtgt password is $age days old (> $($cfg.MaxKrbtgtAgeDays)). If compromise suspected, rotate TWICE." }
        else { Pass "krbtgt password age: $age days" }
    } catch { Info "krbtgt lookup failed ($_)" }
}
function Check-PasswordPolicy {
    Section 'Domain password / lockout policy'
    if (-not $hasAD) { Info 'skipped (no AD module)'; return }
    try {
        $p = Get-ADDefaultDomainPasswordPolicy
        if ($p.MinPasswordLength -lt $cfg.MinPasswordLength) { Warn "Min password length $($p.MinPasswordLength) < expected $($cfg.MinPasswordLength)" } else { Pass "Min password length $($p.MinPasswordLength)" }
        if (-not $p.ComplexityEnabled) { Warn 'Password complexity DISABLED' } else { Pass 'Password complexity enabled' }
        if ($p.LockoutThreshold -eq 0) { Warn 'Account lockout DISABLED (0) — brute force unthrottled' } else { Pass "Lockout threshold $($p.LockoutThreshold)" }
    } catch { Info "policy lookup failed ($_)" }
}
function Check-PwdNeverExpires {
    Section 'Enabled accounts with non-expiring passwords'
    if (-not $hasAD) { Info 'skipped (no AD module)'; return }
    $u = Get-ADUser -Filter 'Enabled -eq $true -and PasswordNeverExpires -eq $true' -ErrorAction SilentlyContinue
    if (-not $u) { Pass 'None' } else { foreach ($x in $u) { Warn "PasswordNeverExpires: $($x.SamAccountName)" } }
}
function Check-PwdNotRequired {
    Section 'Accounts with PASSWD_NOTREQD'
    if (-not $hasAD) { Info 'skipped (no AD module)'; return }
    $u = Get-ADUser -Filter 'PasswordNotRequired -eq $true' -ErrorAction SilentlyContinue
    if (-not $u) { Pass 'None' } else { foreach ($x in $u) { Fail "Password NOT required: $($x.SamAccountName)" } }
}
function Check-ReversibleEncrypt {
    Section 'Reversible password encryption'
    if (-not $hasAD) { Info 'skipped (no AD module)'; return }
    $u = Get-ADUser -Filter 'AllowReversiblePasswordEncryption -eq $true' -ErrorAction SilentlyContinue
    if (-not $u) { Pass 'None' } else { foreach ($x in $u) { Fail "Reversible encryption enabled: $($x.SamAccountName)" } }
}
function Check-Kerberoast {
    Section 'Kerberoastable accounts (user SPNs)'
    if (-not $hasAD) { Info 'skipped (no AD module)'; return }
    $u = Get-ADUser -Filter 'ServicePrincipalName -like "*"' -Properties ServicePrincipalName,MemberOf -ErrorAction SilentlyContinue |
         Where-Object { $_.SamAccountName -ne 'krbtgt' }
    if (-not $u) { Pass 'No user accounts with SPNs' ; return }
    foreach ($x in $u) {
        if ($cfg.ExpectedSpnAccounts -contains $x.SamAccountName) { Pass "SPN account expected: $($x.SamAccountName)"; continue }
        $priv = $x.MemberOf -match 'Domain Admins|Enterprise Admins|Administrators'
        if ($priv) { Fail "PRIVILEGED kerberoastable account: $($x.SamAccountName) (high risk — remove SPN or use gMSA)" }
        else { Warn "Kerberoastable account: $($x.SamAccountName) (ensure long random password)" }
    }
}
function Check-AsrepRoast {
    Section 'AS-REP roastable accounts (no pre-auth)'
    if (-not $hasAD) { Info 'skipped (no AD module)'; return }
    $u = Get-ADUser -Filter 'DoesNotRequirePreAuth -eq $true' -ErrorAction SilentlyContinue
    if (-not $u) { Pass 'None' } else { foreach ($x in $u) { Fail "No Kerberos pre-auth: $($x.SamAccountName)" } }
}
function Check-Delegation {
    Section 'Kerberos delegation (unconstrained / constrained / RBCD)'
    if (-not $hasAD) { Info 'skipped (no AD module)'; return }
    # --- Unconstrained (TRUSTED_FOR_DELEGATION) ---
    $unc = Get-ADComputer -Filter 'TrustedForDelegation -eq $true' -ErrorAction SilentlyContinue
    if ($unc) { foreach ($c in $unc) { if ($c.Name -notmatch '^DC') { Warn "Unconstrained delegation on computer: $($c.Name) (TGTs cached here — coerce+relay risk)" } } } else { Pass 'No unconstrained-delegation computers (excluding DCs)' }
    $ucu = Get-ADUser -Filter 'TrustedForDelegation -eq $true' -ErrorAction SilentlyContinue
    if ($ucu) { foreach ($x in $ucu) { Fail "User account trusted for delegation: $($x.SamAccountName)" } }
    # --- Constrained + protocol transition (msDS-AllowedToDelegateTo / T2A4D) ---
    try {
        $cd = Get-ADObject -LDAPFilter '(msDS-AllowedToDelegateTo=*)' -Properties msDS-AllowedToDelegateTo,userAccountControl,sAMAccountName -ErrorAction SilentlyContinue
        foreach ($o in $cd) {
            $to = ($o.'msDS-AllowedToDelegateTo') -join ', '
            # 0x1000000 = TRUSTED_TO_AUTH_FOR_DELEGATION (protocol transition — higher risk)
            if ($o.userAccountControl -band 0x1000000) { Fail "Constrained delegation w/ protocol transition: $($o.sAMAccountName) -> $to (any-user impersonation)" }
            else { Warn "Constrained delegation: $($o.sAMAccountName) -> $to (verify target list)" }
        }
    } catch { Info "constrained-delegation query failed ($_)" }
    # --- Resource-Based Constrained Delegation (msDS-AllowedToActOnBehalfOfOtherIdentity) ---
    try {
        $rbcd = Get-ADComputer -Filter * -Properties 'msDS-AllowedToActOnBehalfOfOtherIdentity','PrincipalsAllowedToDelegateToAccount' -ErrorAction SilentlyContinue |
                Where-Object { $_.'msDS-AllowedToActOnBehalfOfOtherIdentity' }
        if ($rbcd) {
            foreach ($c in $rbcd) {
                $who = try { ($c.PrincipalsAllowedToDelegateToAccount | ForEach-Object { $_.ToString() }) -join ', ' } catch { '(raw SD present)' }
                Warn "RBCD configured on $($c.Name): allowed = $who (attacker-writable = takeover; confirm expected)"
            }
        } else { Pass 'No computers with RBCD (msDS-AllowedToActOnBehalfOfOtherIdentity) set' }
    } catch { Info "RBCD query failed ($_)" }
}
function Check-AdminCountStale {
    Section 'Stale adminCount=1 accounts (AdminSDHolder)'
    if (-not $hasAD) { Info 'skipped (no AD module)'; return }
    $ac = Get-ADUser -Filter 'adminCount -eq 1' -Properties adminCount -ErrorAction SilentlyContinue
    if (-not $ac) { Pass 'None'; return }
    foreach ($x in $ac) { Info "adminCount=1: $($x.SamAccountName) (verify still-privileged; residual ACLs can be a backdoor)" }
}
function Check-RecentAccounts {
    Section "Accounts created/changed in last $($cfg.RecentAccountHours)h"
    if (-not $hasAD) { Info 'skipped (no AD module)'; return }
    $cut = (Get-Date).AddHours(-1 * $cfg.RecentAccountHours)
    $u = Get-ADUser -Filter * -Properties whenCreated,whenChanged -ErrorAction SilentlyContinue |
         Where-Object { $_.whenCreated -gt $cut -or $_.whenChanged -gt $cut }
    if (-not $u) { Pass 'No recently created/changed accounts' ; return }
    foreach ($x in $u) { Warn "Recent account change: $($x.SamAccountName) (created $($x.whenCreated), changed $($x.whenChanged))" }
}

# =============================================================================
# HOST HARDENING / PERSISTENCE CHECKS
# =============================================================================
function Check-Smbv1 {
    Section 'SMBv1 (EternalBlue)'
    try {
        $s = Get-SmbServerConfiguration -ErrorAction Stop
        if ($s.EnableSMB1Protocol) { Fail 'SMBv1 server protocol ENABLED — disable it' } else { Pass 'SMBv1 server protocol disabled' }
    } catch { Info "Get-SmbServerConfiguration unavailable ($_)" }
}
function Check-Firewall {
    Section 'Windows Firewall posture'
    try {
        Get-NetFirewallProfile -ErrorAction Stop | ForEach-Object {
            if (-not $_.Enabled) { Fail "Firewall profile '$($_.Name)' is DISABLED" } else { Pass "Firewall profile '$($_.Name)' enabled" }
            if ($_.DefaultInboundAction -ne 'Block') { Warn "Profile '$($_.Name)' inbound default is $($_.DefaultInboundAction) (want Block)" }
            if ($_.DefaultOutboundAction -ne 'Block') { Warn "Profile '$($_.Name)' OUTBOUND default is $($_.DefaultOutboundAction) — beacons can egress (want Block + explicit allows)" } else { Pass "Profile '$($_.Name)' outbound default Block (C2 containment)" }
        }
    } catch { Info "Get-NetFirewallProfile unavailable ($_)" }
    Info ("Scored ports {0} must be open by PORT (scorer IP rotates)." -f ($cfg.ScoredPorts -join ','))
    if ($cfg.AdminSubnet) { Info "Admin ports (3389/5985) should be scoped to $($cfg.AdminSubnet) only." }
}
function Check-Listeners {
    Section 'Listening TCP ports vs allowlist'
    try {
        $ports = Get-NetTCPConnection -State Listen -ErrorAction Stop | Select-Object -Expand LocalPort -Unique | Sort-Object
        foreach ($p in $ports) {
            if ($cfg.AllowedListenPorts -contains $p) { Pass "Listening port allowed: $p" }
            else { Fail "Unexpected listening port: $p  (close it or add to allowlist)" }
        }
    } catch { Info "Get-NetTCPConnection unavailable ($_)" }
}
function Check-Outbound {
    Section 'Established outbound to public IPs (possible C2)'
    try {
        $conns = Get-NetTCPConnection -State Established -ErrorAction Stop | Where-Object { Test-PublicIP $_.RemoteAddress }
        if (-not $conns) { Pass 'No established outbound to public IPs right now'; return }
        $conns | Group-Object RemoteAddress | ForEach-Object {
            $proc = try { (Get-Process -Id ($_.Group[0].OwningProcess) -ErrorAction Stop).ProcessName } catch { '?' }
            Warn "Outbound to $($_.Name) by '$proc' (baseline this — beacons hide here)"
        }
    } catch { Info "Get-NetTCPConnection unavailable ($_)" }
}
function Check-ScheduledTasks {
    Section 'Non-Microsoft scheduled tasks (persistence)'
    try {
        $tasks = Get-ScheduledTask -ErrorAction Stop | Where-Object { $_.TaskPath -notlike '\Microsoft\*' -and $_.State -ne 'Disabled' }
        if (-not $tasks) { Pass 'No non-Microsoft enabled tasks'; return }
        foreach ($t in $tasks) {
            $act = ($t.Actions | ForEach-Object { $_.Execute }) -join '; '
            Warn "Task: $($t.TaskPath)$($t.TaskName)  -> $act"
        }
    } catch { Info "Get-ScheduledTask unavailable ($_)" }
}
function Check-Services {
    Section 'Suspicious services (unquoted paths / odd locations)'
    try {
        $svcs = Get-CimInstance Win32_Service -ErrorAction Stop
        foreach ($s in $svcs) {
            if (-not $s.PathName) { continue }
            $bin = $s.PathName.Trim()
            if ($bin -notmatch '^"') {
                # isolate the executable path (up to and including .exe), then test for a space
                $exePart = if ($bin -match '(?i)^(.*?\.exe)') { $matches[1] } else { ($bin -split '\s+')[0] }
                if ($exePart -match '\s') { Warn "Unquoted service path with space: $($s.Name) -> $bin" }
            }
            if ($bin -match '(?i)\\(Users|Temp|AppData|ProgramData|Public)\\') { Fail "Service binary in user-writable path: $($s.Name) -> $bin" }
        }
        Pass 'Service path scan complete (review any WARN/FAIL above)'
    } catch { Info "Win32_Service query failed ($_)" }
}
function Check-RunKeys {
    Section 'Run keys (autostart persistence)'
    $paths = @(
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce'
    )
    $found = $false
    foreach ($p in $paths) {
        if (Test-Path $p) {
            $item = Get-ItemProperty $p -ErrorAction SilentlyContinue
            $item.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object {
                $found = $true; Info "$p :: $($_.Name) = $($_.Value)"
            }
        }
    }
    if (-not $found) { Pass 'No Run-key autostart entries' }
}
function Check-WmiPersistence {
    Section 'WMI event-subscription persistence'
    try {
        $f = Get-CimInstance -Namespace root\subscription -Class __EventFilter -ErrorAction SilentlyContinue
        $c = Get-CimInstance -Namespace root\subscription -Class __EventConsumer -ErrorAction SilentlyContinue
        $b = Get-CimInstance -Namespace root\subscription -Class __FilterToConsumerBinding -ErrorAction SilentlyContinue
        if (-not $f -and -not $c -and -not $b) { Pass 'No WMI event subscriptions' ; return }
        foreach ($x in $f) { Warn "WMI __EventFilter: $($x.Name) query=$($x.Query)" }
        foreach ($x in $c) { Fail "WMI __EventConsumer: $($x.Name) (common fileless persistence)" }
    } catch { Info "WMI subscription query failed ($_)" }
}
function Check-LsaProtections {
    Section 'Credential-theft protections'
    $wd = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Name UseLogonCredential -ErrorAction SilentlyContinue).UseLogonCredential
    if ($wd -eq 1) { Fail 'WDigest UseLogonCredential=1 (plaintext creds in memory — set to 0)' } else { Pass 'WDigest not caching plaintext creds' }
    $ppl = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name RunAsPPL -ErrorAction SilentlyContinue).RunAsPPL
    if ($ppl -eq 1) { Pass 'LSASS protected (RunAsPPL=1)' } else { Info 'LSASS not running protected (RunAsPPL not set) — consider enabling' }
}
function Check-Logging {
    Section 'Logging / EDR presence (informational)'
    if (Get-Service -Name Sysmon*,SysmonDrv -ErrorAction SilentlyContinue) { Pass 'Sysmon appears installed' } else { Info 'Sysmon not detected' }
    $sb = (Get-ItemProperty 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name EnableScriptBlockLogging -ErrorAction SilentlyContinue).EnableScriptBlockLogging
    if ($sb -eq 1) { Pass 'PowerShell ScriptBlock logging enabled' } else { Info 'PowerShell ScriptBlock logging not enabled' }
}

# =============================================================================
# NTLM RELAY / POISONING / LEGACY-PROTOCOL HARDENING
# =============================================================================
function Get-RegVal($path,$name) {
    try { (Get-ItemProperty -Path $path -Name $name -ErrorAction Stop).$name } catch { $null }
}

function Check-Llmnr {
    Section 'LLMNR / NBT-NS poisoning (Responder)'
    $llmnr = Get-RegVal 'HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient' 'EnableMulticast'
    if ($llmnr -eq 0) { Pass 'LLMNR disabled (EnableMulticast=0)' }
    else { Fail 'LLMNR is ENABLED (set DNSClient\EnableMulticast=0 via GPO) — Responder can capture/relay hashes' }
    # NBT-NS is per-interface (2 = disabled)
    try {
        $ifaces = Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces' -ErrorAction Stop
        $bad = @()
        foreach ($i in $ifaces) { $o = (Get-ItemProperty $i.PSPath -ErrorAction SilentlyContinue).NetbiosOptions; if ($o -ne 2) { $bad += $i.PSChildName } }
        if ($bad.Count -eq 0) { Pass 'NetBIOS-over-TCP disabled on all interfaces (NetbiosOptions=2)' }
        else { Warn "NBT-NS still enabled on $($bad.Count) interface(s) — set NetbiosOptions=2 (poisoning vector)" }
    } catch { Info "NetBT interface enumeration failed ($_)" }
}

function Check-SmbSigning {
    Section 'SMB signing (NTLM relay defense)'
    try {
        $s = Get-SmbServerConfiguration -ErrorAction Stop
        if ($s.RequireSecuritySignature) { Pass 'SMB server signing REQUIRED' }
        else { Fail 'SMB server signing NOT required — host is relayable (RequireSecuritySignature=$true)' }
    } catch { Info "Get-SmbServerConfiguration unavailable ($_)" }
    try {
        $c = Get-SmbClientConfiguration -ErrorAction Stop
        if ($c.RequireSecuritySignature) { Pass 'SMB client signing required' } else { Warn 'SMB client signing not required (relay exposure)' }
    } catch { }
}

function Check-NtlmHardening {
    Section 'NTLMv1 / LM hash storage'
    $lm = Get-RegVal 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'LmCompatibilityLevel'
    if ($null -eq $lm) { Warn 'LmCompatibilityLevel not set — default may allow NTLMv1/LM; set to 5' }
    elseif ($lm -ge 5) { Pass "LmCompatibilityLevel=$lm (NTLMv2 only, refuses LM/NTLMv1)" }
    else { Fail "LmCompatibilityLevel=$lm allows NTLMv1/LM downgrade — set to 5" }
    $nolm = Get-RegVal 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'NoLmHash'
    if ($nolm -eq 1) { Pass 'NoLmHash=1 (LM hashes not stored)' } else { Warn 'NoLmHash not enabled — LM hashes may be stored (set to 1)' }
}

function Check-AnonymousAccess {
    Section 'Anonymous / null-session enumeration'
    $lsa = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    $ra  = Get-RegVal $lsa 'RestrictAnonymous'
    $ras = Get-RegVal $lsa 'RestrictAnonymousSAM'
    $rrs = Get-RegVal $lsa 'RestrictRemoteSAM'
    $eia = Get-RegVal $lsa 'EveryoneIncludesAnonymous'
    if ($ras -eq 1) { Pass 'RestrictAnonymousSAM=1' } else { Warn 'RestrictAnonymousSAM not 1 — SAM enumerable anonymously' }
    if ($eia -eq 1) { Fail 'EveryoneIncludesAnonymous=1 (anonymous gets Everyone rights)' } else { Pass 'EveryoneIncludesAnonymous not enabled' }
    if ($rrs) { Pass "RestrictRemoteSAM SDDL set (blocks remote SAM enum by non-admins)" } else { Info 'RestrictRemoteSAM (O:...) not set — consider adding to block SharpHound SAMR' }
    # null-session shares/pipes
    $np = Get-RegVal 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'NullSessionShares'
    if ($np) { Warn "NullSessionShares configured: $($np -join ',')" }
}

function Check-Spooler {
    Section 'Print Spooler (PrintNightmare / PrinterBug)'
    $svc = Get-Service -Name Spooler -ErrorAction SilentlyContinue
    if ($svc) {
        if ($svc.Status -eq 'Running') {
            if ($hasAD) { Fail 'Print Spooler RUNNING on a DC/AD host — disable (PrinterBug coercion + PrintNightmare)' }
            else { Warn 'Print Spooler running — disable if this host is not a print server (PrintNightmare)' }
        } else { Pass "Print Spooler is $($svc.Status)" }
    } else { Pass 'Print Spooler not present' }
    # Point-and-Print registry (PrintNightmare RCE knobs)
    $pnp = 'HKLM:\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint'
    $nw  = Get-RegVal $pnp 'NoWarningNoElevationOnInstall'
    $rdi = Get-RegVal $pnp 'RestrictDriverInstallationToAdministrators'
    if ($nw -eq 1) { Fail 'PointAndPrint NoWarningNoElevationOnInstall=1 — non-admin driver install (PrintNightmare RCE)' }
    if ($rdi -eq 0) { Fail 'RestrictDriverInstallationToAdministrators=0 — non-admins can install drivers' }
    elseif ($rdi -eq 1) { Pass 'RestrictDriverInstallationToAdministrators=1' }
}

function Check-HiveNightmare {
    Section 'HiveNightmare / SeriousSAM (CVE-2021-36934)'
    $sam = "$env:SystemRoot\System32\config\SAM"
    try {
        $acl = (icacls $sam) 2>$null
        if ($acl -match 'BUILTIN\\Users.*\(R') { Fail 'SAM hive is READABLE by BUILTIN\Users (CVE-2021-36934) — fix ACL + delete shadow copies' }
        else { Pass 'SAM hive not user-readable' }
    } catch { Info "icacls on SAM failed ($_)" }
    # exploitable shadow copies expose the readable hive
    try {
        $sc = (vssadmin list shadows) 2>$null | Select-String 'Shadow Copy Volume'
        if ($sc) { Warn "$($sc.Count) VSS shadow copy(ies) present — can expose old SAM even after ACL fix; review" }
    } catch { }
}

function Check-SmbGhost {
    Section 'SMBGhost (CVE-2020-0796, SMBv3 compression)'
    $build = [int](Get-RegVal 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' 'CurrentBuildNumber')
    if ($build -eq 18362 -or $build -eq 18363) {
        $dc = Get-RegVal 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'DisableCompression'
        if ($dc -eq 1) { Pass 'SMB compression disabled (SMBGhost mitigated)' }
        else { Fail "Build $build vulnerable to SMBGhost and compression not disabled — set DisableCompression=1 + patch" }
    } else { Pass "OS build $build not in SMBGhost range (1903/1909 only)" }
}

function Check-WebClient {
    Section 'WebClient / WebDAV (LDAP relay coercion)'
    $svc = Get-Service -Name WebClient -ErrorAction SilentlyContinue
    if (-not $svc) { Pass 'WebClient (WebDAV) service not present' }
    elseif ($svc.Status -eq 'Running') { Warn 'WebClient (WebDAV) service RUNNING — enables HTTP->LDAP relay coercion; disable on servers' }
    else { Pass "WebClient service is $($svc.Status)" }
}

function Check-CredentialGuard {
    Section 'Credential Guard / LSA isolation'
    try {
        $dg = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction Stop
        if ($dg.SecurityServicesRunning -contains 1) { Pass 'Credential Guard is running (SecurityServicesRunning contains 1)' }
        else { Info 'Credential Guard not running — enable to protect derived creds (VBS required)' }
    } catch { Info "DeviceGuard query unavailable ($_)" }
}

function Check-Zerologon {
    Section 'Zerologon (CVE-2020-1472) enforcement'
    if (-not $hasAD) { Info 'Not a DC — Netlogon enforcement check is DC-scoped; skipping'; return }
    $fs = Get-RegVal 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' 'FullSecureChannelProtection'
    if ($fs -eq 1) { Pass 'FullSecureChannelProtection=1 (Zerologon enforcement on)' }
    else { Warn 'FullSecureChannelProtection not =1 — ensure DCs are patched (Aug 2020+) and enforcement is on' }
    Info 'Also review Event IDs 5827/5828/5829 for vulnerable Netlogon connections.'
}

# =============================================================================
# AD MISCONFIG (machine account quota, LDAP signing, DCSync ACL, ADCS)
# =============================================================================
function Check-MachineAccountQuota {
    Section 'Machine Account Quota (NoPAC / RBCD / KrbRelayUp)'
    if (-not $hasAD) { Info 'skipped (no AD module)'; return }
    try {
        $dn = (Get-ADDomain).DistinguishedName
        $maq = (Get-ADObject -Identity $dn -Properties 'ms-DS-MachineAccountQuota').'ms-DS-MachineAccountQuota'
        if ($maq -gt 0) { Fail "ms-DS-MachineAccountQuota=$maq — any user can add machine accounts (NoPAC/RBCD/KrbRelayUp). Set to 0." }
        else { Pass 'ms-DS-MachineAccountQuota=0' }
    } catch { Info "MachineAccountQuota lookup failed ($_)" }
}

function Check-LdapSigning {
    Section 'LDAP signing & channel binding (relay defense)'
    $si = Get-RegVal 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' 'LDAPServerIntegrity'
    if ($si -eq 2) { Pass 'LDAPServerIntegrity=2 (LDAP signing required)' }
    elseif ($null -eq $si) { Info 'LDAPServerIntegrity not set (only meaningful on a DC) — require signing on DCs' }
    else { Fail "LDAPServerIntegrity=$si — LDAP signing NOT required (relayable to LDAP). Set to 2 on DCs." }
    $cb = Get-RegVal 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' 'LdapEnforceChannelBinding'
    if ($cb -eq 2) { Pass 'LdapEnforceChannelBinding=2 (enforced)' }
    elseif ($null -ne $cb) { Warn "LdapEnforceChannelBinding=$cb — set to 2 to block LDAPS relay" }
    else { Info 'LdapEnforceChannelBinding not set — enable on DCs to block LDAPS relay' }
}

function Check-DcsyncRights {
    Section 'DCSync rights on domain object (replication ACL)'
    if (-not $hasAD) { Info 'skipped (no AD module)'; return }
    # Extended-right GUIDs: GetChanges, GetChangesAll, GetChangesInFilteredSet
    $replGuids = @{
        '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2' = 'DS-Replication-Get-Changes'
        '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2' = 'DS-Replication-Get-Changes-All'
        '89e95b76-444d-4c62-991a-0facbeda640c' = 'DS-Replication-Get-Changes-In-Filtered-Set'
    }
    # Principals that legitimately hold replication rights
    $expected = 'Domain Admins|Enterprise Admins|Administrators|Domain Controllers|Enterprise Domain Controllers|SYSTEM|BUILTIN\\Administrators|Enterprise Read-only Domain Controllers'
    try {
        $dn = (Get-ADDomain).DistinguishedName
        $acl = (Get-Acl "AD:$dn").Access | Where-Object {
            $_.ObjectType -and $replGuids.ContainsKey($_.ObjectType.ToString()) -and $_.AccessControlType -eq 'Allow'
        }
        $flagged = $false
        foreach ($ace in $acl) {
            $id = $ace.IdentityReference.ToString()
            if ($id -notmatch $expected) {
                $flagged = $true
                Fail "DCSync right '$($replGuids[$ace.ObjectType.ToString()])' granted to: $id (non-default — DCSync backdoor)"
            }
        }
        if (-not $flagged) { Pass 'Only default principals hold DS-Replication (DCSync) rights' }
    } catch { Info "Domain ACL read failed ($_)" }
}

function Check-AdcsTemplates {
    Section 'ADCS vulnerable certificate templates (ESC1/2/9)'
    if (-not $hasAD) { Info 'skipped (no AD module)'; return }
    try {
        $cfgNC = (Get-ADRootDSE).configurationNamingContext
        $tpath = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$cfgNC"
        $tpls = Get-ADObject -SearchBase $tpath -LDAPFilter '(objectClass=pKICertificateTemplate)' `
                 -Properties msPKI-Certificate-Name-Flag,pKIExtendedKeyUsage,msPKI-Enrollment-Flag,cn -ErrorAction Stop
    } catch { Info "No ADCS templates found / not readable ($_) — likely no CA in domain"; return }
    if (-not $tpls) { Pass 'No certificate templates present'; return }
    $ENROLLEE_SUPPLIES_SUBJECT = 0x1
    $NO_SECURITY_EXTENSION     = 0x80000
    $authEkus = @('1.3.6.1.5.5.7.3.2','1.3.6.1.5.2.3.4','1.3.6.1.4.1.311.20.2.2','2.5.29.37.0')  # ClientAuth, PKINIT, SmartcardLogon, AnyPurpose
    $any = $false
    foreach ($t in $tpls) {
        $nameFlag = [int64]($t.'msPKI-Certificate-Name-Flag')
        $enrFlag  = [int64]($t.'msPKI-Enrollment-Flag')
        $ekus     = @($t.'pKIExtendedKeyUsage')
        $suppliesSubject = ($nameFlag -band $ENROLLEE_SUPPLIES_SUBJECT) -ne 0
        $hasAuthEku = $false; foreach ($e in $ekus) { if ($authEkus -contains $e) { $hasAuthEku = $true } }
        $noEku = ($ekus.Count -eq 0)
        # ESC1: enrollee supplies subject + auth EKU (manager-approval bit 0x2 not set)
        if ($suppliesSubject -and ($hasAuthEku -or $noEku)) {
            $any = $true; Fail "ESC1-like template '$($t.cn)': ENROLLEE_SUPPLIES_SUBJECT + auth/any EKU — verify enrollment ACL & require manager approval"
        }
        # ESC2: Any Purpose or no EKU
        if ($noEku -or ($ekus -contains '2.5.29.37.0')) {
            $any = $true; Warn "ESC2-like template '$($t.cn)': Any-Purpose / no EKU (usable for auth) — restrict"
        }
        # ESC9: no security extension flag
        if (($enrFlag -band $NO_SECURITY_EXTENSION) -ne 0) {
            $any = $true; Warn "ESC9-like template '$($t.cn)': CT_FLAG_NO_SECURITY_EXTENSION set — ensure StrongCertificateBindingEnforcement=2 on DCs"
        }
    }
    if (-not $any) { Pass 'No ESC1/2/9-flagged templates (still verify enrollment ACLs manually)' }
    # ESC9 companion: strong cert binding on this host if it is a DC
    $scb = Get-RegVal 'HKLM:\SYSTEM\CurrentControlSet\Services\Kdc' 'StrongCertificateBindingEnforcement'
    if ($null -ne $scb) { if ($scb -eq 2) { Pass 'StrongCertificateBindingEnforcement=2' } else { Warn "StrongCertificateBindingEnforcement=$scb — set to 2 on every DC (ESC9/cert-mapping)" } }
}

# =============================================================================
# ADVANCED IMPLANT HUNT (custom / pre-planted / in-memory C2)
# Sources: Microsoft (IIS modules), Elastic Security Labs (Hunting In Memory),
# hasherezade (pe-sieve/hollows_hunter), WithSecure (CS named pipes).
# =============================================================================
function Check-NamedPipes {
    Section 'Named-pipe anomalies (C2 SMB / inter-beacon channels)'
    try { $pipes = Get-ChildItem '\\.\pipe\' -ErrorAction Stop | Select-Object -Expand Name }
    catch { Info "Could not enumerate named pipes ($_)"; return }
    $flagged = $false
    foreach ($n in $pipes) {
        # Cobalt Strike defaults + Mythic agent-UUID pipes = near-zero-FP IOCs
        if ($n -match '(?i)^(msagent_|postex_[0-9a-f]|postex_ssh_|status_[0-9]|MSSE-[0-9]|interprocess_|wkssvc[0-9])' -or
            $n -match '^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$') {
            $flagged = $true; Fail "Suspicious named pipe: $n  (Cobalt Strike / Mythic C2 pattern)"
        }
        elseif ($n -match '^[a-f0-9]{16,}$') {
            $flagged = $true; Warn "Long hex-named pipe: $n  (possible custom C2 inter-process channel — verify owner)"
        }
    }
    if (-not $flagged) { Pass 'No named pipes matching known C2 patterns' }
}

function Check-IISModules {
    Section 'IIS native modules (memory-only web-shell backdoors)'
    if (-not (Get-Service -Name W3SVC -ErrorAction SilentlyContinue)) { Pass 'IIS (W3SVC) not installed'; return }
    $appcmd = Join-Path $env:SystemRoot 'System32\inetsrv\appcmd.exe'
    if (Test-Path $appcmd) {
        $mods = & $appcmd list modules 2>$null
        $bad = $false
        foreach ($m in $mods) {
            if ($m -match '(?i)image:(.+\.dll)') {
                $img = $matches[1].Trim()
                # legit native modules live under inetsrv or the .NET framework dirs
                if ($img -notmatch '(?i)\\System32\\inetsrv\\' -and $img -notmatch '(?i)\\Microsoft\.NET\\' -and $img -notmatch '(?i)\\Windows\\assembly\\') {
                    Fail "IIS native module DLL outside inetsrv/.NET (memory-resident backdoor?): $img"; $bad = $true
                }
            }
        }
        if (-not $bad) { Pass 'No IIS native module DLLs from unexpected paths' }
        Info 'Native IIS modules are rare on production — review the full list; any unknown one can proxy/intercept HTTP with no on-disk web shell.'
    } else { Info 'appcmd.exe not found; enumerate with Get-WebGlobalModule (Import-Module WebAdministration).' }
    # The audit log that records module installs (EID 29) and config edits (EID 50)
    try {
        $l = Get-WinEvent -ListLog 'Microsoft-IIS-Configuration/Operational' -ErrorAction Stop
        if ($l.IsEnabled) { Pass 'Microsoft-IIS-Configuration/Operational enabled (EID 29 = module add, EID 50 = config change)' }
        else { Warn 'Microsoft-IIS-Configuration/Operational is DISABLED — enable it (wevtutil sl Microsoft-IIS-Configuration/Operational /e:true) to catch IIS-module backdoors' }
    } catch { Info 'Microsoft-IIS-Configuration/Operational log not present' }
}

function Check-PortProxy {
    Section 'netsh portproxy (port-piggyback / pivot)'
    $out = netsh interface portproxy show all 2>$null
    $rows = $out | Where-Object { $_ -match '^\s*\d+\.\d+\.\d+\.\d+|\*\s+\d' -or $_ -match '^\s*\d{1,5}\s' }
    if ($rows) {
        Warn 'netsh portproxy rules present — can forward a scored/legit port to a hidden listener or pivot inbound:'
        foreach ($r in ($out | Where-Object { $_ -match '\S' })) { Out-Line "        $r" "        $r" 'Yellow' }
    } else { Pass 'No netsh portproxy rules' }
}

function Check-MemoryScan {
    Section 'In-memory implant scan coverage (unbacked / injected code)'
    # A custom/fileless beacon leaves no disk artifact; the reliable catch is a
    # signature-independent memory scanner (unbacked executable memory, RWX,
    # threads starting in floating code). Pure PowerShell can't do this robustly,
    # so verify a scanner is staged and that injection telemetry is on.
    $tools = @()
    foreach ($t in 'pe-sieve.exe','pe-sieve64.exe','hollows_hunter.exe','hollows_hunter64.exe','Moneta.exe','Moneta64.exe') {
        $c = Get-Command $t -ErrorAction SilentlyContinue
        if ($c) { $tools += $c.Source }
    }
    if ($tools) { Pass "Memory scanner staged: $($tools -join ', ')  — run: hollows_hunter /loop /etw  (system-wide, catches injected/unbacked code)" }
    else { Info 'No pe-sieve/hollows_hunter/Moneta on PATH — stage one; it is the only reliable catch for custom in-memory beacons (unbacked/RWX regions).' }
    if (Get-Service -Name Sysmon*,SysmonDrv -ErrorAction SilentlyContinue) {
        Info 'Sysmon present — confirm config logs EID 8 (CreateRemoteThread), 10 (ProcessAccess to lsass 0x1010/0x1410), 25 (ProcessTampering/hollowing).'
    } else { Info 'No Sysmon — EID 8/10/25 injection telemetry unavailable; stage sysmon-modular for in-memory attack coverage.' }
}

# =============================================================================
# RUN
# =============================================================================
$map = [ordered]@{
    LocalAdmins       = 'Check-LocalAdmins';      LocalUsers      = 'Check-LocalUsers'
    PrivilegedGroups  = 'Check-PrivilegedGroups'; Krbtgt          = 'Check-Krbtgt'
    PasswordPolicy    = 'Check-PasswordPolicy';   PwdNeverExpires = 'Check-PwdNeverExpires'
    PwdNotRequired    = 'Check-PwdNotRequired';   ReversibleEncrypt='Check-ReversibleEncrypt'
    Kerberoast        = 'Check-Kerberoast';       AsrepRoast      = 'Check-AsrepRoast'
    Delegation        = 'Check-Delegation';       AdminCountStale = 'Check-AdminCountStale'
    RecentAccounts    = 'Check-RecentAccounts';   Smbv1           = 'Check-Smbv1'
    Firewall          = 'Check-Firewall';         Listeners       = 'Check-Listeners'
    Outbound          = 'Check-Outbound';         ScheduledTasks  = 'Check-ScheduledTasks'
    Services          = 'Check-Services';         RunKeys         = 'Check-RunKeys'
    WmiPersistence    = 'Check-WmiPersistence';   LsaProtections  = 'Check-LsaProtections'
    Logging           = 'Check-Logging'
    Llmnr             = 'Check-Llmnr';            SmbSigning      = 'Check-SmbSigning'
    NtlmHardening     = 'Check-NtlmHardening';    AnonymousAccess = 'Check-AnonymousAccess'
    Spooler           = 'Check-Spooler';          HiveNightmare   = 'Check-HiveNightmare'
    SmbGhost          = 'Check-SmbGhost';         WebClient       = 'Check-WebClient'
    CredentialGuard   = 'Check-CredentialGuard';  Zerologon       = 'Check-Zerologon'
    MachineAccountQuota = 'Check-MachineAccountQuota'; LdapSigning = 'Check-LdapSigning'
    DcsyncRights      = 'Check-DcsyncRights';      AdcsTemplates  = 'Check-AdcsTemplates'
    NamedPipes        = 'Check-NamedPipes';        IISModules     = 'Check-IISModules'
    PortProxy         = 'Check-PortProxy';         MemoryScan     = 'Check-MemoryScan'
}
foreach ($name in $map.Keys) {
    if (Test-Enabled $name) { & $map[$name] }
}

Out-Line ("`nSummary: {0} FAIL  {1} WARN  {2} PASS  {3} INFO" -f $nFail,$nWarn,$nPass,$nInfo) `
         ("Summary: {0} FAIL  {1} WARN  {2} PASS  {3} INFO" -f $nFail,$nWarn,$nPass,$nInfo) 'White'
if ($nFail -gt 0) { exit 1 } else { exit 0 }
