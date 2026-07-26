<#
  btdt-edr.ps1 - BeenThereDefendedThat lightweight host-local EDR sensor (Windows/AD)

  A single-file, dependency-light detect-and-respond sensor for CCDC-style
  competitions where every box is assumed pre-compromised and there is no safe
  central host to run a control plane on. Copy this script + btdt-edr.config.psd1
  to a box (member server or Domain Controller), run elevated, and it hunts the
  mechanisms an implant cannot avoid - C2 named pipes, outbound calls from
  unsigned/temp-path binaries, replication-rights abuse (DCSync), persistence,
  firewall tamper - rather than signatures it can change.

  It is the continuous sensor/responder companion to the point-in-time auditor
  Competition-Playbook/ccdc-audit/ad-audit.ps1: run that once at T0 for the full 40+ check
  triage; leave this running for the rest of the round.

    .\btdt-edr.ps1 -Baseline           # capture T0 state (do this first)
    .\btdt-edr.ps1 -Once               # one sweep, alert only
    .\btdt-edr.ps1 -Watch              # loop forever every WatchInterval seconds
    .\btdt-edr.ps1 -Watch -Respond kill   # loop + auto-contain high-confidence hits

  Controlling a running -Watch loop (handy while developing/tuning, since the
  loop may be in another window or launched by a task):

    .\btdt-edr.ps1 -Status             # is a watch loop running, and as what pid
    .\btdt-edr.ps1 -Stop               # ask it to stop, force-kill if it won't
    .\btdt-edr.ps1 -Watch -Force       # stop whatever is running, then start fresh

  -Watch records its pid under BaselineDir and refuses to start a second loop
  unless -Force is given, so two responders can never fight over the same host.

  Exit codes: 0 = clean sweep (or -Stop/-Status ok), 1 = at least one ALERT this
  sweep, 2 = refused to start because a watch loop is already running.
#>
[CmdletBinding()]
param(
    [string]$Config,
    [string]$OutFile,
    [string]$Only,
    [string]$Skip,
    [ValidateSet('observe','quarantine','kill')][string]$Respond,
    [switch]$Baseline,
    [switch]$Once,
    [switch]$Watch,
    [switch]$Stop,
    [switch]$Status,
    [switch]$Force,
    [switch]$NoColor,
    [switch]$DryRun
)

# --------------------------------------------------------------------------
# Config load
# --------------------------------------------------------------------------
if (-not $Config) {
    $co = Join-Path $PSScriptRoot 'btdt-edr.config.psd1'
    if (Test-Path $co) { $Config = $co }
}
$Cfg = if ($Config -and (Test-Path $Config)) { Import-PowerShellDataFile $Config } else { @{} }

$RespondMode  = if ($Respond) { $Respond } elseif ($Cfg.RespondMode) { $Cfg.RespondMode } else { 'observe' }
$BaselineDir  = if ($Cfg.BaselineDir) { $Cfg.BaselineDir } else { 'C:\ProgramData\btdt-edr' }
$AlertLog     = Join-Path $BaselineDir 'alerts.jsonl'
$WatchInterval= if ($Cfg.WatchInterval) { [int]$Cfg.WatchInterval } else { 30 }
$LookbackMin  = if ($Cfg.EventLookbackMinutes) { [int]$Cfg.EventLookbackMinutes } else { 10 }
$ScoredPorts  = @($Cfg.ScoredPorts)
$AllowedListen= @($Cfg.AllowedListenPorts)
$Lolbins      = @($Cfg.LolbinEgress)
$PrivGroups   = @($Cfg.PrivilegedGroups)
$Checks       = if ($Cfg.Checks) { $Cfg.Checks } else { @{} }
$OnlyList     = if ($Only) { $Only -split '[,\s]+' } else { @() }
$SkipList     = if ($Skip) { $Skip -split '[,\s]+' } else { @() }

if (-not $Baseline -and -not $Watch -and -not $Stop -and -not $Status) { $Once = $true }

$script:AlertCount = 0
$script:SweepCount = 0
$script:LogEnabled = $false
$script:SeenEvents = @{}   # RecordIds already alerted, so -Watch doesn't re-fire
try { New-Item -ItemType Directory -Force -Path $BaselineDir -ErrorAction Stop | Out-Null
      [IO.File]::AppendAllText($AlertLog, ''); $script:LogEnabled = $true } catch { }

# --------------------------------------------------------------------------
# Output
# --------------------------------------------------------------------------
function Now-Ts { (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') }

function Emit($level, $check, $conf, $msg) {
    $ts = Now-Ts
    switch ($level) {
        'ALERT' { $fg = 'Red';    $script:AlertCount++ }
        'WARN'  { $fg = 'Yellow' }
        'OK'    { $fg = 'Green' }
        default { $fg = 'Cyan' }
    }
    $line = '[{0,-5}] {1} {2} {3}' -f $level, $ts, $check, $msg
    if ($NoColor) { Write-Host $line } else { Write-Host $line -ForegroundColor $fg }
    if ($OutFile) { try { Add-Content -Path $OutFile -Value $line -ErrorAction SilentlyContinue } catch {} }
    if ($script:LogEnabled) {
        $o = [ordered]@{ ts=$ts; host=$env:COMPUTERNAME; level=$level; check=$check; confidence=$conf; msg=$msg }
        try { Add-Content -Path $AlertLog -Value ($o | ConvertTo-Json -Compress) -ErrorAction SilentlyContinue } catch {}
    }
}
function Alert($check, $conf, $msg) { Emit 'ALERT' $check $conf $msg }
function Warn($check, $msg)         { Emit 'WARN'  $check 'med' $msg }
function Info($check, $msg)         { Emit 'INFO'  $check 'low' $msg }

# --------------------------------------------------------------------------
# Instance control
#
# -Watch drops a pid file so a second shell can find and stop the loop without
# hunting for it in Task Manager. Stopping is two-stage: touch a stop file the
# loop polls (so it unwinds cleanly and removes its own pid file), then force
# -kill if it hasn't gone in StopGraceSec. Both files live in BaselineDir, so
# if that isn't writable (unelevated) -Stop degrades to the command-line scan.
# --------------------------------------------------------------------------
$PidFile      = Join-Path $BaselineDir 'btdt-edr.pid'
$StopFile     = Join-Path $BaselineDir 'btdt-edr.stop'
$StopGraceSec = 15

function Write-PidFile {
    try {
        $me = Get-Process -Id $PID -ErrorAction Stop
        # Store StartTime too: a pid alone is reusable, and killing a recycled
        # pid would take out an unrelated process.
        $o = [ordered]@{ pid=$PID; start=$me.StartTime.ToString('o'); since=(Now-Ts); respond=$RespondMode }
        Set-Content -Path $PidFile -Value ($o | ConvertTo-Json -Compress) -ErrorAction Stop
    } catch { Warn 'instance' "could not write pid file, -Stop will fall back to a process scan: $_" }
}
function Clear-PidFile  { Remove-Item $PidFile  -Force -ErrorAction SilentlyContinue }
function Clear-StopFile { Remove-Item $StopFile -Force -ErrorAction SilentlyContinue }
function Test-StopRequested { return ($Watch -and (Test-Path $StopFile)) }

# Live process recorded in the pid file, or $null. Stale files are cleaned up.
function Get-RunningInstance {
    if (-not (Test-Path $PidFile)) { return $null }
    try { $rec = Get-Content $PidFile -Raw -ErrorAction Stop | ConvertFrom-Json } catch { Clear-PidFile; return $null }
    if (-not $rec.pid -or $rec.pid -eq $PID) { return $null }
    $p = Get-Process -Id $rec.pid -ErrorAction SilentlyContinue
    if (-not $p) { Clear-PidFile; return $null }
    if ($rec.start) {
        $same = try { $p.StartTime.ToString('o') -eq $rec.start } catch { $false }
        if (-not $same) { Clear-PidFile; return $null }   # pid was recycled
    }
    return $p
}

# Fallback for a lost pid file: any other PowerShell running this script.
function Find-OrphanInstances {
    try {
        @(Get-CimInstance Win32_Process -Filter "Name='powershell.exe' OR Name='pwsh.exe'" -ErrorAction Stop |
            Where-Object { $_.ProcessId -ne $PID -and $_.CommandLine -match 'btdt-edr\.ps1' -and
                           $_.CommandLine -notmatch '-Stop|-Status' })
    } catch { @() }
}

function Stop-Instance {
    $p = Get-RunningInstance
    if (-not $p) {
        $orphans = Find-OrphanInstances
        if (-not $orphans.Count) { Info 'instance' 'no running instance found'; Clear-StopFile; return $false }
        foreach ($o in $orphans) {
            Warn 'instance' "no pid file, but pid $($o.ProcessId) is running this script - killing"
            try { Stop-Process -Id $o.ProcessId -Force -ErrorAction Stop } catch { Warn 'instance' "kill failed: $_" }
        }
        Clear-StopFile; Clear-PidFile
        return $true
    }
    Info 'instance' "stop requested for pid $($p.Id), waiting up to ${StopGraceSec}s for it to unwind"
    try { Set-Content -Path $StopFile -Value (Now-Ts) -ErrorAction Stop }
    catch { Warn 'instance' "could not write stop file, going straight to force-kill: $_" }
    $exited = try { $p.WaitForExit($StopGraceSec * 1000) } catch { $false }
    if (-not $exited) {
        Warn 'instance' "pid $($p.Id) did not stop in ${StopGraceSec}s - forcing"
        try { Stop-Process -Id $p.Id -Force -ErrorAction Stop } catch { Warn 'instance' "force-kill failed: $_" }
    }
    Clear-StopFile; Clear-PidFile
    Emit 'OK' 'instance' 'low' "stopped pid $($p.Id)"
    return $true
}

function Show-Status {
    $p = Get-RunningInstance
    if ($p) {
        Emit 'OK' 'instance' 'low' "watch loop running: pid $($p.Id), started $($p.StartTime.ToString('u'))"
        return
    }
    $orphans = Find-OrphanInstances
    if ($orphans.Count) {
        Warn 'instance' "no pid file, but these look like this script: $(($orphans.ProcessId) -join ', ')"
    } else {
        Info 'instance' 'no watch loop running'
    }
}

# Sleep in 1s slices so -Stop lands inside a second instead of a whole interval.
function Wait-Interval($seconds) {
    for ($i = 0; $i -lt $seconds; $i++) {
        if (Test-Path $StopFile) { return }
        Start-Sleep -Seconds 1
    }
}

function Test-Enabled($name) {
    if ($Checks.Contains($name) -and (-not $Checks[$name])) { return $false }
    if ($OnlyList.Count -and ($OnlyList -notcontains $name)) { return $false }
    if ($SkipList -contains $name) { return $false }
    return $true
}

function Test-PublicIP([string]$ip) {
    if (-not $ip) { return $false }
    if ($ip -eq '::1' -or $ip -eq '0.0.0.0' -or $ip -eq '127.0.0.1') { return $false }
    if ($ip -match '^(127\.|10\.|192\.168\.|169\.254\.|fe80:|ff)') { return $false }
    if ($ip -match '^f[cd][0-9a-f][0-9a-f]:') { return $false }       # ULA fc00::/7
    if ($ip -match '^172\.(1[6-9]|2[0-9]|3[01])\.') { return $false }
    foreach ($r in (@($Cfg.InternalResolvers) + @($Cfg.InternalExtra))) {
        if ($r -and $ip.StartsWith(($r -split '/')[0])) { return $false }
    }
    return $true
}

function Get-Entropy([string]$s) {
    if (-not $s) { return 0 }
    $len = $s.Length; $h = 0.0
    foreach ($g in ($s.ToCharArray() | Group-Object)) {
        $p = $g.Count / $len; $h -= $p * [Math]::Log($p, 2)
    }
    return $h
}

function Get-EventsSafe($log, $id, $minutes) {
    $start = (Get-Date).AddMinutes(-1 * $minutes)
    try { $evs = @(Get-WinEvent -FilterHashtable @{ LogName=$log; Id=$id; StartTime=$start } -ErrorAction Stop) }
    catch { return @() }   # "No events were found" throws - treat as empty
    # Return only events not already alerted, so -Watch fires once per event.
    $fresh = @()
    foreach ($e in $evs) {
        $k = "$log/$id/$($e.RecordId)"
        if (-not $script:SeenEvents.ContainsKey($k)) { $script:SeenEvents[$k] = $true; $fresh += $e }
    }
    return $fresh
}

# --------------------------------------------------------------------------
# Response layer - gated by RespondMode + confidence. Fail-open on scored ports.
# --------------------------------------------------------------------------
function Should-Respond($conf, $need) {
    if ($conf -ne 'high') { return $false }
    if ($need -eq 'kill')       { return ($RespondMode -eq 'kill') }
    if ($need -eq 'quarantine') { return ($RespondMode -eq 'kill' -or $RespondMode -eq 'quarantine') }
    return $false
}
function Invoke-Act([string]$desc, [scriptblock]$sb) {
    Info 'respond' "would $desc"
    if ($DryRun) { return }
    try { & $sb | Out-Null } catch { Warn 'respond' "action failed: $desc :: $_" }
}
# Confirmation that an action actually ran - silent in dry-run so we never claim
# to have contained something we only simulated.
function Contained($msg) { if (-not $DryRun) { Emit 'WARN' 'respond' 'high' $msg } }
function Resp-Kill($procId, $name) {
    if (-not (Should-Respond 'high' 'kill')) { return }
    Invoke-Act "kill pid $procId ($name)" { Stop-Process -Id $procId -Force -ErrorAction Stop }
    Contained "contained: killed pid $procId ($name)"
}
function Resp-Sever($ip, $port) {
    if (-not (Should-Respond 'high' 'quarantine')) { return }
    if ($ScoredPorts -contains [int]$port) { Info 'respond' "refusing to sever scored port $port (fail-open)"; return }
    Invoke-Act "block+sever $ip`:$port" {
        try { Get-NetTCPConnection -RemoteAddress $ip -RemotePort $port -ErrorAction Stop | Remove-NetTCPConnection -Confirm:$false -ErrorAction Stop }
        catch { New-NetFirewallRule -DisplayName "BTDT-block-$ip" -Direction Outbound -RemoteAddress $ip -Action Block -ErrorAction Stop | Out-Null }
    }
    Contained "contained: severed/blocked $ip`:$port"
}
function Resp-QuarantineFile($path) {
    if (-not (Should-Respond 'high' 'quarantine')) { return }
    if (-not $path -or -not (Test-Path $path)) { return }
    $q = Join-Path $BaselineDir 'quarantine'; New-Item -ItemType Directory -Force -Path $q | Out-Null
    Invoke-Act "quarantine $path" {
        Move-Item -Path $path -Destination $q -Force -ErrorAction Stop
        & icacls (Join-Path $q (Split-Path $path -Leaf)) /inheritance:r /deny "Everyone:(F)" 2>$null | Out-Null
    }
    Contained "contained: quarantined $path -> $q"
}
function Resp-Firewall {
    if (-not (Should-Respond 'high' 'kill')) { return }
    Invoke-Act "re-enable all firewall profiles" { Set-NetFirewallProfile -All -Enabled True -ErrorAction Stop }
    Contained "contained: re-enabled firewall profiles"
}
function Resp-RevertGroup($group, $member) {
    if (-not (Should-Respond 'high' 'kill')) { return }
    Invoke-Act "remove $member from $group" { Remove-ADGroupMember -Identity $group -Members $member -Confirm:$false -ErrorAction Stop }
    Contained "contained: removed $member from $group"
}

# --------------------------------------------------------------------------
# Baseline snapshots
# --------------------------------------------------------------------------
function Get-PersistSnapshot {
    $h = @{}
    $h['tasks'] = try {
        Get-ScheduledTask -ErrorAction Stop | Where-Object { $_.TaskPath -notlike '\Microsoft\*' } | ForEach-Object {
            $act = ($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join ' | '
            "$($_.TaskPath)$($_.TaskName) :: $act"
        }
    } catch { @() }
    $rks = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
           'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
           'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
           'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce'
    $h['runkeys'] = foreach ($rk in $rks) {
        if (Test-Path $rk) {
            (Get-ItemProperty $rk).PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } |
                ForEach-Object { "$rk :: $($_.Name) = $($_.Value)" }
        }
    }
    $h['services'] = try { Get-CimInstance Win32_Service -ErrorAction Stop | ForEach-Object { "$($_.Name) :: $($_.PathName)" } } catch { @() }
    $h['wmi'] = try { Get-CimInstance -Namespace root\subscription -Class __FilterToConsumerBinding -ErrorAction Stop | ForEach-Object { "$($_.Filter) -> $($_.Consumer)" } } catch { @() }
    return $h
}

function Invoke-Baseline {
    Info 'baseline' "capturing T0 baseline into $BaselineDir"
    $pdir = Join-Path $BaselineDir 'persist'; New-Item -ItemType Directory -Force -Path $pdir | Out-Null
    $snap = Get-PersistSnapshot
    foreach ($cat in $snap.Keys) { @($snap[$cat]) | Set-Content -Path (Join-Path $pdir "$cat.txt") }
    try { Get-NetTCPConnection -State Listen -EA Stop | Select-Object -Expand LocalPort -Unique | Sort-Object | Set-Content (Join-Path $BaselineDir 'listeners.txt') } catch {}
    try { Get-NetFirewallProfile | ForEach-Object { "$($_.Name)=$($_.Enabled),$($_.DefaultOutboundAction)" } | Set-Content (Join-Path $BaselineDir 'firewall.txt') } catch {}
    if ($script:HasAD) {
        $gdir = Join-Path $BaselineDir 'privgroups'; New-Item -ItemType Directory -Force -Path $gdir | Out-Null
        foreach ($g in $PrivGroups) {
            try { Get-ADGroupMember -Identity $g -Recursive -EA Stop | Select-Object -Expand SamAccountName | Sort-Object |
                    Set-Content (Join-Path $gdir ("{0}.txt" -f ($g -replace '\s','_'))) } catch {}
        }
    }
    Emit 'OK' 'baseline' 'low' "baseline captured"
}

# --------------------------------------------------------------------------
# Detections
# --------------------------------------------------------------------------
function Det-NamedPipes {
    try { $pipes = [System.IO.Directory]::GetFiles('\\.\pipe\') } catch { return }
    foreach ($p in $pipes) {
        $n = $p -replace '^\\\\\.\\pipe\\',''
        if ($n -match '^(msagent_|postex_|status_[0-9]|MSSE-[0-9]|interprocess_|wkssvc[0-9])' -or
            $n -match '^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$') {
            Alert 'NamedPipes' 'high' "Cobalt Strike / Mythic C2 named pipe: $n"
        } elseif ($n -match '^[a-f0-9]{16,}$') {
            Warn 'NamedPipes' "long-hex named pipe (possible custom C2): $n"
        }
    }
}

function Get-Outbound {
    try { $conns = Get-NetTCPConnection -State Established,SynSent -ErrorAction Stop } catch { return @() }
    foreach ($c in $conns) {
        if (-not (Test-PublicIP $c.RemoteAddress)) { continue }
        $pr = Get-Process -Id $c.OwningProcess -ErrorAction SilentlyContinue
        [pscustomobject]@{
            OwnPid = $c.OwningProcess
            Name   = if ($pr) { $pr.Name } else { '?' }
            Path   = if ($pr) { $pr.Path } else { $null }
            Remote = $c.RemoteAddress
            Port   = $c.RemotePort
        }
    }
}

function Det-Egress {
    foreach ($o in (Get-Outbound)) {
        $sig = if ($o.Path) { try { (Get-AuthenticodeSignature $o.Path -EA Stop).Status } catch { 'Unknown' } } else { 'NoPath' }
        $tempish = $o.Path -and ($o.Path -match 'Temp|AppData|ProgramData|\\Users\\Public|\\Downloads')
        if ($sig -ne 'Valid' -or $tempish) {
            Alert 'Egress' 'high' "outbound $($o.Remote):$($o.Port) from $($o.Name) (pid=$($o.OwnPid)) path=$($o.Path) sig=$sig"
            Resp-Sever $o.Remote $o.Port
            Resp-Kill $o.OwnPid $o.Name
        }
    }
}

function Det-LolbinEgress {
    foreach ($o in (Get-Outbound)) {
        if ($Lolbins -contains $o.Name) {
            Alert 'LolbinEgress' 'high' "LOLBin with outbound connection: $($o.Name) -> $($o.Remote):$($o.Port) (pid=$($o.OwnPid))"
            Resp-Sever $o.Remote $o.Port
            Resp-Kill $o.OwnPid $o.Name
        }
    }
}

function Det-Listeners {
    try { $ls = Get-NetTCPConnection -State Listen -ErrorAction Stop } catch { return }
    foreach ($l in ($ls | Sort-Object LocalPort -Unique)) {
        if ($AllowedListen -contains [int]$l.LocalPort) { continue }
        $pr = Get-Process -Id $l.OwningProcess -ErrorAction SilentlyContinue
        Warn 'Listeners' "unexpected listener on port $($l.LocalPort) (proc=$(if($pr){$pr.Name}else{'?'}) pid=$($l.OwningProcess))"
    }
}

function Det-Persistence {
    $pdir = Join-Path $BaselineDir 'persist'
    if (-not (Test-Path $pdir)) { Info 'Persistence' 'no baseline yet - run -Baseline at T0'; return }
    $snap = Get-PersistSnapshot
    foreach ($cat in $snap.Keys) {
        $bf = Join-Path $pdir "$cat.txt"
        $base = if (Test-Path $bf) { @(Get-Content $bf) } else { @() }
        $cur  = @($snap[$cat])
        if (-not $cur.Count -and -not $base.Count) { continue }
        Compare-Object -ReferenceObject $base -DifferenceObject $cur |
            Where-Object { $_.SideIndicator -eq '=>' } |
            ForEach-Object { Alert 'Persistence' 'high' "new $cat since T0: $($_.InputObject)" }
    }
}

function Det-Firewall {
    try { $profs = Get-NetFirewallProfile -ErrorAction Stop } catch { return }
    $off = $profs | Where-Object { -not $_.Enabled }
    if ($off) {
        Alert 'Firewall' 'high' "firewall profile(s) disabled: $(($off | Select-Object -Expand Name) -join ',') (T1562.004 egress-freeing tamper)"
        Resp-Firewall
    }
}

function Det-PortProxy {
    $out = & netsh interface portproxy show all 2>$null
    if ($out -match '\d{1,3}(\.\d{1,3}){3}') {
        Alert 'PortProxy' 'high' "netsh portproxy rule present (pivot / port-piggyback): $(($out | Where-Object {$_ -match '\d'}) -join ' ')"
    }
}

function Det-IISModules {
    if (-not (Get-Service W3SVC -ErrorAction SilentlyContinue)) { return }
    $appcmd = Join-Path $env:SystemRoot 'System32\inetsrv\appcmd.exe'
    if (-not (Test-Path $appcmd)) { Info 'IISModules' 'appcmd.exe not found'; return }
    foreach ($m in (& $appcmd list modules 2>$null)) {
        if ($m -match 'image:(.+?\.dll)') {
            $img = $Matches[1].Trim()
            if ($img -notmatch 'System32\\inetsrv|Microsoft\.NET|Windows\\assembly|Microsoft Shared') {
                Alert 'IISModules' 'high' "IIS native module loaded from non-system path: $img"
            }
        }
    }
}

function Det-LogClear {
    $c = @(Get-EventsSafe 'Security' 1102 $LookbackMin) + @(Get-EventsSafe 'System' 104 $LookbackMin)
    foreach ($e in $c) { Alert 'LogClear' 'high' "event log cleared (anti-forensics) at $($e.TimeCreated)" }
}

function Det-DnsTunnel {
    try { $cache = Get-DnsClientCache -ErrorAction Stop } catch { return }
    foreach ($r in $cache) {
        if (-not $r.Name) { continue }
        $label = ($r.Name -split '\.')[0]
        if ($label.Length -gt 25 -or (Get-Entropy $label) -gt 3.8) {
            Warn 'DnsTunnel' "high-entropy/long DNS label (possible tunnel): $($r.Name)"
        }
    }
}

# ---- Active Directory (Domain Controller) -----------------------------------
function Det-DCSync {
    if (-not $script:HasAD) { Info 'DCSync' 'no AD module - skipped'; return }
    foreach ($e in (Get-EventsSafe 'Security' 4662 $LookbackMin)) {
        try { $x = [xml]$e.ToXml() } catch { continue }
        $data = $x.Event.EventData.Data
        $props   = ($data | Where-Object { $_.Name -eq 'Properties' }).'#text'
        $subject = ($data | Where-Object { $_.Name -eq 'SubjectUserName' }).'#text'
        if ($props -match '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2|1131f6ad-9c07-11d1-f79f-00c04fc2dcd2|89e95b76-444d-4c62-991a-0facbeda640c') {
            if ($subject -and $subject -notmatch '\$$' -and $subject -notmatch '^MSOL_') {
                Alert 'DCSync' 'high' "DCSync: directory-replication right exercised by non-DC principal '$subject'"
            }
        }
    }
}

function Det-Kerberoast {
    if (-not $script:HasAD) { return }
    foreach ($e in (Get-EventsSafe 'Security' 4769 $LookbackMin)) {
        try { $x = [xml]$e.ToXml() } catch { continue }
        $data = $x.Event.EventData.Data
        $enc = ($data | Where-Object { $_.Name -eq 'TicketEncryptionType' }).'#text'
        $svc = ($data | Where-Object { $_.Name -eq 'ServiceName' }).'#text'
        $usr = ($data | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'
        if ($enc -eq '0x17' -and $svc -ne 'krbtgt' -and $svc -notmatch '\$$') {
            Warn 'Kerberoast' "RC4 (0x17) service ticket requested for SPN '$svc' by '$usr' - possible Kerberoasting"
        }
    }
}

function Det-AsrepRoast {
    if (-not $script:HasAD) { return }
    foreach ($e in (Get-EventsSafe 'Security' 4768 $LookbackMin)) {
        try { $x = [xml]$e.ToXml() } catch { continue }
        $data = $x.Event.EventData.Data
        $pre = ($data | Where-Object { $_.Name -eq 'PreAuthType' }).'#text'
        $usr = ($data | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'
        if ($pre -eq '0') { Warn 'AsrepRoast' "AS-REQ without pre-authentication for '$usr' - possible AS-REP roasting" }
    }
    try {
        Get-ADUser -Filter 'useraccountcontrol -band 4194304' -Properties useraccountcontrol -EA Stop |
            ForEach-Object { Warn 'AsrepRoast' "account has DONT_REQ_PREAUTH set (roastable): $($_.SamAccountName)" }
    } catch {}
}

function Det-PrivGroups {
    if (-not $script:HasAD) { Info 'PrivGroups' 'no AD module - skipped'; return }
    $gdir = Join-Path $BaselineDir 'privgroups'
    foreach ($g in $PrivGroups) {
        $bf = Join-Path $gdir ("{0}.txt" -f ($g -replace '\s','_'))
        $cur = try { @(Get-ADGroupMember -Identity $g -Recursive -EA Stop | Select-Object -Expand SamAccountName) } catch { continue }
        if (-not (Test-Path $bf)) { Info 'PrivGroups' "no baseline for '$g' - run -Baseline at T0"; continue }
        $base = @(Get-Content $bf)
        Compare-Object -ReferenceObject $base -DifferenceObject $cur |
            Where-Object { $_.SideIndicator -eq '=>' } |
            ForEach-Object {
                Alert 'PrivGroups' 'high' "new member of '$g' since T0: $($_.InputObject)"
                Resp-RevertGroup $g $_.InputObject
            }
    }
}

# --------------------------------------------------------------------------
# Sweep driver
# --------------------------------------------------------------------------
$Dispatch = [ordered]@{
    NamedPipes   = { Det-NamedPipes }
    Egress       = { Det-Egress }
    LolbinEgress = { Det-LolbinEgress }
    Listeners    = { Det-Listeners }
    Persistence  = { Det-Persistence }
    Firewall     = { Det-Firewall }
    PortProxy    = { Det-PortProxy }
    IISModules   = { Det-IISModules }
    LogClear     = { Det-LogClear }
    DnsTunnel    = { Det-DnsTunnel }
    DCSync       = { Det-DCSync }
    Kerberoast   = { Det-Kerberoast }
    AsrepRoast   = { Det-AsrepRoast }
    PrivGroups   = { Det-PrivGroups }
}

function Invoke-Sweep {
    $script:AlertCount = 0
    $script:SweepCount++
    foreach ($name in $Dispatch.Keys) {
        # Checked per-check, not just per-sweep, so -Stop doesn't have to wait
        # out a full sweep on a slow box.
        if (Test-StopRequested) { return }
        if (Test-Enabled $name) {
            try { & $Dispatch[$name] } catch { Warn $name "check errored: $_" }
        }
    }
}

# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

# Control verbs first: they don't sweep, so skip the AD import and the
# elevation warning entirely and stay fast.
if ($Status) { Show-Status; exit 0 }
if ($Stop)   { Stop-Instance | Out-Null; exit 0 }

$script:HasAD = $false
try { Import-Module ActiveDirectory -ErrorAction Stop; $script:HasAD = $true } catch { }

$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
         ).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
if (-not $admin) { Warn 'init' 'not elevated - event-log, socket-owner and firewall checks will be degraded' }
Info 'init' "btdt-edr | mode=$(if($Watch){'watch'}else{'once'}) respond=$RespondMode ad=$($script:HasAD) dry-run=$([bool]$DryRun)"

if ($Baseline) { Invoke-Baseline; if (-not $Watch -and -not $Once) { exit 0 } }

if ($Watch) {
    $existing = Get-RunningInstance
    if ($existing) {
        if ($Force) {
            Info 'instance' "-Force: replacing watch loop at pid $($existing.Id)"
            Stop-Instance | Out-Null
        } else {
            Warn 'instance' "already watching as pid $($existing.Id) - use -Stop, or -Watch -Force to replace it"
            exit 2
        }
    }
    Clear-StopFile            # don't let a leftover stop file kill a fresh loop
    Write-PidFile
    Info 'instance' "watch loop is pid $PID - stop it with: .\btdt-edr.ps1 -Stop"
    try {
        while (-not (Test-Path $StopFile)) {
            Invoke-Sweep
            if (Test-Path $StopFile) { break }
            if ($script:AlertCount -gt 0) { Emit 'WARN' 'sweep' 'low' "sweep complete: $($script:AlertCount) alert(s)" }
            else { Emit 'OK' 'sweep' 'low' 'sweep complete: clean' }
            Wait-Interval $WatchInterval
        }
        Info 'instance' "stopping on request after $($script:SweepCount) sweep(s)"
    } finally {
        # Also runs on Ctrl+C, so an interactively-killed loop doesn't leave a
        # pid file behind that blocks the next -Watch.
        Clear-PidFile
        Clear-StopFile
    }
    exit 0
} else {
    Invoke-Sweep
    if ($script:AlertCount -gt 0) { Write-Host "Summary: $($script:AlertCount) ALERT" -ForegroundColor Red; exit 1 }
    else { Write-Host 'Summary: clean' -ForegroundColor Green; exit 0 }
}
