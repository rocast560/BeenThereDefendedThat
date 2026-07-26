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
$ProcCreateCfg= if ($Cfg.ProcCreate) { $Cfg.ProcCreate } else { @{} }
$MemScanCfg   = if ($Cfg.MemScan) { $Cfg.MemScan } else { @{} }
$TrustedPeers = @($Cfg.TrustedInternalPeers)
$FirewallLog  = if ($Cfg.FirewallLog) { $Cfg.FirewallLog } else { 'C:\Windows\System32\LogFiles\Firewall\pfirewall.log' }

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

# Pull a named field out of an event's EventData, trying several names so the same
# code reads both the Security-4688 and Sysmon schemas. $data is $xml.Event.EventData.Data.
function Get-EventField($data, [string[]]$names) {
    foreach ($n in $names) {
        $v = ($data | Where-Object { $_.Name -eq $n }).'#text'
        if ($null -ne $v -and $v -ne '') { return $v }
    }
    return $null
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

# A dropped/injected binary's signature + path are the same suspicion signals the
# public-egress check uses; factored out so InternalBeacon can reuse them.
function Get-ProcSig($path) {
    if (-not $path) { return 'NoPath' }
    try { return (Get-AuthenticodeSignature $path -EA Stop).Status } catch { return 'Unknown' }
}
function Test-TempPath($path) { return ($path -and ($path -match 'Temp|AppData|ProgramData|\\Users\\Public|\\Downloads')) }

# Internal peers this host is talking to, minus loopback/self and the configured
# trusted set. Public peers are Det-Egress's job; this is the RFC1918 blind spot.
function Get-OutboundInternal {
    try { $conns = Get-NetTCPConnection -State Established,SynSent -ErrorAction Stop } catch { return @() }
    foreach ($c in $conns) {
        $ip = $c.RemoteAddress
        if (-not $ip -or (Test-PublicIP $ip)) { continue }
        if ($ip -match '^(127\.|::1$|0\.0\.0\.0$|::$|fe80:|169\.254\.)') { continue }
        $trusted = $false
        foreach ($t in $TrustedPeers) { if ($t -and $ip.StartsWith($t)) { $trusted = $true; break } }
        if ($trusted) { continue }
        $pr = Get-Process -Id $c.OwningProcess -ErrorAction SilentlyContinue
        [pscustomobject]@{
            OwnPid = $c.OwningProcess
            Name   = if ($pr) { $pr.Name } else { '?' }
            Path   = if ($pr) { $pr.Path } else { $null }
            Remote = $ip
            Port   = $c.RemotePort
        }
    }
}

function Det-Egress {
    foreach ($o in (Get-Outbound)) {
        $sig = Get-ProcSig $o.Path
        $tempish = Test-TempPath $o.Path
        if ($sig -ne 'Valid' -or $tempish) {
            Alert 'Egress' 'high' "outbound $($o.Remote):$($o.Port) from $($o.Name) (pid=$($o.OwnPid)) path=$($o.Path) sig=$sig"
            Resp-Sever $o.Remote $o.Port
            Resp-Kill $o.OwnPid $o.Name
        }
    }
}

# #3 A suspicious process (unsigned / temp-path / LOLBin) beaconing to a
# non-trusted internal peer. Only fires when the *process* is itself suspect, so a
# normal signed system service talking on the LAN stays silent -- keeps FP low
# while closing the internal-C2 / pivot / redirector gap. WARN, never auto-acts.
function Det-InternalBeacon {
    foreach ($o in (Get-OutboundInternal)) {
        $sig = Get-ProcSig $o.Path
        $tempish = Test-TempPath $o.Path
        $lol = $Lolbins -contains $o.Name
        if ($sig -ne 'Valid' -or $tempish -or $lol) {
            $why = @(); if ($sig -ne 'Valid') { $why += "sig=$sig" }; if ($tempish) { $why += 'temp-path' }; if ($lol) { $why += 'lolbin' }
            Warn 'InternalBeacon' "suspicious process to non-trusted internal peer $($o.Remote):$($o.Port) from $($o.Name) (pid=$($o.OwnPid)) [$(($why) -join ',')] path=$($o.Path)"
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
    # #3 If T0 had outbound default-deny and it has since flipped to Allow, someone
    # freed egress for a beacon. Baseline line format: Name=Enabled,DefaultOutboundAction
    $bf = Join-Path $BaselineDir 'firewall.txt'
    if (Test-Path $bf) {
        $base = @{}
        foreach ($ln in (Get-Content $bf)) {
            if ($ln -match '^(\w+)=[^,]+,(\w+)') { $base[$Matches[1]] = $Matches[2] }
        }
        foreach ($p in $profs) {
            if ($base[$p.Name] -eq 'Block' -and "$($p.DefaultOutboundAction)" -ne 'Block') {
                Alert 'Firewall' 'high' "outbound default-action on '$($p.Name)' changed from Block to $($p.DefaultOutboundAction) since T0 (egress freed)"
            }
        }
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

# #1 -------------------------------------------------------------------------
# Launch-time process telemetry. The sweep loop is a poller and can never see the
# instant a beacon starts; the OS can, via Security 4688 (with command-line
# auditing) or Sysmon EID 1. This reads both and alerts on the launch patterns a
# stager cannot avoid: an office/script host spawning an interpreter, an encoded
# PowerShell command, or an image running from a drop path. It never auto-kills --
# a wrong kill on powershell.exe is worse than the WARN.
function Det-ProcCreate {
    $parents  = @($ProcCreateCfg.SuspectParents)
    $children = @($ProcCreateCfg.SuspectChildren)
    $paths    = if ($ProcCreateCfg.SuspectPaths) { $ProcCreateCfg.SuspectPaths } else { 'Temp|AppData|\\Downloads' }
    $cap      = if ($ProcCreateCfg.MaxPerSweep) { [int]$ProcCreateCfg.MaxPerSweep } else { 500 }

    $events = @(Get-EventsSafe 'Security' 4688 $LookbackMin) +
              @(Get-EventsSafe 'Microsoft-Windows-Sysmon/Operational' 1 $LookbackMin)
    $n = 0
    foreach ($e in $events) {
        if ($n -ge $cap) { break }; $n++
        try { $x = [xml]$e.ToXml() } catch { continue }
        $data     = $x.Event.EventData.Data
        $img      = Get-EventField $data @('NewProcessName','Image')
        $parent   = Get-EventField $data @('ParentProcessName','ParentImage')
        $cmd      = Get-EventField $data @('CommandLine','ProcessCommandLine')
        if (-not $img) { continue }
        $leaf     = Split-Path $img -Leaf
        $child    = ($leaf   -replace '\.exe$','').ToLower()
        $pname    = if ($parent) { (Split-Path $parent -Leaf) -replace '\.exe$','' } else { '' }
        $pname    = $pname.ToLower()
        $c        = "$cmd"

        $encoded = $c -match '(?i)(-enc(odedcommand)?\b|\s-e\s+[A-Za-z0-9+/=]{20,}|FromBase64String|Invoke-Expression|\bIEX\b|DownloadString|DownloadData|Net\.WebClient|-nop\b.*-w(indowstyle)?\s+hidden|hidden.*-nop)'
        if ($encoded) {
            Alert 'ProcCreate' 'high' "encoded/obfuscated launch: $pname -> $leaf :: $(Limit-Str $c 300)"
            continue
        }
        if (($parents -contains $pname) -and ($children -contains $child)) {
            Alert 'ProcCreate' 'high' "suspicious lineage: $pname spawned $leaf :: $(Limit-Str $c 300)"
            continue
        }
        if ($img -match $paths) {
            $sig = Get-ProcSig $img
            if ($sig -ne 'Valid') { Alert 'ProcCreate' 'high' "unsigned image launched from drop path: $img (sig=$sig) :: $(Limit-Str $c 200)" }
            else { Warn 'ProcCreate' "signed image launched from drop path: $img :: $(Limit-Str $c 200)" }
            continue
        }
        if (($children -contains $child) -and ($c -match '(?i)https?://|\\\\[^ ]+\\|-w(indowstyle)?\s+hidden')) {
            Warn 'ProcCreate' "interpreter with network/hidden args: $pname -> $leaf :: $(Limit-Str $c 200)"
        }
    }
}
function Limit-Str([string]$s, [int]$max) { if ($null -eq $s) { return '' }; if ($s.Length -le $max) { return $s }; return $s.Substring(0, $max) + '...' }

# #2 -------------------------------------------------------------------------
# In-memory injection scan. Point-in-time network/pipe checks are blind to a
# beacon injected into a legit process that sleeps with jitter on an internal C2.
# The tell that needs neither the network nor a file on disk: private, committed,
# executable memory (RWX or exec-writecopy) -- reflectively-loaded shellcode.
# Native (no dependencies); heavy, so it runs on a slow cadence. If a memory
# scanner is staged in <BaselineDir>\tools it gets a second opinion on hits.
$script:MemApiReady = $null
function Initialize-MemApi {
    if ($null -ne $script:MemApiReady) { return $script:MemApiReady }
    if ([IntPtr]::Size -ne 8) { $script:MemApiReady = $false; return $false }  # x64 layout only
    try {
        Add-Type -ErrorAction Stop -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
public static class BtdtMem {
    [StructLayout(LayoutKind.Sequential)]
    struct MBI { public IntPtr BaseAddress; public IntPtr AllocationBase; public uint AllocationProtect;
                 public IntPtr RegionSize; public uint State; public uint Protect; public uint Type; }
    [DllImport("kernel32.dll", SetLastError=true)] static extern IntPtr OpenProcess(uint a, bool inh, uint pid);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool CloseHandle(IntPtr h);
    [DllImport("kernel32.dll", SetLastError=true)] static extern IntPtr VirtualQueryEx(IntPtr h, IntPtr addr, out MBI mbi, IntPtr len);
    const uint MEM_COMMIT=0x1000, MEM_PRIVATE=0x20000, PAGE_GUARD=0x100;
    public static List<string> Scan(uint pid, long minBytes) {
        var outp = new List<string>();
        IntPtr h = OpenProcess(0x0400, false, pid);   // PROCESS_QUERY_INFORMATION only -- VirtualQueryEx needs no VM_READ, so we never open lsass with read rights (avoids tripping AV/ASR)
        if (h == IntPtr.Zero) return outp;
        try {
            IntPtr addr = IntPtr.Zero;
            int sz = Marshal.SizeOf(typeof(MBI));
            for (int i = 0; i < 200000; i++) {
                MBI m;
                if (VirtualQueryEx(h, addr, out m, (IntPtr)sz) == IntPtr.Zero) break;
                long region = (long)m.RegionSize;
                if (region <= 0) break;
                uint p = m.Protect;
                bool guard = (p & PAGE_GUARD) != 0;
                uint pb = p & 0xFF;
                bool execWrite = (pb == 0x40 /*RWX*/ || pb == 0x80 /*exec-writecopy*/);
                if (!guard && (m.State & MEM_COMMIT) != 0 && (m.Type & MEM_PRIVATE) != 0 && execWrite && region >= minBytes)
                    outp.Add(string.Format("0x{0:X}+{1}KB prot=0x{2:X}", (long)m.BaseAddress, region/1024, pb));
                long next = (long)m.BaseAddress + region;
                if (next <= (long)addr) break;
                addr = (IntPtr)next;
            }
        } finally { CloseHandle(h); }
        return outp;
    }
}
'@
        $script:MemApiReady = $true
    } catch { $script:MemApiReady = $false }
    return $script:MemApiReady
}
function Det-MemScan {
    $everyN = if ($null -ne $MemScanCfg.EveryNSweeps) { [int]$MemScanCfg.EveryNSweeps } else { 10 }
    if ($everyN -gt 0 -and (($script:SweepCount - 1) % $everyN) -ne 0) { return }  # runs on sweep 1, N+1, ...
    if (-not (Initialize-MemApi)) { Info 'MemScan' 'native memory API unavailable (need 64-bit PowerShell) - skipped'; return }
    $minKB = if ($MemScanCfg.MinRegionKB) { [int]$MemScanCfg.MinRegionKB } else { 12 }
    $minBytes = 1024 * $minKB
    $allow = @($MemScanCfg.AllowProc)
    $scanner = @(Get-ChildItem (Join-Path $BaselineDir 'tools') -Filter '*.exe' -EA SilentlyContinue |
                 Where-Object { $_.Name -match 'pe-?sieve|hollows' } | Select-Object -First 1 -Expand FullName)
    foreach ($p in (Get-Process -EA SilentlyContinue)) {
        if ($p.Id -le 4 -or $p.Id -eq $PID) { continue }
        if ($allow -contains $p.Name) { continue }
        $hits = try { [BtdtMem]::Scan([uint32]$p.Id, [int64]$minBytes) } catch { @() }
        if (-not $hits -or $hits.Count -eq 0) { continue }
        $path = try { $p.Path } catch { $null }
        $sig  = Get-ProcSig $path
        $regions = ($hits | Select-Object -First 4) -join ' '
        $msg = "private executable (RWX) memory in $($p.Name) (pid=$($p.Id)) sig=$sig path=$path regions=[$regions]"
        # Unsigned or drop-path host with injected RWX is about as good as this gets short of a full scan.
        if ($sig -ne 'Valid' -or (Test-TempPath $path)) { Alert 'MemScan' 'high' $msg } else { Warn 'MemScan' $msg }
        if ($scanner) {
            try { $out = & $scanner /pid $p.Id /quiet 2>$null | Select-Object -Last 3
                  if ($out) { Info 'MemScan' "second-opinion ($(Split-Path $scanner -Leaf)) pid $($p.Id): $(($out -join ' ').Trim())" } } catch {}
        }
    }
}

# #3 -------------------------------------------------------------------------
# Blocked call-home in the Windows Firewall log. With default-deny outbound on,
# every beacon check-in is logged as a dropped SEND instead of hoping the sweep
# samples a live socket. Reads only bytes appended since the last sweep and only
# surfaces drops to public IPs.
$script:FwLogPos = $null
function Det-FirewallLog {
    if (-not (Test-Path $FirewallLog)) {
        if ($null -eq $script:FwLogPos) { Info 'FirewallLog' "no firewall log at $FirewallLog - enable: Set-NetFirewallProfile -All -DefaultOutboundAction Block -LogBlocked True"; $script:FwLogPos = 0 }
        return
    }
    try { $fs = [System.IO.File]::Open($FirewallLog, 'Open', 'Read', 'ReadWrite') } catch { return }
    try {
        $len = $fs.Length
        if ($null -eq $script:FwLogPos) { $script:FwLogPos = $len; return }  # first sweep: skip history
        if ($len -lt $script:FwLogPos) { $script:FwLogPos = 0 }              # log rotated/truncated
        if ($len -eq $script:FwLogPos) { return }
        [void]$fs.Seek($script:FwLogPos, 'Begin')
        $reader = New-Object System.IO.StreamReader($fs)
        $text = $reader.ReadToEnd()
        $script:FwLogPos = $len
    } finally { $fs.Close() }
    foreach ($line in ($text -split "`n")) {
        if ($line -notmatch ' DROP ') { continue }
        $f = $line -split '\s+'
        if ($f.Count -lt 8) { continue }
        # W3C firewall fields: date time action protocol src-ip dst-ip src-port dst-port ...
        $dst = $f[5]; $dport = $f[7]
        if (Test-PublicIP $dst) {
            Warn 'FirewallLog' "blocked outbound to public $dst`:$dport (firewall denied a call-home)"
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
    NamedPipes    = { Det-NamedPipes }
    ProcCreate    = { Det-ProcCreate }
    Egress        = { Det-Egress }
    LolbinEgress  = { Det-LolbinEgress }
    InternalBeacon= { Det-InternalBeacon }
    MemScan       = { Det-MemScan }
    Listeners     = { Det-Listeners }
    Persistence   = { Det-Persistence }
    Firewall      = { Det-Firewall }
    FirewallLog   = { Det-FirewallLog }
    PortProxy     = { Det-PortProxy }
    IISModules    = { Det-IISModules }
    LogClear      = { Det-LogClear }
    DnsTunnel     = { Det-DnsTunnel }
    DCSync        = { Det-DCSync }
    Kerberoast    = { Det-Kerberoast }
    AsrepRoast    = { Det-AsrepRoast }
    PrivGroups    = { Det-PrivGroups }
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
