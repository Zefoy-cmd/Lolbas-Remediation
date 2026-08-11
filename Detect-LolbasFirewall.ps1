#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Detection half of the LOLBAS firewall hardening remediation package for Intune.

.DESCRIPTION
    Read-only. Compares the firewall rules that SHOULD exist (given the config below) with
    what is actually present, and reports drift.

    Exit 0 -> compliant, no remediation needed.
    Exit 1 -> non-compliant, Intune will run Remediate-LolbasFirewall.ps1.

    The CONFIG block and the SHARED BLOCK below MUST match Remediate-LolbasFirewall.ps1,
    otherwise the pair will fight each other and remediate on every cycle.

.NOTES
    Version : 1.0.0
    Intune surfaces roughly the last 2 KB of stdout as pre/post-remediation output, so this
    script keeps its output short and puts the detail in a log file.
#>

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$ScriptVersion = '1.0.0'

# ------------------- ADMIN CONFIG (must match the remediation script) -------------------
$RuleGroup       = 'LOLBAS Hardening'
$RulePrefix      = 'LOLBAS Block'
$IncludeHighRisk = $false
$BlockInbound    = $false
$BlockScope      = 'All'          # 'All' or 'InternetOnly'
$ExcludeBinary   = @()
$LogDirectory    = "$env:ProgramData\LolbasHardening\Logs"
$MaxNamesToPrint = 8              # keeps stdout inside Intune's output limit
# ---------------------------------------------------------------------------------------

#region ============ SHARED BLOCK - KEEP IN SYNC WITH Remediate-LolbasFirewall.ps1 ============

$Script:CatalogVersion = '2026.08.11'

$Script:LolbasCatalog = @(
    # ---- Standard: download / staging / remote-payload execution ----
    [pscustomobject]@{ Name='bitsadmin.exe';                    Where='Sys';       Risk='Standard'; Note='BITS CLI, arbitrary download' }
    [pscustomobject]@{ Name='certreq.exe';                      Where='Sys';       Risk='Standard'; Note='HTTP POST upload / download' }
    [pscustomobject]@{ Name='certutil.exe';                     Where='Sys';       Risk='Standard'; Note='Download and base64 decode' }
    [pscustomobject]@{ Name='cmdl32.exe';                       Where='Sys';       Risk='Standard'; Note='Download via VPN profile config' }
    [pscustomobject]@{ Name='cmstp.exe';                        Where='Sys';       Risk='Standard'; Note='Remote INF / SCT execution' }
    [pscustomobject]@{ Name='cscript.exe';                      Where='Sys';       Risk='Standard'; Note='Script host, download and execute' }
    [pscustomobject]@{ Name='curl.exe';                         Where='Sys';       Risk='Standard'; Note='Download; may affect admin scripts' }
    [pscustomobject]@{ Name='desktopimgdownldr.exe';            Where='Sys';       Risk='Standard'; Note='Spotlight image downloader abuse' }
    [pscustomobject]@{ Name='dfsvc.exe';                        Where='Net';       Risk='Standard'; Note='ClickOnce remote execution' }
    [pscustomobject]@{ Name='diantz.exe';                       Where='Sys';       Risk='Standard'; Note='Cab to/from UNC' }
    [pscustomobject]@{ Name='esentutl.exe';                     Where='Sys';       Risk='Standard'; Note='Copy from UNC / ADS' }
    [pscustomobject]@{ Name='expand.exe';                        Where='Sys';      Risk='Standard'; Note='Copy from UNC' }
    [pscustomobject]@{ Name='extrac32.exe';                     Where='Sys';       Risk='Standard'; Note='Copy from UNC' }
    [pscustomobject]@{ Name='findstr.exe';                      Where='Sys';       Risk='Standard'; Note='Read/stage from UNC' }
    [pscustomobject]@{ Name='ftp.exe';                          Where='Sys';       Risk='Standard'; Note='Download / exfil' }
    [pscustomobject]@{ Name='gpscript.exe';                     Where='Sys';       Risk='Standard'; Note='Executes GPO logon scripts' }
    [pscustomobject]@{ Name='hh.exe';                           Where='Sys';       Risk='Standard'; Note='Remote CHM / script execution' }
    [pscustomobject]@{ Name='ieexec.exe';                       Where='Net';       Risk='Standard'; Note='Executes remote .NET assemblies' }
    [pscustomobject]@{ Name='IMEWDBLD.exe';                     Where='ImeShared'; Risk='Standard'; Note='IME dictionary downloader abuse' }
    [pscustomobject]@{ Name='infdefaultinstall.exe';            Where='Sys';       Risk='Standard'; Note='Remote INF execution' }
    [pscustomobject]@{ Name='installutil.exe';                  Where='Net';       Risk='Standard'; Note='.NET installer, proxy execution' }
    [pscustomobject]@{ Name='ldifde.exe';                       Where='Sys';       Risk='Standard'; Note='Download via LDIF import' }
    [pscustomobject]@{ Name='makecab.exe';                       Where='Sys';      Risk='Standard'; Note='Stage to/from UNC' }
    [pscustomobject]@{ Name='mavinject.exe';                    Where='Sys';       Risk='Standard'; Note='DLL injection' }
    [pscustomobject]@{ Name='Microsoft.Workflow.Compiler.exe';  Where='Net';       Risk='Standard'; Note='Executes arbitrary XOML/C#' }
    [pscustomobject]@{ Name='msdt.exe';                         Where='Sys';       Risk='Standard'; Note='Diagnostic package execution' }
    [pscustomobject]@{ Name='mshta.exe';                        Where='Sys';       Risk='Standard'; Note='Remote HTA execution' }
    [pscustomobject]@{ Name='odbcconf.exe';                     Where='Sys';       Risk='Standard'; Note='Loads DLL via response file' }
    [pscustomobject]@{ Name='pcalua.exe';                       Where='Sys';       Risk='Standard'; Note='Proxy execution' }
    [pscustomobject]@{ Name='presentationhost.exe';             Where='Sys';       Risk='Standard'; Note='Runs remote XBAP' }
    [pscustomobject]@{ Name='print.exe';                        Where='Sys';       Risk='Standard'; Note='Copy from UNC' }
    [pscustomobject]@{ Name='regasm.exe';                       Where='Net';       Risk='Standard'; Note='Proxy execution via DLL' }
    [pscustomobject]@{ Name='regsvcs.exe';                      Where='Net';       Risk='Standard'; Note='Proxy execution via DLL' }
    [pscustomobject]@{ Name='regsvr32.exe';                     Where='Sys';       Risk='Standard'; Note='Remote scriptlet (squiblydoo)' }
    [pscustomobject]@{ Name='replace.exe';                      Where='Sys';       Risk='Standard'; Note='Copy from UNC' }
    [pscustomobject]@{ Name='runscripthelper.exe';              Where='Sys';       Risk='Standard'; Note='Executes PowerShell from path' }
    [pscustomobject]@{ Name='scriptrunner.exe';                 Where='Sys';       Risk='Standard'; Note='Proxy execution incl. UNC' }
    [pscustomobject]@{ Name='syncappvpublishingserver.exe';     Where='Sys';       Risk='Standard'; Note='PowerShell proxy execution' }
    [pscustomobject]@{ Name='wmic.exe';                         Where='Wbem';      Risk='Standard'; Note='Remote XSL execution / recon' }
    [pscustomobject]@{ Name='wscript.exe';                      Where='Sys';       Risk='Standard'; Note='Script host, download and execute' }
    [pscustomobject]@{ Name='xwizard.exe';                      Where='Sys';       Risk='Standard'; Note='Downloads XML / runs COM' }

    # ---- HighRisk: real operational blast radius. Pilot before enabling. ----
    [pscustomobject]@{ Name='cmd.exe';                          Where='Sys';       Risk='HighRisk'; Note='Breaks UNC copy from scripts' }
    [pscustomobject]@{ Name='MpCmdRun.exe';                     Where='Defender';  Risk='HighRisk'; Note='Breaks -SignatureUpdate downloads' }
    [pscustomobject]@{ Name='msbuild.exe';                      Where='Net';       Risk='HighRisk'; Note='Breaks developer workstations' }
    [pscustomobject]@{ Name='msiexec.exe';                      Where='Sys';       Risk='HighRisk'; Note='Breaks install from URL' }
    [pscustomobject]@{ Name='powershell.exe';                   Where='Ps';        Risk='HighRisk'; Note='Breaks many mgmt/deployment scripts' }
    [pscustomobject]@{ Name='powershell_ise.exe';               Where='Ps';        Risk='HighRisk'; Note='ISE network access' }
    [pscustomobject]@{ Name='pwsh.exe';                         Where='Pwsh';      Risk='HighRisk'; Note='PowerShell 7 network access' }
    [pscustomobject]@{ Name='rundll32.exe';                     Where='Sys';       Risk='HighRisk'; Note='Used by legitimate OS components' }
    [pscustomobject]@{ Name='winrs.exe';                        Where='Sys';       Risk='HighRisk'; Note='Breaks admin remoting' }
)

$Script:InternetOnlyRanges = @(
    '1.0.0.0-9.255.255.255'
    '11.0.0.0-100.63.255.255'
    '100.128.0.0-126.255.255.255'
    '128.0.0.0-169.253.255.255'
    '169.255.0.0-172.15.255.255'
    '172.32.0.0-192.167.255.255'
    '192.169.0.0-223.255.255.255'
    '2000::/3'
)

function Initialize-PathRoot {
    $Script:WinDir     = $env:windir
    $Script:Sys32Rule  = Join-Path $Script:WinDir 'System32'
    $Script:Is32BitHost = ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess)
    $Script:Sys32Probe = if ($Script:Is32BitHost) { Join-Path $Script:WinDir 'Sysnative' } else { $Script:Sys32Rule }
    $Script:WowRoot    = Join-Path $Script:WinDir 'SysWOW64'
    $Script:PF64       = if ($env:ProgramW6432) { $env:ProgramW6432 } else { $env:ProgramFiles }
    $Script:PF86       = ${env:ProgramFiles(x86)}
}

function Get-CandidateDirectory {
    param([Parameter(Mandatory)][string]$Where)
    switch ($Where) {
        'Sys'       { @($Script:Sys32Probe, $Script:WowRoot) }
        'Wbem'      { @((Join-Path $Script:Sys32Probe 'wbem'), (Join-Path $Script:WowRoot 'wbem')) }
        'ImeShared' { @((Join-Path $Script:Sys32Probe 'IME\SHARED'), (Join-Path $Script:WowRoot 'IME\SHARED')) }
        'Ps'        { @((Join-Path $Script:Sys32Probe 'WindowsPowerShell\v1.0'), (Join-Path $Script:WowRoot 'WindowsPowerShell\v1.0')) }
        'Net'       { @((Join-Path $Script:WinDir 'Microsoft.NET\Framework*\v*')) }
        'Defender'  { @((Join-Path $Script:PF64 'Windows Defender'),
                        (Join-Path $env:ProgramData 'Microsoft\Windows Defender\Platform\*')) }
        'Pwsh'      { @((Join-Path $Script:PF64 'PowerShell\*'),
                        $(if ($Script:PF86) { Join-Path $Script:PF86 'PowerShell\*' })) }
        default     { @() }
    }
}

function Resolve-LolbasTarget {
    param([Parameter(Mandatory)][pscustomobject]$Entry)

    $found = New-Object System.Collections.Generic.List[string]
    $sysnative = Join-Path $Script:WinDir 'Sysnative'

    foreach ($pattern in @(Get-CandidateDirectory -Where $Entry.Where | Where-Object { $_ })) {
        $dirs = @()
        if ($pattern -match '[\*\?]') {
            $dirs = @(Get-Item -Path $pattern -Force -ErrorAction SilentlyContinue |
                        Where-Object { $_.PSIsContainer } |
                        Select-Object -ExpandProperty FullName)
        }
        elseif (Test-Path -LiteralPath $pattern -PathType Container) {
            $dirs = @($pattern)
        }

        foreach ($dir in $dirs) {
            $candidate = Join-Path $dir $Entry.Name
            if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) { continue }

            $item = Get-Item -LiteralPath $candidate -Force -ErrorAction SilentlyContinue
            if (-not $item) { continue }

            $rulePath = $item.FullName
            if ($Script:Is32BitHost -and $rulePath.StartsWith($sysnative, [StringComparison]::OrdinalIgnoreCase)) {
                $rulePath = $Script:Sys32Rule + $rulePath.Substring($sysnative.Length)
            }
            if (-not ($found | Where-Object { $_ -ieq $rulePath })) { $found.Add($rulePath) }
        }
    }
    $found
}

function Get-PathTag {
    param([Parameter(Mandatory)][string]$Path)
    $dir = Split-Path -Path $Path -Parent
    $tag = $dir -replace '^[A-Za-z]:\\', ''
    $tag = $tag -replace '^(?i)Windows\\', ''
    $tag -replace '\\', '/'
}

function Get-ShortHash {
    param([Parameter(Mandatory)][string]$Text)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Text.ToLowerInvariant()))
        ((($bytes | ForEach-Object { $_.ToString('x2') }) -join '')).Substring(0, 8)
    }
    finally { $sha.Dispose() }
}

function Get-DesiredRuleSet {
    param(
        [Parameter(Mandatory)][string]$RuleGroup,
        [Parameter(Mandatory)][string]$RulePrefix,
        [bool]$IncludeHighRisk = $false,
        [bool]$BlockInbound    = $false,
        [string]$BlockScope    = 'All',
        [string[]]$ExcludeBinary = @()
    )

    $remoteAddress = if ($BlockScope -eq 'InternetOnly') { $Script:InternetOnlyRanges } else { @('Any') }
    $configFingerprint = Get-ShortHash -Text ("scope={0};remote={1};profile=Any;action=Block;cat={2}" -f `
                            $BlockScope, ($remoteAddress -join ','), $Script:CatalogVersion)

    $directions = @('Outbound')
    if ($BlockInbound) { $directions += 'Inbound' }

    foreach ($entry in $Script:LolbasCatalog) {
        if ($entry.Risk -eq 'HighRisk' -and -not $IncludeHighRisk) { continue }
        if ($ExcludeBinary -contains $entry.Name) { continue }

        foreach ($path in (Resolve-LolbasTarget -Entry $entry)) {
            $tag  = Get-PathTag  -Path $path
            $hash = Get-ShortHash -Text $path
            $base = [System.IO.Path]::GetFileNameWithoutExtension($entry.Name)

            foreach ($direction in $directions) {
                $short = if ($direction -eq 'Outbound') { 'Out' } else { 'In' }
                [pscustomobject]@{
                    RuleName      = 'LOLBAS_{0}_{1}_{2}' -f $base, $short, $hash
                    DisplayName   = '{0} - {1} [{2}] ({3})' -f $RulePrefix, $entry.Name, $tag, $short
                    Description   = 'Managed by LOLBAS firewall hardening. {0}. cfg={1}' -f $entry.Note, $configFingerprint
                    Group         = $RuleGroup
                    Program       = $path
                    Direction     = $direction
                    RemoteAddress = $remoteAddress
                    Risk          = $entry.Risk
                    Binary        = $entry.Name
                }
            }
        }
    }
}

#endregion ================== END SHARED BLOCK ==================

#region ---------------------------- Logging ----------------------------

$Script:LogFile = Join-Path $LogDirectory 'Detect-LolbasFirewall.log'

function Initialize-Log {
    try {
        if (-not (Test-Path -LiteralPath $LogDirectory)) {
            New-Item -Path $LogDirectory -ItemType Directory -Force | Out-Null
        }
        if (Test-Path -LiteralPath $Script:LogFile) {
            if ((Get-Item -LiteralPath $Script:LogFile).Length -gt 2MB) {
                Move-Item -LiteralPath $Script:LogFile -Destination "$($Script:LogFile).bak" -Force
            }
        }
    }
    catch { $Script:LogFile = $null }
}

function Write-DetailLog {
    param([string]$Message, [ValidateSet('INFO','OK','WARN','ERROR')][string]$Level = 'INFO')
    if (-not $Script:LogFile) { return }
    $line = '{0} [{1,-5}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    try { Add-Content -LiteralPath $Script:LogFile -Value $line -Encoding UTF8 -ErrorAction Stop } catch { }
}

#endregion

#region ---------------------------- Main ----------------------------

Initialize-Log
Initialize-PathRoot

try {
    Write-DetailLog "=== Detection v$ScriptVersion starting (catalog $Script:CatalogVersion) ==="

    if (-not (Get-Command -Name Get-NetFirewallRule -ErrorAction SilentlyContinue)) {
        Write-Output 'NetSecurity module unavailable - cannot evaluate. Triggering remediation.'
        Write-DetailLog 'NetSecurity module unavailable.' 'ERROR'
        exit 1
    }

    $desired = @(Get-DesiredRuleSet -RuleGroup $RuleGroup -RulePrefix $RulePrefix `
                    -IncludeHighRisk $IncludeHighRisk -BlockInbound $BlockInbound `
                    -BlockScope $BlockScope -ExcludeBinary $ExcludeBinary)

    if ($desired.Count -eq 0) {
        Write-Output 'Desired rule set is empty - configuration problem, not remediating.'
        Write-DetailLog 'Desired rule set empty.' 'ERROR'
        exit 0
    }

    # Actual state
    $actual = @{}
    foreach ($r in @(Get-NetFirewallRule -Group $RuleGroup -PolicyStore PersistentStore -ErrorAction SilentlyContinue)) {
        $actual[[string]$r.Name] = $r
    }

    $programMap = @{}
    Get-NetFirewallApplicationFilter -All -PolicyStore PersistentStore -ErrorAction SilentlyContinue |
        ForEach-Object { if ($_.InstanceID) { $programMap[[string]$_.InstanceID] = [string]$_.Program } }

    $missing  = New-Object System.Collections.Generic.List[string]
    $drifted  = New-Object System.Collections.Generic.List[string]
    $compliant = 0

    foreach ($d in $desired) {
        $current = $actual[$d.RuleName]
        if (-not $current) { $missing.Add($d.DisplayName); continue }

        $reason = $null
        if     ([string]$current.Enabled     -ne 'True')             { $reason = 'disabled' }
        elseif ([string]$current.Action      -ne 'Block')            { $reason = 'action is ' + $current.Action }
        elseif ([string]$current.Direction   -ne $d.Direction)       { $reason = 'wrong direction' }
        elseif ([string]$current.Profile     -ne 'Any')              { $reason = 'profile is ' + $current.Profile }
        elseif ([string]$current.DisplayName -ne $d.DisplayName)     { $reason = 'display name changed' }
        elseif ([string]$current.Description -ne $d.Description)     { $reason = 'config fingerprint changed' }
        else {
            $program = $programMap[[string]$current.Name]
            if (-not $program)              { $reason = 'no program filter' }
            elseif ($program -ine $d.Program) { $reason = 'program path mismatch' }
        }

        if ($reason) { $drifted.Add(('{0} ({1})' -f $d.DisplayName, $reason)) } else { $compliant++ }
    }

    # Rules we own that are no longer wanted
    $wanted = @{}
    foreach ($d in $desired) { $wanted[$d.RuleName] = $true }
    $stale = @($actual.Keys | Where-Object { -not $wanted.ContainsKey($_) })

    # Detail to the log, summary to stdout
    foreach ($m in $missing) { Write-DetailLog "MISSING : $m" 'WARN' }
    foreach ($m in $drifted) { Write-DetailLog "DRIFTED : $m" 'WARN' }
    foreach ($m in $stale)   { Write-DetailLog "STALE   : $m ($($actual[$m].DisplayName))" 'WARN' }

    $problemCount = $missing.Count + $drifted.Count + $stale.Count

    if ($problemCount -eq 0) {
        $msg = 'Compliant: {0}/{1} LOLBAS block rules present and correct (scope={2}, highRisk={3}).' -f `
                    $compliant, $desired.Count, $BlockScope, $IncludeHighRisk
        Write-Output $msg
        Write-DetailLog $msg 'OK'
        exit 0
    }

    $summary = New-Object System.Collections.Generic.List[string]
    $summary.Add(('Non-compliant: {0} missing, {1} drifted, {2} stale (of {3} expected).' -f `
                    $missing.Count, $drifted.Count, $stale.Count, $desired.Count))

    $sample = @($missing) + @($drifted) | Select-Object -First $MaxNamesToPrint
    foreach ($s in $sample) { $summary.Add("  - $s") }
    if ($problemCount -gt $MaxNamesToPrint) {
        $summary.Add(('  ... and {0} more (see {1})' -f ($problemCount - $MaxNamesToPrint), $Script:LogFile))
    }

    $out = $summary -join [Environment]::NewLine
    Write-Output $out
    Write-DetailLog 'Detection result: non-compliant.' 'WARN'
    exit 1
}
catch {
    Write-Output "Detection error: $($_.Exception.Message)"
    Write-DetailLog "Fatal: $($_.Exception.Message)" 'ERROR'
    Write-DetailLog "At: $($_.InvocationInfo.PositionMessage)" 'ERROR'
    # Fail closed: let remediation run rather than silently reporting healthy.
    exit 1
}

#endregion
