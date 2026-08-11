#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Blocks known LOLBAS (Living Off The Land Binaries And Scripts) executables from making
    network connections, using Windows Defender Firewall rules.

.DESCRIPTION
    Intended as the REMEDIATION half of an Intune "Scripts and remediations" package
    (pair it with Detect-LolbasFirewall.ps1).

    For every binary in the catalog that actually exists on the device, the script creates a
    deterministic, idempotent outbound (optionally also inbound) BLOCK rule scoped to the
    executable's full path. Rules are tagged with a firewall Group so they can be audited,
    reported on, and removed cleanly.

    The script is safe to re-run. It will:
      * create missing rules
      * repair rules that have drifted (disabled, changed action, changed scope, wrong path)
      * remove rules in its own Group that are no longer expected (e.g. after you change
        $IncludeHighRisk, $ExcludeBinary, or after a binary is uninstalled)

.PARAMETER Remove
    Removes every rule in the managed Group and deletes the registry stamp. Use for rollback.

.NOTES
    Version : 1.0.0
    Exit 0  = success, Exit 1 = one or more rules could not be applied.

    IMPORTANT: Run this in 64-bit PowerShell (Intune setting "Run script in 64-bit
    PowerShell host" = Yes). The script will still work under a 32-bit host via Sysnative,
    but 64-bit is strongly preferred.

    IMPORTANT: If your firewall profiles are managed by GPO/Intune firewall policy with
    local rule merging DISABLED, locally created rules will not take effect. The script
    warns about this in its log but cannot fix it. In that case, deploy the equivalent
    rules via Endpoint security > Firewall > Rules instead.
#>

[CmdletBinding()]
param(
    # ----------------------------- ADMIN CONFIG -----------------------------
    # Intune calls the script with no arguments, so these defaults are what ships.

    # Firewall Group used to tag/own the rules. Do not reuse for anything else.
    [string]   $RuleGroup   = 'LOLBAS Hardening',

    # Human-readable prefix for rule display names.
    [string]   $RulePrefix  = 'LOLBAS Block',

    # $false = only the "Standard" catalog (low breakage risk).
    # $true  = also the "HighRisk" catalog (powershell.exe, rundll32.exe, msiexec.exe, cmd.exe...).
    #          Do NOT enable this without a pilot ring. See README.
    [bool]     $IncludeHighRisk = $false,

    # Also create matching inbound block rules. Outbound is where the value is.
    [bool]     $BlockInbound    = $false,

    # 'All'          = block all remote addresses (strictest).
    # 'InternetOnly' = block only routable/public addresses, so LAN + UNC traffic keeps working.
    #                  Much lower breakage, still stops internet download/C2 via LOLBins.
    [ValidateSet('All','InternetOnly')]
    [string]   $BlockScope      = 'All',

    # File names to skip entirely, e.g. @('findstr.exe','curl.exe')
    [string[]] $ExcludeBinary   = @(),

    [string]   $LogDirectory    = "$env:ProgramData\LolbasHardening\Logs",
    [string]   $StampKey        = 'HKLM:\SOFTWARE\LolbasHardening',
    # ------------------------------------------------------------------------

    [switch]   $Remove
)

$ErrorActionPreference = 'Stop'
$ScriptVersion = '1.0.0'

#region ============ SHARED BLOCK - KEEP IN SYNC WITH Detect-LolbasFirewall.ps1 ============

$Script:CatalogVersion = '2026.08.11'

# Where  : location token resolved by Get-CandidateDirectory
# Risk   : Standard = deploy broadly | HighRisk = pilot first, opt-in via $IncludeHighRisk
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

# Public/routable address space only: excludes 0/8, 10/8, 100.64/10, 127/8, 169.254/16,
# 172.16/12, 192.168/16, multicast and reserved. IPv6 global unicast only (no ULA/link-local).
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
    <# Returns the concrete on-disk paths for a catalog entry, or nothing if absent. #>
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
            # A 32-bit host sees the native folder as Sysnative; the firewall needs System32.
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
    <#
      Produces the full set of rules that SHOULD exist on this device given the
      current configuration. Detection and remediation both call this so they
      can never disagree.
    #>
    param(
        [Parameter(Mandatory)][string]$RuleGroup,
        [Parameter(Mandatory)][string]$RulePrefix,
        [bool]$IncludeHighRisk = $false,
        [bool]$BlockInbound    = $false,
        [string]$BlockScope    = 'All',
        [string[]]$ExcludeBinary = @()
    )

    $remoteAddress = if ($BlockScope -eq 'InternetOnly') { $Script:InternetOnlyRanges } else { @('Any') }
    # Any change to scope/profile/action changes this fingerprint, which forces a rebuild.
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

$Script:LogFile = Join-Path $LogDirectory 'Remediate-LolbasFirewall.log'

function Initialize-Log {
    try {
        if (-not (Test-Path -LiteralPath $LogDirectory)) {
            New-Item -Path $LogDirectory -ItemType Directory -Force | Out-Null
        }
        if (Test-Path -LiteralPath $Script:LogFile) {
            $size = (Get-Item -LiteralPath $Script:LogFile).Length
            if ($size -gt 2MB) {
                Move-Item -LiteralPath $Script:LogFile -Destination "$($Script:LogFile).bak" -Force
            }
        }
    }
    catch { $Script:LogFile = $null }   # never let logging break remediation
}

function Write-Log {
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet('INFO','OK','WARN','ERROR')][string]$Level = 'INFO'
    )
    $line = '{0} [{1,-5}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    Write-Output $line
    if ($Script:LogFile) {
        try { Add-Content -LiteralPath $Script:LogFile -Value $line -Encoding UTF8 -ErrorAction Stop } catch { }
    }
}

#endregion

#region ------------------------- Helper routines -------------------------

function Get-ManagedRule {
    param([Parameter(Mandatory)][string]$Group)
    @(Get-NetFirewallRule -Group $Group -PolicyStore PersistentStore -ErrorAction SilentlyContinue)
}

function Get-ApplicationFilterMap {
    $map = @{}
    Get-NetFirewallApplicationFilter -All -PolicyStore PersistentStore -ErrorAction SilentlyContinue |
        ForEach-Object { if ($_.InstanceID) { $map[[string]$_.InstanceID] = [string]$_.Program } }
    $map
}

function Test-RuleMatchesDesiredState {
    param(
        [Parameter(Mandatory)]$ExistingRule,
        [Parameter(Mandatory)][pscustomobject]$Desired,
        [Parameter(Mandatory)][hashtable]$ProgramMap
    )
    if ([string]$ExistingRule.Enabled     -ne 'True')              { return $false }
    if ([string]$ExistingRule.Action      -ne 'Block')             { return $false }
    if ([string]$ExistingRule.Direction   -ne $Desired.Direction)  { return $false }
    if ([string]$ExistingRule.Profile     -ne 'Any')               { return $false }
    if ([string]$ExistingRule.DisplayName -ne $Desired.DisplayName){ return $false }
    # Description carries the config fingerprint, so a scope change invalidates the rule.
    if ([string]$ExistingRule.Description -ne $Desired.Description) { return $false }

    $program = $ProgramMap[[string]$ExistingRule.Name]
    if (-not $program -or $program -ine $Desired.Program) { return $false }

    return $true
}

function New-ManagedFirewallRule {
    param([Parameter(Mandatory)][pscustomobject]$Desired)
    $params = @{
        Name        = $Desired.RuleName
        DisplayName = $Desired.DisplayName
        Description = $Desired.Description
        Group       = $Desired.Group
        Direction   = $Desired.Direction
        Action      = 'Block'
        Enabled     = 'True'
        Profile     = 'Any'
        Program     = $Desired.Program
        PolicyStore = 'PersistentStore'
        ErrorAction = 'Stop'
    }
    if ($Desired.RemoteAddress -and ($Desired.RemoteAddress -join ',') -ne 'Any') {
        $params['RemoteAddress'] = $Desired.RemoteAddress
    }
    New-NetFirewallRule @params | Out-Null
}

function Write-Stamp {
    param([hashtable]$Values)
    try {
        if (-not (Test-Path -LiteralPath $StampKey)) { New-Item -Path $StampKey -Force | Out-Null }
        foreach ($k in $Values.Keys) {
            New-ItemProperty -Path $StampKey -Name $k -Value $Values[$k] -PropertyType String -Force | Out-Null
        }
    }
    catch { Write-Log "Could not write registry stamp: $($_.Exception.Message)" 'WARN' }
}

function Test-LocalRuleMerge {
    <# Local rules are ignored if policy disables merging. Warn loudly, do not fail. #>
    try {
        foreach ($p in (Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop)) {
            if ([string]$p.AllowLocalFirewallRules -eq 'False') {
                Write-Log ("Profile '{0}' has AllowLocalFirewallRules=False. Locally created rules will NOT be enforced - deploy these rules via firewall policy instead." -f $p.Name) 'WARN'
            }
        }
    }
    catch { Write-Log "Could not read firewall profiles: $($_.Exception.Message)" 'WARN' }
}

#endregion

#region ---------------------------- Main ----------------------------

Initialize-Log
Initialize-PathRoot

$exitCode = 0
try {
    Write-Log ("=== LOLBAS firewall remediation v{0} (catalog {1}) starting ===" -f $ScriptVersion, $Script:CatalogVersion)
    Write-Log ("Host: 64-bit OS={0}, 64-bit process={1}, user={2}" -f `
        [Environment]::Is64BitOperatingSystem, [Environment]::Is64BitProcess, "$env:USERDOMAIN\$env:USERNAME")
    if ($Script:Is32BitHost) {
        Write-Log 'Running in a 32-bit PowerShell host. Using Sysnative to enumerate native binaries. Prefer the 64-bit host in Intune.' 'WARN'
    }

    if (-not (Get-Command -Name New-NetFirewallRule -ErrorAction SilentlyContinue)) {
        throw 'The NetSecurity module is unavailable on this device.'
    }

    # ---------- Rollback path ----------
    if ($Remove) {
        Write-Log "Remove mode: deleting all rules in group '$RuleGroup'."
        $toRemove = Get-ManagedRule -Group $RuleGroup
        foreach ($r in $toRemove) {
            try {
                Remove-NetFirewallRule -Name $r.Name -PolicyStore PersistentStore -ErrorAction Stop
                Write-Log "Removed $($r.DisplayName)" 'OK'
            }
            catch {
                $exitCode = 1
                Write-Log "Failed to remove $($r.Name): $($_.Exception.Message)" 'ERROR'
            }
        }
        try { if (Test-Path -LiteralPath $StampKey) { Remove-Item -LiteralPath $StampKey -Recurse -Force } } catch { }
        Write-Log ("Remove complete. {0} rule(s) deleted." -f $toRemove.Count)
        exit $exitCode
    }

    Test-LocalRuleMerge

    # ---------- Build desired state ----------
    $desired = @(Get-DesiredRuleSet -RuleGroup $RuleGroup -RulePrefix $RulePrefix `
                    -IncludeHighRisk $IncludeHighRisk -BlockInbound $BlockInbound `
                    -BlockScope $BlockScope -ExcludeBinary $ExcludeBinary)

    if ($desired.Count -eq 0) { throw 'Desired rule set is empty - check the catalog and exclusion list.' }

    $binaryCount = ($desired | Select-Object -ExpandProperty Binary -Unique).Count
    Write-Log ("Configuration: scope={0}, inbound={1}, highRisk={2}, excluded={3}" -f `
        $BlockScope, $BlockInbound, $IncludeHighRisk, $(if ($ExcludeBinary) { $ExcludeBinary -join ',' } else { 'none' }))
    Write-Log ("Desired state: {0} rule(s) covering {1} binary path group(s)." -f $desired.Count, $binaryCount)

    # ---------- Reconcile ----------
    $programMap = Get-ApplicationFilterMap
    $existing   = @{}
    foreach ($r in (Get-ManagedRule -Group $RuleGroup)) { $existing[[string]$r.Name] = $r }

    $created = 0; $repaired = 0; $compliant = 0; $failed = 0

    foreach ($d in $desired) {
        try {
            $current = $existing[$d.RuleName]
            if ($current) {
                if (Test-RuleMatchesDesiredState -ExistingRule $current -Desired $d -ProgramMap $programMap) {
                    $compliant++
                    continue
                }
                Remove-NetFirewallRule -Name $d.RuleName -PolicyStore PersistentStore -ErrorAction Stop
                New-ManagedFirewallRule -Desired $d
                $repaired++
                Write-Log "Repaired: $($d.DisplayName)" 'OK'
            }
            else {
                # Guard against a same-named rule living outside our group.
                $orphan = Get-NetFirewallRule -Name $d.RuleName -PolicyStore PersistentStore -ErrorAction SilentlyContinue
                if ($orphan) { Remove-NetFirewallRule -Name $d.RuleName -PolicyStore PersistentStore -ErrorAction Stop }
                New-ManagedFirewallRule -Desired $d
                $created++
                Write-Log "Created: $($d.DisplayName)" 'OK'
            }
        }
        catch {
            $failed++
            Write-Log "Failed '$($d.DisplayName)' -> $($d.Program): $($_.Exception.Message)" 'ERROR'
        }
    }

    # ---------- Remove rules we own but no longer want ----------
    $wanted = @{}
    foreach ($d in $desired) { $wanted[$d.RuleName] = $true }

    $stale = 0
    foreach ($name in $existing.Keys) {
        if ($wanted.ContainsKey($name)) { continue }
        try {
            Remove-NetFirewallRule -Name $name -PolicyStore PersistentStore -ErrorAction Stop
            $stale++
            Write-Log "Removed stale rule: $($existing[$name].DisplayName)" 'OK'
        }
        catch {
            $failed++
            Write-Log "Failed to remove stale rule '$name': $($_.Exception.Message)" 'ERROR'
        }
    }

    Write-Log ("Summary: created={0}, repaired={1}, already-compliant={2}, stale-removed={3}, failed={4}" -f `
        $created, $repaired, $compliant, $stale, $failed)

    Write-Stamp -Values @{
        ScriptVersion   = $ScriptVersion
        CatalogVersion  = $Script:CatalogVersion
        RuleGroup       = $RuleGroup
        BlockScope      = $BlockScope
        IncludeHighRisk = [string]$IncludeHighRisk
        BlockInbound    = [string]$BlockInbound
        ExcludedBinary  = ($ExcludeBinary -join ',')
        RuleCount       = [string]$desired.Count
        LastRunUtc      = (Get-Date).ToUniversalTime().ToString('s') + 'Z'
        LastResult      = $(if ($failed -gt 0) { 'PartialFailure' } else { 'Success' })
    }

    if ($failed -gt 0) {
        $exitCode = 1
        Write-Log "Remediation completed with $failed failure(s)." 'ERROR'
    }
    else {
        Write-Log 'Remediation completed successfully.' 'OK'
    }
}
catch {
    $exitCode = 1
    Write-Log "Fatal: $($_.Exception.Message)" 'ERROR'
    Write-Log "At: $($_.InvocationInfo.PositionMessage)" 'ERROR'
}

exit $exitCode

#endregion
