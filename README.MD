# LOLBAS Firewall Hardening for Intune

Blocks known LOLBAS binaries from making network connections using Windows Defender Firewall
program-scoped BLOCK rules. Ships as a detection + remediation pair for Intune Remediations.

| File | Role |
|---|---|
| `Detect-LolbasFirewall.ps1` | Detection script. Read-only. Exit 0 = compliant, exit 1 = remediate. |
| `Remediate-LolbasFirewall.ps1` | Creates/repairs/removes the rules. Exit 0 = success. |

## What it does

- Resolves each catalogued binary to its real path(s) — System32, SysWOW64, `System32\wbem`,
  `Microsoft.NET\Framework*\v*`, `WindowsPowerShell\v1.0`, Defender platform folders — and
  only creates rules for binaries that actually exist on that device.
- Creates one outbound block rule per resolved path, with a deterministic rule ID derived
  from a hash of the path, so re-runs are idempotent.
- Tags every rule with the firewall Group `LOLBAS Hardening` for auditing and clean removal.
- Repairs drift: disabled rules, changed action, changed program path, changed block scope.
- Removes its own rules that are no longer wanted (after you change config or a binary is
  uninstalled). It never touches rules outside its Group.
- Logs to `C:\ProgramData\LolbasHardening\Logs\` and stamps
  `HKLM:\SOFTWARE\LolbasHardening` with version, config, rule count and last run.

Two tiers in the catalog:

- **Standard** (~41 binaries, deployed by default) — `certutil`, `mshta`, `bitsadmin`,
  `regsvr32`, `cscript`/`wscript`, `hh`, `ftp`, `curl`, `wmic`, `installutil`, `msdt`,
  `presentationhost`, `esentutl`, `expand`, `extrac32`, `findstr`, and similar. These have
  low breakage risk in a typical managed fleet.
- **HighRisk** (opt-in via `$IncludeHighRisk = $true`) — `powershell.exe`, `pwsh.exe`,
  `cmd.exe`, `rundll32.exe`, `msiexec.exe`, `msbuild.exe`, `MpCmdRun.exe`, `winrs.exe`.
  Do not enable these outside a pilot ring; see warnings below.

## Deploy in Intune

**Devices → Scripts and remediations → Remediations → Create**

1. Detection script: `Detect-LolbasFirewall.ps1`
2. Remediation script: `Remediate-LolbasFirewall.ps1`
3. Settings:
   - Run this script using the logged-on credentials: **No** (needs SYSTEM)
   - Enforce script signature check: **No** (or sign both scripts and set Yes)
   - Run script in 64-bit PowerShell: **Yes** ← important
4. Schedule: daily is plenty. The scripts are cheap and idempotent.
5. Assign to a pilot group first.

Remediations require appropriate Windows/Intune licensing, and that has changed over time —
confirm your entitlement in the portal. If Remediations aren't available to you, you can
deploy `Remediate-LolbasFirewall.ps1` alone under **Devices → Scripts → Platform scripts**
(same settings), though you lose the compliance reporting.

## Configuration

Edit the `ADMIN CONFIG` block at the top of **both** scripts — they must match, or detection
will report non-compliant on every cycle and remediation will churn.

| Setting | Default | Notes |
|---|---|---|
| `$IncludeHighRisk` | `$false` | Adds the HighRisk tier. Pilot first. |
| `$BlockInbound` | `$false` | Adds matching inbound rules. Outbound is where the value is. |
| `$BlockScope` | `'All'` | `'InternetOnly'` blocks only public/routable addresses so LAN and UNC traffic still works — far lower breakage, still stops internet download and C2. |
| `$ExcludeBinary` | `@()` | e.g. `@('curl.exe','findstr.exe')` for binaries your tooling depends on. |
| `$RuleGroup` | `'LOLBAS Hardening'` | Ownership boundary. Don't reuse it for other rules. |

The `SHARED BLOCK` region (catalog, path resolution, rule naming) is duplicated verbatim in
both scripts because Intune runs them as standalone files. If you add a binary, add it to
both.

## Before you deploy — read this

**Local rules may be ignored.** If your firewall profiles are managed by GPO or an Intune
firewall policy with local rule merging disabled, locally created rules are not enforced.
Check with:

```powershell
Get-NetFirewallProfile -PolicyStore ActiveStore |
    Select-Object Name, Enabled, AllowLocalFirewallRules
```

If `AllowLocalFirewallRules` is `False`, this script's rules will be inert — the remediation
log warns about it. In that case deploy the equivalent rules through **Endpoint security →
Firewall → Rules** instead, or enable local merging for the profile.

**These rules block network access, not execution.** A LOLBin can still run locally, read
files and be abused for local proxy execution. This is one layer — pair it with ASR rules,
WDAC/AppLocker, and Defender.

**Known breakage to plan for:**

- `curl.exe` and `findstr.exe` are commonly used inside admin scripts and vendor installers.
- `cscript.exe`/`wscript.exe` will break legacy logon scripts that fetch anything over the
  network or read from a UNC path.
- `ldifde.exe` breaks AD LDIF import/export from managed endpoints.
- `MpCmdRun.exe` (HighRisk) breaks `-SignatureUpdate`-based Defender definition downloads.
- `msbuild.exe` (HighRisk) breaks NuGet restore and developer workstations generally.
- `powershell.exe`/`pwsh.exe` (HighRisk) break a large amount of management tooling,
  including Win32 app installers and detection scripts that download content. This one is
  the most likely to cause an outage.
- `cmd.exe` (HighRisk) breaks `copy \\server\share\...` from any batch file or script.

Using `$BlockScope = 'InternetOnly'` resolves most of the UNC-related items above while
keeping the internet-download protection, and is a good middle setting for a broad ring.

## Verify

```powershell
# What got created
Get-NetFirewallRule -Group 'LOLBAS Hardening' |
    Select-Object DisplayName, Direction, Action, Enabled |
    Sort-Object DisplayName

# Rule count and last run
Get-ItemProperty 'HKLM:\SOFTWARE\LolbasHardening'

# Functional test - should fail to connect
certutil.exe -urlcache -split -f "http://example.com/" "$env:TEMP\t.txt"

# Logs
Get-Content 'C:\ProgramData\LolbasHardening\Logs\Remediate-LolbasFirewall.log' -Tail 40
```

## Rollback

```powershell
.\Remediate-LolbasFirewall.ps1 -Remove
```

Removes every rule in the Group and deletes the registry stamp. To roll back fleet-wide,
deploy that as a platform script (or temporarily replace the remediation script body with
the `-Remove` call) and unassign the remediation afterwards — unassigning alone does not
delete already-created rules.

## Ops notes

- Roughly 60–80 rules on a typical Windows 11 device with the Standard tier. That's fine for
  the firewall engine, but if you already have thousands of rules, watch policy evaluation
  time.
- Blocked connections are auditable: enable dropped-packet logging per profile, or query
  `Microsoft-Windows-Windows Firewall With Advanced Security/Firewall`. In Defender for
  Endpoint, hunt `DeviceNetworkEvents` for `ActionType == "ConnectionFailed"` on these image
  names to find legitimate usage before you tighten further.
- Recommended rollout: pilot with defaults → broad with defaults or `InternetOnly` → pilot
  `$IncludeHighRisk` on a small, well-monitored ring only if you have the appetite.
