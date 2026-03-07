#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Silently removes Microsoft 365 and OneNote (all language variants) using
    each product's own registered UninstallString from the Windows registry.

.DESCRIPTION
    Instead of building custom C2R arguments (which caused exit 17100),
    this script reads the UninstallString directly from:
      HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall
    for each matching product -- exactly what Add/Remove Programs calls.

.NOTES
    Version : 3.0  (fixes exit code 17100 from v2.0)
    Target  : Dell desktop, C2R Office 16.0.17328.20206
    Deploy  : Run as local Admin or SYSTEM via RMM
#>

# --- Logging ------------------------------------------------------------------

$LogDir  = "$env:ProgramData\Faronics\Logs"
$LogFile = "$LogDir\Remove-M365-OneNote-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
$null    = New-Item -Path $LogDir -ItemType Directory -Force -ErrorAction SilentlyContinue

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $Entry = "[{0}] [{1}] {2}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    $Entry | Tee-Object -FilePath $LogFile -Append | Write-Host
}

# --- Products to remove (display name substrings) -----------------------------

$TargetDisplayNames = @(
    "Microsoft 365 - en-us",
    "Microsoft 365 - es-es",
    "Microsoft 365 - fr-fr",
    "Microsoft 365 - pt-br",
    "Microsoft OneNote - en-us",
    "Microsoft OneNote - es-es",
    "Microsoft OneNote - fr-fr",
    "Microsoft OneNote - pt-br"
)

# --- Step 1: Enumerate uninstall entries --------------------------------------

Write-Log "===== Remove-M365-OneNote-Bloatware v3.0 ====="
Write-Log "Running as: $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)"
Write-Log "--- Scanning registry for uninstall entries ---"

$UninstallRoots = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
)

$Found = [System.Collections.Generic.List[PSObject]]::new()

foreach ($Root in $UninstallRoots) {
    Get-ChildItem -Path $Root -ErrorAction SilentlyContinue | ForEach-Object {
        $Props = Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue
        if (-not $Props.DisplayName) { return }

        foreach ($Target in $TargetDisplayNames) {
            if ($Props.DisplayName -like "*$Target*") {
                Write-Log "Found: '$($Props.DisplayName)'"
                Write-Log "  UninstallString: $($Props.UninstallString)"
                $Found.Add([PSCustomObject]@{
                    DisplayName     = $Props.DisplayName
                    UninstallString = $Props.UninstallString
                    QuietUninstall  = $Props.QuietUninstallString
                })
                break
            }
        }
    }
}

if ($Found.Count -eq 0) {
    Write-Log "No matching products found in registry. Already removed?" "WARN"
    Write-Log "Log saved to: $LogFile"
    exit 0
}

Write-Log "Found $($Found.Count) product(s) to remove."

# --- Step 2: Uninstall each product -------------------------------------------

Write-Log "--- Beginning uninstall ---"

foreach ($Product in $Found) {
    Write-Log "Uninstalling: $($Product.DisplayName)"

    # Prefer QuietUninstallString if present, otherwise use UninstallString
    # and append silent flags
    $RawString = if ($Product.QuietUninstall) {
        $Product.QuietUninstall
    } else {
        $Product.UninstallString
    }

    if ([string]::IsNullOrWhiteSpace($RawString)) {
        Write-Log "  No uninstall string available -- skipping." "WARN"
        continue
    }

    # The uninstall string is typically:
    # "C:\Program Files\...\OfficeClickToRun.exe" scenario=... productstoremove=...
    # We need to split the executable from its arguments.

    if ($RawString -match '^"([^"]+)"\s*(.*)$') {
        $Exe  = $Matches[1]
        $Args = $Matches[2].Trim()
    } elseif ($RawString -match '^(\S+\.exe)\s*(.*)$') {
        $Exe  = $Matches[1]
        $Args = $Matches[2].Trim()
    } else {
        Write-Log "  Could not parse uninstall string: $RawString" "WARN"
        continue
    }

    # Append silent/no-UI flags if not already present
    if ($Args -notmatch 'DisplayLevel') {
        $Args += " DisplayLevel=False"
    }
    if ($Args -notmatch 'forceappshutdown') {
        $Args += " forceappshutdown=True"
    }

    Write-Log "  Exe : $Exe"
    Write-Log "  Args: $Args"

    try {
        $proc = Start-Process -FilePath $Exe `
                              -ArgumentList $Args `
                              -Wait `
                              -PassThru `
                              -ErrorAction Stop

        $ExitCode = $proc.ExitCode
        Write-Log "  Exit code: $ExitCode"

        switch ($ExitCode) {
            0     { Write-Log "  SUCCESS" }
            13    { Write-Log "  SUCCESS -- reboot required" "WARN" }
            17002 { Write-Log "  Already removed or cancelled (17002)" "WARN" }
            17044 { Write-Log "  SUCCESS -- reboot required (17044)" "WARN" }
            default { Write-Log "  Completed with unexpected code $ExitCode" "WARN" }
        }
    } catch {
        Write-Log "  FAILED to launch uninstaller: $_" "ERROR"
    }

    # Brief pause between products to avoid C2R engine conflicts
    Start-Sleep -Seconds 3
}

# --- Step 3: Verify -----------------------------------------------------------

Write-Log "--- Post-removal verification ---"
Start-Sleep -Seconds 5

$Remaining = [System.Collections.Generic.List[string]]::new()

foreach ($Root in $UninstallRoots) {
    Get-ChildItem -Path $Root -ErrorAction SilentlyContinue | ForEach-Object {
        $Props = Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue
        foreach ($Target in $TargetDisplayNames) {
            if ($Props.DisplayName -like "*$Target*") {
                $Remaining.Add($Props.DisplayName)
            }
        }
    }
}

if ($Remaining.Count -gt 0) {
    Write-Log "Still present after removal attempt:" "WARN"
    $Remaining | ForEach-Object { Write-Log "  - $_" "WARN" }
    Write-Log "A reboot and re-run may be required." "WARN"
} else {
    Write-Log "All targeted products have been removed successfully."
}

# --- Step 4: Cleanup shortcuts ------------------------------------------------

Write-Log "--- Cleaning up shortcuts ---"

$Shortcuts = @(
    "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Microsoft Office",
    "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Microsoft 365",
    "$env:PUBLIC\Desktop\Microsoft 365*.lnk",
    "$env:PUBLIC\Desktop\Microsoft OneNote*.lnk",
    "$env:PUBLIC\Desktop\OneNote*.lnk"
)

foreach ($Path in $Shortcuts) {
    if (Test-Path $Path) {
        Write-Log "Removing: $Path"
        Remove-Item -Path $Path -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# --- Done ---------------------------------------------------------------------

Write-Log "===== Script Complete ====="
Write-Log "Log saved to: $LogFile"
