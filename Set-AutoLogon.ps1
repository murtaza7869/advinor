#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Configures Windows Automatic Logon for a local user account.

.DESCRIPTION
    Sets or clears Windows Auto Logon using the Winlogon registry keys.
    Designed for RMM deployment (DeepFreeze Cloud, NinjaRMM, etc.)

.PARAMETER Username
    The local Windows account username to auto-logon with.

.PARAMETER Password
    The plaintext password for the account (passed as RMM script argument).

.PARAMETER Domain
    (Optional) Computer name / domain. Defaults to local computer name.

.PARAMETER LogonCount
    (Optional) Number of times to auto-logon before disabling. 0 = unlimited (default).

.PARAMETER Disable
    (Switch) Disables Auto Logon and clears stored credentials.

.EXAMPLE
    .\Set-AutoLogon.ps1 -Username "KioskUser" -Password "P@ssw0rd!"

.EXAMPLE
    .\Set-AutoLogon.ps1 -Username "KioskUser" -Password "P@ssw0rd!" -LogonCount 3

.EXAMPLE
    .\Set-AutoLogon.ps1 -Disable

.NOTES
    Registry : HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
    Security : Password stored in plaintext under DefaultPassword (standard Windows behavior).
               Restrict access to this key via GPO on shared/kiosk endpoints.
    Version  : 1.3
#>

[CmdletBinding(SupportsShouldProcess)]
param (
    [Parameter(Mandatory = $false)]
    [string]$Username,

    [Parameter(Mandatory = $false)]
    [string]$Password,

    [Parameter(Mandatory = $false)]
    [string]$Domain = $env:COMPUTERNAME,

    [Parameter(Mandatory = $false)]
    [ValidateRange(0, 999)]
    [int]$LogonCount = 0,

    [Parameter(Mandatory = $false)]
    [switch]$Disable
)

# ==============================================================
#  Constants
# ==============================================================
$WinlogonPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
$ScriptName   = "Set-AutoLogon"
$LogFile      = "$env:ProgramData\RMM\Logs\$ScriptName.log"

# ==============================================================
#  Logging Helper
# ==============================================================
function Write-Log {
    param (
        [string]$Message,
        [ValidateSet("INFO","WARN","ERROR","SUCCESS")]
        [string]$Level = "INFO"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $entry = "[$timestamp] [$Level] $Message"
    Write-Host $entry

    $logDir = Split-Path $LogFile
    if (-not (Test-Path $logDir)) {
        New-Item -ItemType Directory -Path $logDir -Force | Out-Null
    }
    Add-Content -Path $LogFile -Value $entry
}

# ==============================================================
#  Validate Winlogon Registry Path
# ==============================================================
function Test-WinlogonPath {
    if (-not (Test-Path $WinlogonPath)) {
        Write-Log "Winlogon registry path not found: $WinlogonPath" -Level ERROR
        exit 1
    }
}

# ==============================================================
#  Set a Registry Value
# ==============================================================
function Set-WinlogonValue {
    param (
        [string]$Name,
        [string]$Value,
        [string]$Type = "String"
    )
    try {
        Set-ItemProperty -Path $WinlogonPath -Name $Name -Value $Value -Type $Type -Force
        if ($Name -eq "DefaultPassword") {
            Write-Log "Set registry value: $Name = ********"
        } else {
            Write-Log "Set registry value: $Name = $Value"
        }
    }
    catch {
        Write-Log "Failed to set registry value '$Name': $_" -Level ERROR
        exit 1
    }
}

# ==============================================================
#  Remove a Registry Value (if it exists)
# ==============================================================
function Remove-WinlogonValue {
    param ([string]$Name)
    try {
        $existing = Get-ItemProperty -Path $WinlogonPath -Name $Name -ErrorAction SilentlyContinue
        if ($null -ne $existing) {
            Remove-ItemProperty -Path $WinlogonPath -Name $Name -Force
            Write-Log "Removed registry value: $Name"
        }
    }
    catch {
        Write-Log "Could not remove registry value '$Name': $_" -Level WARN
    }
}

# ==============================================================
#  Verify the Local User Account Exists
# ==============================================================
function Test-LocalUser {
    param ([string]$User)
    $localUser = Get-LocalUser -Name $User -ErrorAction SilentlyContinue
    if ($null -eq $localUser) {
        Write-Log "Local user account '$User' was NOT found on this machine." -Level ERROR
        return $false
    }
    if ($localUser.Enabled -eq $false) {
        Write-Log "Local user account '$User' exists but is DISABLED. Consider enabling it first." -Level WARN
    }
    return $true
}

# ==============================================================
#  DISABLE Auto Logon
# ==============================================================
function Disable-AutoLogon {
    Write-Log "=== Disabling Windows Auto Logon ==="
    Test-WinlogonPath

    Set-WinlogonValue    -Name "AutoAdminLogon" -Value "0"
    Remove-WinlogonValue -Name "DefaultUserName"
    Remove-WinlogonValue -Name "DefaultPassword"
    Remove-WinlogonValue -Name "DefaultDomainName"
    Remove-WinlogonValue -Name "AutoLogonCount"

    Write-Log "Auto Logon has been disabled and credentials cleared." -Level SUCCESS
}

# ==============================================================
#  ENABLE Auto Logon
# ==============================================================
function Enable-AutoLogon {
    Write-Log "=== Enabling Windows Auto Logon ==="
    Write-Log "Username   : $Username"
    Write-Log "Domain     : $Domain"

    if ($LogonCount -eq 0) {
        Write-Log "LogonCount : Unlimited"
    } else {
        Write-Log "LogonCount : $LogonCount"
    }

    Test-WinlogonPath

    if (-not (Test-LocalUser -User $Username)) {
        exit 1
    }

    Set-WinlogonValue -Name "AutoAdminLogon"    -Value "1"
    Set-WinlogonValue -Name "DefaultUserName"   -Value $Username
    Set-WinlogonValue -Name "DefaultPassword"   -Value $Password
    Set-WinlogonValue -Name "DefaultDomainName" -Value $Domain

    if ($LogonCount -gt 0) {
        Set-WinlogonValue -Name "AutoLogonCount" -Value $LogonCount -Type "DWord"
        Write-Log "AutoLogonCount set to $LogonCount. Auto Logon will disable after $LogonCount logon(s)."
    } else {
        Remove-WinlogonValue -Name "AutoLogonCount"
        Write-Log "AutoLogonCount not set - Auto Logon is unlimited."
    }

    Write-Log "Auto Logon successfully configured for user: $Username" -Level SUCCESS
    Write-Log "A restart is required for Auto Logon to take effect." -Level INFO
}

# ==============================================================
#  MAIN
# ==============================================================
Write-Log "=========================================="
Write-Log "$ScriptName started on $env:COMPUTERNAME"
Write-Log "=========================================="

$currentPrincipal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Log "Script must be run as Administrator." -Level ERROR
    exit 1
}

if ($Disable) {
    Disable-AutoLogon
} else {
    if ([string]::IsNullOrWhiteSpace($Username)) {
        Write-Log "Username is required when enabling Auto Logon. Use -Username <value>." -Level ERROR
        exit 1
    }
    if ([string]::IsNullOrWhiteSpace($Password)) {
        Write-Log "Password is required when enabling Auto Logon. Use -Password <value>." -Level ERROR
        exit 1
    }
    Enable-AutoLogon
}

Write-Log "=========================================="
Write-Log "$ScriptName completed."
Write-Log "=========================================="
exit 0
