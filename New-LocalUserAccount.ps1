#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Creates a standard local Windows user account (RMM-friendly, fully non-interactive).

.DESCRIPTION
    Creates a local user account with:
      - Password never expires
      - User cannot change password
      - Account never expires
      - Added to the local Users group

.PARAMETER Username
    The username for the new local account. (Required)

.PARAMETER Password
    The password as plain text — suitable for RMM argument passing. (Required)

.PARAMETER FullName
    The display/full name for the account. (Optional)

.PARAMETER Description
    A description for the account. (Optional, defaults to "Standard local user account")

.EXAMPLE
    .\New-LocalUserAccount.ps1 -Username "jsmith" -Password "P@ssw0rd!"

.EXAMPLE
    .\New-LocalUserAccount.ps1 -Username "jsmith" -Password "P@ssw0rd!" -FullName "John Smith" -Description "Kiosk account"
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [ValidateLength(1, 20)]
    [ValidatePattern('^[a-zA-Z0-9._-]+$')]
    [string]$Username,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$Password,

    [Parameter(Mandatory = $false)]
    [string]$FullName = "",

    [Parameter(Mandatory = $false)]
    [string]$Description = "Standard local user account"
)

# ─────────────────────────────────────────────
#  Helper: Write coloured status messages
# ─────────────────────────────────────────────
function Write-Status {
    param([string]$Message, [string]$Type = "INFO")
    $colours = @{ INFO = "Cyan"; SUCCESS = "Green"; WARNING = "Yellow"; ERROR = "Red" }
    Write-Host "[$Type] $Message" -ForegroundColor $colours[$Type]
}

# ─────────────────────────────────────────────
#  Convert plain-text password to SecureString
# ─────────────────────────────────────────────
$SecurePassword = ConvertTo-SecureString $Password -AsPlainText -Force

# ─────────────────────────────────────────────
#  Check if account already exists
# ─────────────────────────────────────────────
Write-Status "Checking whether user '$Username' already exists..." "INFO"

if (Get-LocalUser -Name $Username -ErrorAction SilentlyContinue) {
    Write-Status "User '$Username' already exists on this machine. Aborting." "WARNING"
    exit 1
}

# ─────────────────────────────────────────────
#  Create the user account
#  NOTE: -PasswordNeverExpires and -UserMayNotChangePassword are switches,
#        they must NOT be followed by $true/$false
# ─────────────────────────────────────────────
Write-Status "Creating local user account: $Username" "INFO"

try {
    New-LocalUser `
        -Name                     $Username `
        -Password                 $SecurePassword `
        -FullName                 $FullName `
        -Description              $Description `
        -PasswordNeverExpires `
        -UserMayNotChangePassword `
        -AccountNeverExpires `
        -ErrorAction Stop | Out-Null

    Write-Status "User '$Username' created successfully." "SUCCESS"
}
catch {
    Write-Status "Failed to create user '$Username': $_" "ERROR"
    exit 1
}

# ─────────────────────────────────────────────
#  Add to the local 'Users' group
# ─────────────────────────────────────────────
try {
    Add-LocalGroupMember -Group "Users" -Member $Username -ErrorAction Stop
    Write-Status "Added '$Username' to the local 'Users' group." "SUCCESS"
}
catch {
    Write-Status "Could not add '$Username' to the Users group: $_" "WARNING"
}

# ─────────────────────────────────────────────
#  Verify & display summary
# ─────────────────────────────────────────────
$user = Get-LocalUser -Name $Username

Write-Host ""
Write-Host "────────────────────────────────────────" -ForegroundColor DarkGray
Write-Host " Account Summary" -ForegroundColor White
Write-Host "────────────────────────────────────────" -ForegroundColor DarkGray
Write-Host " Username         : $($user.Name)"
Write-Host " Full Name        : $(if ($user.FullName) { $user.FullName } else { '(not set)' })"
Write-Host " Description      : $($user.Description)"
Write-Host " Enabled          : $($user.Enabled)"
Write-Host " Pwd Never Expires: $($user.PasswordNeverExpires)"
Write-Host " Cannot Change Pwd: $($user.UserMayNotChangePassword)"
Write-Host " Account Expires  : $(if ($user.AccountExpires) { $user.AccountExpires } else { 'Never' })"
Write-Host "────────────────────────────────────────" -ForegroundColor DarkGray
