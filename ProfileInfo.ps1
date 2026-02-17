# ============================================================
# Windows 11 - User Profile, Account & Redirection Enumeration
# Domain-Joined Machine Edition
# ============================================================

Write-Host ("=" * 70) -ForegroundColor Cyan
Write-Host "  WINDOWS 11 USER PROFILE & ACCOUNT ENUMERATION" -ForegroundColor Cyan
Write-Host "  Computer: $env:COMPUTERNAME | Domain: $env:USERDNSDOMAIN" -ForegroundColor Cyan
Write-Host "  Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Cyan
Write-Host ("=" * 70) -ForegroundColor Cyan

# -----------------------------------------------------------
# SECTION 1: All User Profiles + Roaming Profile Detection
# -----------------------------------------------------------
Write-Host "`n[SECTION 1] USER PROFILES & ROAMING STATUS" -ForegroundColor Yellow
Write-Host ("-" * 60)

$profileListReg = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\*" |
    Where-Object { $_.PSChildName -match '^S-1-5-21' }

foreach ($prof in $profileListReg) {
    $sid = $prof.PSChildName
    $profilePath = $prof.ProfileImagePath

    # Resolve username
    try {
        $objSID = New-Object System.Security.Principal.SecurityIdentifier($sid)
        $username = $objSID.Translate([System.Security.Principal.NTAccount]).Value
    } catch {
        $username = "Unknown (Orphaned)"
    }

    # Roaming profile detection
    $centralProfile = $prof.CentralProfile
    $roamingPath = $prof.CentralProfile
    $state = $prof.State
    # State flags: 0x01=local, 0x02=new local, 0x04=new central, 0x08=roaming update needed
    $isRoaming = if ($centralProfile -and $centralProfile -ne "") { $true } else { $false }

    # Profile type
    $profileType = if ($isRoaming) { "ROAMING" } else { "LOCAL" }
    $color = if ($isRoaming) { "Magenta" } else { "Green" }

    # Last use time
    $lastUsed = "N/A"
    if ($prof.LocalProfileLoadTimeLow -and $prof.LocalProfileLoadTimeHigh) {
        $ft = ([Int64]$prof.LocalProfileLoadTimeHigh -shl 32) -bor [UInt32]$prof.LocalProfileLoadTimeLow
        if ($ft -gt 0) { $lastUsed = [DateTime]::FromFileTime($ft).ToString("yyyy-MM-dd HH:mm:ss") }
    }

    Write-Host "`n  User:          $username" -ForegroundColor White
    Write-Host "  SID:           $sid"
    Write-Host "  Local Path:    $profilePath"
    Write-Host "  Profile Type:  $profileType" -ForegroundColor $color
    if ($isRoaming) {
        Write-Host "  Roaming Path:  $centralProfile" -ForegroundColor Magenta
    }
    Write-Host "  Last Used:     $lastUsed"
}

# -----------------------------------------------------------
# SECTION 2: Folder Redirection Detection (Per Profile)
# -----------------------------------------------------------
Write-Host "`n`n[SECTION 2] FOLDER REDIRECTION CHECK" -ForegroundColor Yellow
Write-Host ("-" * 60)
Write-Host "  Checking known shell folders for network redirection...`n"

# Known shell folder GUIDs in the registry
$knownFolders = @{
    "Desktop"       = "{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}"
    "Documents"     = "{FDD39AD0-238F-46AF-ADB4-6C85480369C7}"
    "Downloads"     = "{374DE290-123F-4565-9164-39C4925E467B}"
    "Music"         = "{4BD8D571-6D19-48D3-BE97-422220080E43}"
    "Pictures"      = "{33E28130-4E1E-4676-835A-98395C3BC3BB}"
    "Videos"        = "{18989B1D-99B5-455B-841C-AB7C74E4DDFC}"
    "Favorites"     = "{1777F761-68AD-4D8A-87BD-30B759FA33DD}"
    "AppData"       = "{3EB685DB-65F9-4CF6-A03A-E3EF65729F3D}"
}

# Also check via User Shell Folders registry per loaded profile
$userHives = Get-ChildItem "Registry::HKEY_USERS" -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -match 'S-1-5-21-[^_]+$' }

foreach ($hive in $userHives) {
    $sid = $hive.PSChildName
    
    # Resolve username
    try {
        $objSID = New-Object System.Security.Principal.SecurityIdentifier($sid)
        $username = $objSID.Translate([System.Security.Principal.NTAccount]).Value
    } catch {
        $username = "SID: $sid"
    }

    Write-Host "  [$username]" -ForegroundColor White

    $shellFolderPath = "Registry::HKEY_USERS\$sid\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"
    
    $redirectionFound = $false

    if (Test-Path $shellFolderPath) {
        $shellFolders = Get-ItemProperty -Path $shellFolderPath -ErrorAction SilentlyContinue

        $foldersToCheck = @(
            @{Name="Desktop";         Key="Desktop"},
            @{Name="Documents";       Key="Personal"},
            @{Name="Downloads";       Key="{374DE290-123F-4565-9164-39C4925E467B}"},
            @{Name="Music";           Key="My Music"},
            @{Name="Pictures";        Key="My Pictures"},
            @{Name="Videos";          Key="My Video"},
            @{Name="Favorites";       Key="Favorites"},
            @{Name="AppData Roaming"; Key="AppData"},
            @{Name="Start Menu";      Key="Start Menu"}
        )

        foreach ($folder in $foldersToCheck) {
            $value = $shellFolders.$($folder.Key)
            if ($value) {
                # Expand any environment variables for display
                $expanded = [Environment]::ExpandEnvironmentVariables($value)
                
                # Detect network paths (UNC or mapped drive pointing to network)
                $isNetwork = $false
                $location = "LOCAL"
                
                if ($value -like "\\*") {
                    $isNetwork = $true
                    $location = "NETWORK (UNC)"
                }
                elseif ($value -notlike "%USERPROFILE%*" -and $value -notlike "C:\*" -and $value -notlike "%SystemDrive%*") {
                    # Could be a mapped drive or unusual path
                    $isNetwork = $true
                    $location = "REDIRECTED (Non-Standard)"
                }

                if ($isNetwork) {
                    $redirectionFound = $true
                    Write-Host ("    {0,-20} -> {1}" -f $folder.Name, $value) -ForegroundColor Red
                    Write-Host ("    {0,-20}    Status: $location" -f "") -ForegroundColor Red
                } else {
                    Write-Host ("    {0,-20} -> {1}  [LOCAL]" -f $folder.Name, $value) -ForegroundColor Gray
                }
            }
        }
    } else {
        Write-Host "    Registry hive not loaded (user not logged in). See Section 2B." -ForegroundColor DarkYellow
    }

    if (-not $redirectionFound) {
        Write-Host "    ** No folder redirection detected - all folders appear LOCAL **" -ForegroundColor Green
    }
    Write-Host ""
}

# -----------------------------------------------------------
# SECTION 2B: Offline Profile Folder Redirection (Hive Load)
# -----------------------------------------------------------
Write-Host "`n[SECTION 2B] OFFLINE PROFILES - FOLDER REDIRECTION CHECK" -ForegroundColor Yellow
Write-Host ("-" * 60)
Write-Host "  Loading NTUSER.DAT for profiles not currently logged in...`n"

foreach ($prof in $profileListReg) {
    $sid = $prof.PSChildName
    $profilePath = $prof.ProfileImagePath

    # Skip if hive is already loaded (user logged in)
    if (Test-Path "Registry::HKEY_USERS\$sid\Software") { continue }

    try {
        $objSID = New-Object System.Security.Principal.SecurityIdentifier($sid)
        $username = $objSID.Translate([System.Security.Principal.NTAccount]).Value
    } catch {
        $username = "SID: $sid"
    }

    $ntUserDat = Join-Path $profilePath "NTUSER.DAT"
    if (-not (Test-Path $ntUserDat)) {
        Write-Host "  [$username] - NTUSER.DAT not found, skipping." -ForegroundColor DarkYellow
        continue
    }

    $tempKey = "HKU_TEMP_$($sid -replace '-','_')"

    try {
        # Load the hive
        $null = reg load "HKU\$tempKey" "$ntUserDat" 2>&1

        Write-Host "  [$username]" -ForegroundColor White

        $shellPath = "Registry::HKEY_USERS\$tempKey\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"

        if (Test-Path $shellPath) {
            $shellFolders = Get-ItemProperty -Path $shellPath -ErrorAction SilentlyContinue
            $redirectionFound = $false

            $foldersToCheck = @(
                @{Name="Desktop";    Key="Desktop"},
                @{Name="Documents";  Key="Personal"},
                @{Name="Downloads";  Key="{374DE290-123F-4565-9164-39C4925E467B}"},
                @{Name="Music";      Key="My Music"},
                @{Name="Pictures";   Key="My Pictures"},
                @{Name="Videos";     Key="My Video"},
                @{Name="Favorites";  Key="Favorites"},
                @{Name="AppData";    Key="AppData"}
            )

            foreach ($folder in $foldersToCheck) {
                $value = $shellFolders.$($folder.Key)
                if ($value) {
                    $isNetwork = $value -like "\\*" -or ($value -notlike "%USERPROFILE%*" -and $value -notlike "C:\*" -and $value -notlike "%SystemDrive%*")

                    if ($isNetwork) {
                        $redirectionFound = $true
                        Write-Host ("    {0,-20} -> {1}  [REDIRECTED]" -f $folder.Name, $value) -ForegroundColor Red
                    } else {
                        Write-Host ("    {0,-20} -> {1}  [LOCAL]" -f $folder.Name, $value) -ForegroundColor Gray
                    }
                }
            }

            if (-not $redirectionFound) {
                Write-Host "    ** All folders LOCAL **" -ForegroundColor Green
            }
        } else {
            Write-Host "    Shell folders registry key not found." -ForegroundColor DarkYellow
        }
    } catch {
        Write-Host "  [$username] Error loading hive: $_" -ForegroundColor Red
    } finally {
        # Unload the hive
        [GC]::Collect()
        Start-Sleep -Milliseconds 500
        $null = reg unload "HKU\$tempKey" 2>&1
    }
    Write-Host ""
}

# -----------------------------------------------------------
# SECTION 3: Local User Accounts
# -----------------------------------------------------------
Write-Host "`n[SECTION 3] LOCAL USER ACCOUNTS" -ForegroundColor Yellow
Write-Host ("-" * 60)

Get-LocalUser | Select-Object Name, Enabled,
    @{Name="LastLogon";Expression={if($_.LastLogon){$_.LastLogon.ToString("yyyy-MM-dd HH:mm:ss")}else{"Never"}}},
    @{Name="PasswordLastSet";Expression={if($_.PasswordLastSet){$_.PasswordLastSet.ToString("yyyy-MM-dd HH:mm:ss")}else{"N/A"}}},
    Description | Format-Table -AutoSize -Wrap

# -----------------------------------------------------------
# SECTION 4: Admin vs Standard Classification
# -----------------------------------------------------------
Write-Host "[SECTION 4] ACCESS LEVEL (Admin vs Standard)" -ForegroundColor Yellow
Write-Host ("-" * 60)

$adminMembers = @()
try {
    $adminMembers = (Get-LocalGroupMember -Group "Administrators" -ErrorAction Stop).Name
} catch {
    Write-Host "  Could not enumerate Administrators group: $_" -ForegroundColor Red
}

foreach ($user in Get-LocalUser) {
    $fullName = "$env:COMPUTERNAME\$($user.Name)"
    $isAdmin = $adminMembers | Where-Object { $_ -eq $fullName -or $_ -like "*\$($user.Name)" }
    $accessLevel = if ($isAdmin) { "ADMINISTRATOR" } else { "STANDARD USER" }
    $status = if ($user.Enabled) { "Enabled" } else { "Disabled" }
    $color = if ($isAdmin) { "Red" } else { "Green" }
    Write-Host ("  {0,-25} | {1,-15} | {2}" -f $user.Name, $accessLevel, $status) -ForegroundColor $color
}

# -----------------------------------------------------------
# SECTION 5: Group Memberships Per User
# -----------------------------------------------------------
Write-Host "`n`n[SECTION 5] LOCAL GROUP MEMBERSHIPS" -ForegroundColor Yellow
Write-Host ("-" * 60)

foreach ($user in Get-LocalUser) {
    $groups = @()
    foreach ($group in Get-LocalGroup) {
        try {
            $members = Get-LocalGroupMember -Group $group.Name -ErrorAction SilentlyContinue
            if ($members.Name -like "*\$($user.Name)") { $groups += $group.Name }
        } catch { }
    }
    $groupList = if ($groups.Count -gt 0) { $groups -join ", " } else { "None" }
    Write-Host ("  {0,-25} -> {1}" -f $user.Name, $groupList)
}

# -----------------------------------------------------------
# SECTION 6: Non-Local Accounts with Admin Access
# -----------------------------------------------------------
Write-Host "`n`n[SECTION 6] DOMAIN/AZURE AD ACCOUNTS IN ADMIN GROUP" -ForegroundColor Yellow
Write-Host ("-" * 60)

try {
    $allAdmins = Get-LocalGroupMember -Group "Administrators" -ErrorAction Stop
    $nonLocal = $allAdmins | Where-Object { $_.PrincipalSource -ne "Local" }
    if ($nonLocal) {
        foreach ($m in $nonLocal) {
            Write-Host ("  {0,-40} | Type: {1} | Source: {2}" -f $m.Name, $m.ObjectClass, $m.PrincipalSource)
        }
    } else {
        Write-Host "  No domain/AzureAD accounts in Administrators group." -ForegroundColor Gray
    }
} catch {
    Write-Host "  Could not query: $_" -ForegroundColor Red
}

# -----------------------------------------------------------
# SECTION 7: GPO Folder Redirection Policy Check
# -----------------------------------------------------------
Write-Host "`n`n[SECTION 7] GROUP POLICY - FOLDER REDIRECTION SETTINGS" -ForegroundColor Yellow
Write-Host ("-" * 60)
Write-Host "  Checking if folder redirection GPO is applied...`n"

$gpRedirectionPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
$frEnabled = $false

# Check common GPO indicators for folder redirection
$policiesToCheck = @(
    "HKCU:\Software\Policies\Microsoft\Windows\Explorer",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
)

# Check machine-level GP result
try {
    $gpResult = gpresult /Scope Computer /v 2>&1 | Select-String -Pattern "Folder Redirection|FolderRedirection" -SimpleMatch
    if ($gpResult) {
        Write-Host "  GPO Folder Redirection detected in gpresult:" -ForegroundColor Red
        $gpResult | ForEach-Object { Write-Host "    $_" -ForegroundColor Red }
        $frEnabled = $true
    }
} catch { }

# Check user-level GP result
try {
    $gpResultUser = gpresult /Scope User /v 2>&1 | Select-String -Pattern "Folder Redirection|FolderRedirection" -SimpleMatch
    if ($gpResultUser) {
        Write-Host "  GPO Folder Redirection (User scope) detected:" -ForegroundColor Red
        $gpResultUser | ForEach-Object { Write-Host "    $_" -ForegroundColor Red }
        $frEnabled = $true
    }
} catch { }

if (-not $frEnabled) {
    Write-Host "  No Folder Redirection GPO detected via gpresult." -ForegroundColor Green
}

# Check for offline files / CSC (Client-Side Caching) which often accompanies redirection
$cscPath = "HKLM:\SYSTEM\CurrentControlSet\Services\CSC\Parameters"
if (Test-Path $cscPath) {
    Write-Host "`n  Offline Files (CSC) service parameters found - may indicate folder sync." -ForegroundColor Yellow
} else {
    Write-Host "`n  No Offline Files (CSC) configuration found." -ForegroundColor Gray
}

# -----------------------------------------------------------
# SUMMARY
# -----------------------------------------------------------
Write-Host "`n" + ("=" * 70) -ForegroundColor Cyan
Write-Host "  SCAN COMPLETE" -ForegroundColor Cyan
Write-Host "  Total profiles: $($profileListReg.Count)" -ForegroundColor Cyan
Write-Host "  Total local accounts: $((Get-LocalUser).Count)" -ForegroundColor Cyan
Write-Host ("=" * 70) -ForegroundColor Cyan
Write-Host "`n  TIP: Run as Administrator for full results." -ForegroundColor DarkYellow
Write-Host "  TIP: Pipe to file: .\script.ps1 | Tee-Object -FilePath C:\Temp\ProfileReport.txt`n" -ForegroundColor DarkYellow
