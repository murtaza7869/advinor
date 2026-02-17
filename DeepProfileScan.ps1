# ============================================================
# Folder Redirection & Network Profile Mapping - Deep Audit
# Checks GPO, Registry, Scripts, Scheduled Tasks, Drive Maps
# ============================================================

$ErrorActionPreference = "SilentlyContinue"

Write-Host ("=" * 70) -ForegroundColor Cyan
Write-Host "  FOLDER REDIRECTION & NETWORK MAPPING - DEEP AUDIT" -ForegroundColor Cyan
Write-Host "  Computer: $env:COMPUTERNAME | Domain: $env:USERDNSDOMAIN" -ForegroundColor Cyan
Write-Host "  Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Cyan
Write-Host ("=" * 70) -ForegroundColor Cyan

# -----------------------------------------------------------
# 1. GPO - Resultant Set of Policy (RSoP) Full Dump
# -----------------------------------------------------------
Write-Host "`n[1] GROUP POLICY - FULL RSoP ANALYSIS" -ForegroundColor Yellow
Write-Host ("-" * 60)

# Generate GP Report as XML for parsing
$gpReportPath = "$env:TEMP\GPReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').xml"
$gpReportHTML = "$env:TEMP\GPReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"

Write-Host "  Generating GP report (XML + HTML)..."
gpresult /X "$gpReportPath" /F 2>&1 | Out-Null
gpresult /H "$gpReportHTML" /F 2>&1 | Out-Null

if (Test-Path $gpReportPath) {
    [xml]$gpXml = Get-Content $gpReportPath
    
    Write-Host "`n  [1A] Applied GPOs:" -ForegroundColor White
    
    # Computer GPOs
    $computerGPOs = $gpXml.Rsop.ComputerResults.GPO
    if ($computerGPOs) {
        Write-Host "  --- Computer-Scope GPOs ---" -ForegroundColor Gray
        foreach ($gpo in $computerGPOs) {
            $gpoName = $gpo.Name
            $gpoEnabled = $gpo.Enabled
            $gpoLink = $gpo.Link.SOMPath
            Write-Host ("    {0,-40} | Enabled: {1} | Link: {2}" -f $gpoName, $gpoEnabled, $gpoLink)
        }
    }
    
    # User GPOs
    $userGPOs = $gpXml.Rsop.UserResults.GPO
    if ($userGPOs) {
        Write-Host "`n  --- User-Scope GPOs ---" -ForegroundColor Gray
        foreach ($gpo in $userGPOs) {
            $gpoName = $gpo.Name
            $gpoEnabled = $gpo.Enabled
            $gpoLink = $gpo.Link.SOMPath
            $color = "White"
            # Highlight anything suspicious
            if ($gpoName -match "redirect|folder|profile|map|drive|home|network|share") {
                $color = "Red"
            }
            Write-Host ("    {0,-40} | Enabled: {1} | Link: {2}" -f $gpoName, $gpoEnabled, $gpoLink) -ForegroundColor $color
        }
    }

    # Search entire XML for folder redirection references
    Write-Host "`n  [1B] Searching GP report for redirection/mapping keywords..." -ForegroundColor White
    $gpContent = Get-Content $gpReportPath -Raw
    $keywords = @("FolderRedirection", "Redirect", "\\\\192.168", "\\\\server", "NetDrive", "HomeDrive", "HomeDirectory", "LogonScript", "MapDrive")
    foreach ($kw in $keywords) {
        if ($gpContent -match $kw) {
            Write-Host "    FOUND keyword: '$kw' in GP report!" -ForegroundColor Red
        }
    }
    
    Write-Host "`n  HTML report saved: $gpReportHTML" -ForegroundColor DarkYellow
    Write-Host "  XML report saved: $gpReportPath" -ForegroundColor DarkYellow
} else {
    Write-Host "  Failed to generate GP report. Run as admin." -ForegroundColor Red
}

# -----------------------------------------------------------
# 2. Registry - Direct Folder Redirection Keys
# -----------------------------------------------------------
Write-Host "`n`n[2] REGISTRY - FOLDER REDIRECTION ENTRIES" -ForegroundColor Yellow
Write-Host ("-" * 60)

$userHives = Get-ChildItem "Registry::HKEY_USERS" |
    Where-Object { $_.Name -match 'S-1-5-21-[^_]+$' }

foreach ($hive in $userHives) {
    $sid = $hive.PSChildName
    try {
        $objSID = New-Object System.Security.Principal.SecurityIdentifier($sid)
        $username = $objSID.Translate([System.Security.Principal.NTAccount]).Value
    } catch { $username = "SID: $sid" }

    Write-Host "`n  [$username]" -ForegroundColor White

    # Check User Shell Folders
    $shellPath = "Registry::HKEY_USERS\$sid\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"
    if (Test-Path $shellPath) {
        $shellFolders = Get-ItemProperty -Path $shellPath
        $props = $shellFolders.PSObject.Properties | Where-Object { $_.Value -like "\\*" }
        if ($props) {
            Write-Host "    Network-redirected shell folders:" -ForegroundColor Red
            foreach ($p in $props) {
                Write-Host ("      {0,-30} -> {1}" -f $p.Name, $p.Value) -ForegroundColor Red
            }
        } else {
            Write-Host "    No UNC paths in User Shell Folders." -ForegroundColor Green
        }
    }

    # Check for GP-enforced folder redirection policy keys
    $policyPaths = @(
        "Registry::HKEY_USERS\$sid\Software\Policies\Microsoft\Windows\Explorer",
        "Registry::HKEY_USERS\$sid\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer",
        "Registry::HKEY_USERS\$sid\Software\Policies\Microsoft\Windows\System"
    )
    foreach ($polPath in $policyPaths) {
        if (Test-Path $polPath) {
            $polProps = Get-ItemProperty -Path $polPath
            Write-Host "    Policy key found: $polPath" -ForegroundColor Yellow
            $polProps.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object {
                Write-Host ("      {0} = {1}" -f $_.Name, $_.Value)
            }
        }
    }

    # Check for Folder Redirection GP extension data
    $frGPExtPath = "Registry::HKEY_USERS\$sid\Software\Microsoft\Windows\CurrentVersion\Group Policy\History\{25537BA6-77A8-11D2-9B6C-0000F8080861}"
    if (Test-Path $frGPExtPath) {
        Write-Host "    ** GP Folder Redirection CSE history FOUND **" -ForegroundColor Red
        $frHistory = Get-ItemProperty -Path $frGPExtPath
        $frHistory.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object {
            Write-Host ("      {0} = {1}" -f $_.Name, $_.Value) -ForegroundColor Red
        }
        # Check sub-keys (per-folder GP settings)
        Get-ChildItem $frGPExtPath -ErrorAction SilentlyContinue | ForEach-Object {
            Write-Host "      Sub-key: $($_.PSChildName)" -ForegroundColor Red
            Get-ItemProperty $_.PSPath | Select-Object * -ExcludeProperty PS* | ForEach-Object {
                $_.PSObject.Properties | ForEach-Object {
                    Write-Host ("        {0} = {1}" -f $_.Name, $_.Value) -ForegroundColor Red
                }
            }
        }
    }
}

# -----------------------------------------------------------
# 3. AD User Object - Home Drive & Home Directory
# -----------------------------------------------------------
Write-Host "`n`n[3] ACTIVE DIRECTORY - HOME FOLDER & PROFILE PATH" -ForegroundColor Yellow
Write-Host ("-" * 60)

try {
    $searcher = New-Object System.DirectoryServices.DirectorySearcher
    $searcher.Filter = "(&(objectCategory=person)(objectClass=user))"
    $searcher.PropertiesToLoad.AddRange(@("samaccountname","homedirectory","homedrive","profilepath","scriptpath"))
    $searcher.PageSize = 1000
    
    $results = $searcher.FindAll()
    
    $usersWithNetPaths = @()
    
    foreach ($result in $results) {
        $props = $result.Properties
        $samName = ($props["samaccountname"] | Select-Object -First 1)
        $homeDir = ($props["homedirectory"] | Select-Object -First 1)
        $homeDrive = ($props["homedrive"] | Select-Object -First 1)
        $profilePath = ($props["profilepath"] | Select-Object -First 1)
        $scriptPath = ($props["scriptpath"] | Select-Object -First 1)
        
        if ($homeDir -or $profilePath -or $scriptPath) {
            $usersWithNetPaths += [PSCustomObject]@{
                Username    = $samName
                HomeDrive   = if($homeDrive){"$homeDrive"}else{"N/A"}
                HomeDir     = if($homeDir){"$homeDir"}else{"N/A"}
                ProfilePath = if($profilePath){"$profilePath"}else{"N/A"}
                LogonScript = if($scriptPath){"$scriptPath"}else{"N/A"}
            }
        }
    }
    
    if ($usersWithNetPaths) {
        Write-Host "  Users with network home folders, roaming profiles, or logon scripts:`n" -ForegroundColor Red
        $usersWithNetPaths | Format-Table -AutoSize -Wrap
    } else {
        Write-Host "  No AD users have Home Directory, Profile Path, or Logon Script set." -ForegroundColor Green
    }
    
    $results.Dispose()
} catch {
    Write-Host "  Could not query AD: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "  (Run on a domain-joined machine with AD access)" -ForegroundColor DarkYellow
}

# -----------------------------------------------------------
# 4. Logon Scripts (GPO & AD)
# -----------------------------------------------------------
Write-Host "`n[4] LOGON SCRIPTS CHECK" -ForegroundColor Yellow
Write-Host ("-" * 60)

# Check NETLOGON share for scripts
$netlogonPath = "\\$env:USERDNSDOMAIN\NETLOGON"
Write-Host "  Checking NETLOGON share: $netlogonPath"

if (Test-Path $netlogonPath) {
    $scripts = Get-ChildItem $netlogonPath -Recurse -Include *.bat,*.cmd,*.ps1,*.vbs,*.js -ErrorAction SilentlyContinue
    if ($scripts) {
        Write-Host "  Scripts found in NETLOGON:" -ForegroundColor Yellow
        foreach ($script in $scripts) {
            Write-Host "    $($script.FullName)" -ForegroundColor Yellow
            
            # Search script content for drive mapping or redirection
            $content = Get-Content $script.FullName -Raw -ErrorAction SilentlyContinue
            if ($content) {
                $mappingPatterns = @("net use", "New-PSDrive", "MapNetworkDrive", "\\\\192.168", "subst ", "mklink", "New-SmbMapping")
                foreach ($pattern in $mappingPatterns) {
                    $matches = $content | Select-String -Pattern $pattern -AllMatches
                    if ($matches) {
                        Write-Host "      ** Contains '$pattern' **" -ForegroundColor Red
                        $matches.Matches | ForEach-Object {
                            $lineNum = ($content.Substring(0, $_.Index) -split "`n").Count
                            $line = ($content -split "`n")[$lineNum - 1].Trim()
                            Write-Host "         Line $lineNum`: $line" -ForegroundColor Red
                        }
                    }
                }
                
                # Also check for folder redirection via mklink/junction
                if ($content -match "mklink|junction|symlink") {
                    Write-Host "      ** Contains symbolic link/junction commands - possible folder redirection **" -ForegroundColor Red
                }
            }
        }
    } else {
        Write-Host "  No scripts found in NETLOGON." -ForegroundColor Green
    }
} else {
    Write-Host "  Cannot access NETLOGON share." -ForegroundColor DarkYellow
}

# Check GP logon script registry entries
Write-Host "`n  Checking GP-assigned logon scripts in registry..."
foreach ($hive in $userHives) {
    $sid = $hive.PSChildName
    try {
        $objSID = New-Object System.Security.Principal.SecurityIdentifier($sid)
        $username = $objSID.Translate([System.Security.Principal.NTAccount]).Value
    } catch { $username = "SID: $sid" }

    $scriptPaths = @(
        "Registry::HKEY_USERS\$sid\Software\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Logon",
        "Registry::HKEY_USERS\$sid\Software\Policies\Microsoft\Windows\System\Scripts\Logon"
    )
    
    foreach ($sp in $scriptPaths) {
        if (Test-Path $sp) {
            Write-Host "  [$username] GP Logon scripts found:" -ForegroundColor Yellow
            Get-ChildItem $sp -Recurse | ForEach-Object {
                $scriptProps = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
                if ($scriptProps.Script) {
                    Write-Host "    Script: $($scriptProps.Script)" -ForegroundColor Yellow
                    Write-Host "    Params: $($scriptProps.Parameters)" -ForegroundColor Yellow
                }
            }
        }
    }
}

# -----------------------------------------------------------
# 5. Scheduled Tasks That Map Drives or Redirect
# -----------------------------------------------------------
Write-Host "`n`n[5] SCHEDULED TASKS - DRIVE MAPPING / REDIRECTION" -ForegroundColor Yellow
Write-Host ("-" * 60)

$tasks = Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.State -ne "Disabled" }
$suspiciousTasks = @()

foreach ($task in $tasks) {
    $actions = $task.Actions
    foreach ($action in $actions) {
        $cmdLine = "$($action.Execute) $($action.Arguments)"
        if ($cmdLine -match "net use|New-PSDrive|MapNetworkDrive|\\\\|subst|mklink|New-SmbMapping") {
            $suspiciousTasks += [PSCustomObject]@{
                TaskName = $task.TaskName
                TaskPath = $task.TaskPath
                Command  = $cmdLine.Trim()
                Trigger  = ($task.Triggers | ForEach-Object { $_.CimClass.CimClassName }) -join ", "
            }
        }
    }
}

if ($suspiciousTasks) {
    Write-Host "  Scheduled tasks with drive/network mapping commands:" -ForegroundColor Red
    $suspiciousTasks | Format-Table -AutoSize -Wrap
} else {
    Write-Host "  No scheduled tasks found with drive mapping commands." -ForegroundColor Green
}

# -----------------------------------------------------------
# 6. Mapped Network Drives (Current Session)
# -----------------------------------------------------------
Write-Host "`n[6] CURRENTLY MAPPED NETWORK DRIVES" -ForegroundColor Yellow
Write-Host ("-" * 60)

$netDrives = Get-PSDrive -PSProvider FileSystem | Where-Object { $_.DisplayRoot -like "\\*" }
if ($netDrives) {
    foreach ($drive in $netDrives) {
        Write-Host ("  {0}: -> {1}" -f $drive.Name, $drive.DisplayRoot) -ForegroundColor Yellow
    }
} else {
    Write-Host "  No mapped network drives in current session." -ForegroundColor Gray
}

# Also check via WMI for persistent mappings
Write-Host "`n  Persistent network connections (net use):"
$netUse = net use 2>&1
$netUse | ForEach-Object {
    if ($_ -match "\\\\") {
        Write-Host "  $_" -ForegroundColor Yellow
    }
}

# -----------------------------------------------------------
# 7. Symbolic Links / Junctions in User Profiles
# -----------------------------------------------------------
Write-Host "`n`n[7] SYMBOLIC LINKS & JUNCTIONS IN USER PROFILES" -ForegroundColor Yellow
Write-Host ("-" * 60)

$profilesDir = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList").ProfilesDirectory
$userFolders = Get-ChildItem $profilesDir -Directory -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -notin @("Public","Default","Default User") }

foreach ($uf in $userFolders) {
    Write-Host "`n  [$($uf.Name)]" -ForegroundColor White
    $foldersToCheck = @("Desktop","Documents","Downloads","Music","Pictures","Videos","Favorites","AppData")
    $junctionFound = $false
    
    foreach ($folder in $foldersToCheck) {
        $fullPath = Join-Path $uf.FullName $folder
        if (Test-Path $fullPath) {
            $item = Get-Item $fullPath -Force -ErrorAction SilentlyContinue
            if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
                $target = (Get-Item $fullPath -Force).Target
                Write-Host ("    {0,-15} -> JUNCTION/SYMLINK -> {1}" -f $folder, $target) -ForegroundColor Red
                $junctionFound = $true
            }
        }
    }
    if (-not $junctionFound) {
        Write-Host "    No junctions or symlinks detected." -ForegroundColor Green
    }
}

# -----------------------------------------------------------
# 8. The Specific Server Share Check
# -----------------------------------------------------------
Write-Host "`n`n[8] TARGET SERVER SHARE ANALYSIS (\\192.168.0.200)" -ForegroundColor Yellow
Write-Host ("-" * 60)

$targetServer = "192.168.0.200"
Write-Host "  Checking connectivity to $targetServer..."

if (Test-Connection $targetServer -Count 1 -Quiet) {
    Write-Host "  Server is REACHABLE." -ForegroundColor Green
    
    # List shares
    try {
        $shares = net view "\\$targetServer" 2>&1
        Write-Host "`n  Available shares on \\${targetServer}:" -ForegroundColor White
        $shares | ForEach-Object { Write-Host "    $_" }
    } catch {
        Write-Host "  Could not enumerate shares." -ForegroundColor DarkYellow
    }
    
    # Check if user-named folders exist
    Write-Host "`n  Checking for user-named folders on share..."
    $profileListReg2 = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\*" |
        Where-Object { $_.PSChildName -match '^S-1-5-21' }
    
    foreach ($prof in $profileListReg2) {
        try {
            $objSID = New-Object System.Security.Principal.SecurityIdentifier($prof.PSChildName)
            $username = ($objSID.Translate([System.Security.Principal.NTAccount]).Value -split '\\')[-1]
        } catch { continue }
        
        $sharePath = "\\$targetServer\$username"
        if (Test-Path $sharePath -ErrorAction SilentlyContinue) {
            Write-Host "    FOUND: $sharePath" -ForegroundColor Red
            $subFolders = Get-ChildItem $sharePath -Directory -ErrorAction SilentlyContinue
            if ($subFolders) {
                $subFolders | ForEach-Object {
                    Write-Host "      |- $($_.Name)" -ForegroundColor Yellow
                }
            }
        }
    }
} else {
    Write-Host "  Server $targetServer is NOT reachable." -ForegroundColor Red
}

# -----------------------------------------------------------
# SUMMARY
# -----------------------------------------------------------
Write-Host "`n" + ("=" * 70) -ForegroundColor Cyan
Write-Host "  AUDIT COMPLETE" -ForegroundColor Cyan
Write-Host "  GP HTML Report: $gpReportHTML" -ForegroundColor Cyan
Write-Host "  Open the HTML report in a browser for full GP details." -ForegroundColor Cyan
Write-Host ("=" * 70) -ForegroundColor Cyan
Write-Host @"

  WHAT TO LOOK FOR:
  -------------------------------------------------
  - Section 3: AD user Home Directory is the most common
    way admins set up per-user network folders
  - Section 4: Logon scripts with 'net use' commands
    that map drives or create folder redirections  
  - Section 2: Registry UNC paths = active redirection
  - Section 7: Junctions/symlinks = sneaky local-to-
    network redirection without changing shell folders

  If Section 3 shows HomeDirectory = \\192.168.0.200\%username%
  that's your answer - the previous admin set it in AD user
  properties, not via GPO (which is why gpresult showed nothing).
"@ -ForegroundColor DarkYellow
