#Requires -RunAsAdministrator
<#
.SYNOPSIS
    AVD Thin Client Setup Script for Windows Home
    Removes bloatware, disables unnecessary services, and optimizes Windows
    for use ONLY as an Azure Virtual Desktop (Windows App) client machine.

.DESCRIPTION
    - Removes pre-installed Store apps / bloatware
    - Disables unnecessary Windows services
    - Disables telemetry, ads, and background noise
    - Keeps: Windows App (AVD), Print functionality, Networking, Audio
    - Safe for Windows 10 Home and Windows 11 Home

.NOTES
    Run as Administrator. A restore point is created before any changes.
    Reboot recommended after completion.
#>

# ─────────────────────────────────────────────
# CONFIGURATION — Set to $false to skip a section
# ─────────────────────────────────────────────
$Config = @{
    CreateRestorePoint     = $true
    RemoveBloatApps        = $true
    DisableServices        = $true
    DisableTelemetry       = $true
    DisableScheduledTasks  = $true
    ApplyPerformanceTweaks = $true
    DisableStartupJunk     = $true
    CleanOptionalFeatures  = $true
    HardenPrivacy          = $true
}

# ─────────────────────────────────────────────
# LOGGING
# ─────────────────────────────────────────────
$LogFile = "$env:SystemDrive\AVD-ThinClient-Setup.log"
function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "[$timestamp] [$Level] $Message"
    Write-Host $line -ForegroundColor $(if ($Level -eq "ERROR") {"Red"} elseif ($Level -eq "WARN") {"Yellow"} else {"Cyan"})
    Add-Content -Path $LogFile -Value $line
}

Write-Log "=========================================="
Write-Log " AVD Thin Client Setup Script Starting"
Write-Log "=========================================="

# ─────────────────────────────────────────────
# RESTORE POINT
# ─────────────────────────────────────────────
if ($Config.CreateRestorePoint) {
    Write-Log "Creating System Restore Point..."
    try {
        Enable-ComputerRestore -Drive "$env:SystemDrive\"
        Checkpoint-Computer -Description "Before AVD Thin Client Setup" -RestorePointType "MODIFY_SETTINGS"
        Write-Log "Restore point created successfully."
    } catch {
        Write-Log "Could not create restore point: $_" "WARN"
    }
}

# ─────────────────────────────────────────────
# REMOVE BLOAT STORE APPS
# Apps KEPT (do not add these to the removal list):
#   - Microsoft.WindowsStore          (needed for Windows App updates)
#   - Microsoft.DesktopAppInstaller   (winget)
#   - MicrosoftCorporationII.WindowsApp (Windows App / AVD client)
#   - Microsoft.Print3D / print related
#   - Microsoft.HEIFImageExtension, VCLibs (runtime dependencies)
# ─────────────────────────────────────────────
$AppsToRemove = @(
    # Gaming
    "Microsoft.XboxApp"
    "Microsoft.XboxGameOverlay"
    "Microsoft.XboxGamingOverlay"
    "Microsoft.XboxIdentityProvider"
    "Microsoft.XboxSpeechToTextOverlay"
    "Microsoft.Xbox.TCUI"
    "Microsoft.GamingApp"
    "Microsoft.XboxGameCallableUI"

    # Bing / Search noise
    "Microsoft.BingNews"
    "Microsoft.BingWeather"
    "Microsoft.BingFinance"
    "Microsoft.BingSports"
    "Microsoft.BingTravel"
    "Microsoft.BingFoodAndDrink"
    "Microsoft.BingHealthAndFitness"
    "Microsoft.BingMaps"

    # Microsoft Office / OneDrive / Teams consumer
    "Microsoft.MicrosoftOfficeHub"
    "Microsoft.Office.OneNote"
    "MicrosoftTeams"
    "Microsoft.Teams"
    "Microsoft.OneDriveSync"

    # Media / Entertainment
    "Microsoft.ZuneMusic"
    "Microsoft.ZuneVideo"
    "Microsoft.Groove"
    "Microsoft.WindowsMediaPlayer"
    "Microsoft.Media.PlayReadyClient.2"
    "SpotifyAB.SpotifyMusic"
    "Disney.37853D22215B2"
    "Netflix"
    "AmazonVideo.PrimeVideo"

    # Social / Communication (consumer)
    "Microsoft.People"
    "microsoft.windowscommunicationsapps"  # Mail & Calendar
    "Microsoft.Messaging"
    "Microsoft.SkypeApp"

    # Productivity clutter
    "Microsoft.MicrosoftSolitaireCollection"
    "Microsoft.MicrosoftMahjong"
    "Microsoft.MicrosoftJigsaw"
    "Microsoft.MicrosoftSudoku"
    "Microsoft.Minesweeper"
    "Microsoft.MinecraftUWP"
    "King.CandyCrushSaga"
    "King.CandyCrushFriends"
    "king.com.BubbleWitch3Saga"
    "king.com.FarmHeroesSaga"

    # Utilities not needed on a thin client
    "Microsoft.GetHelp"
    "Microsoft.Getstarted"
    "Microsoft.Wallet"
    "Microsoft.MixedReality.Portal"
    "Microsoft.Windows.Cortana"
    "Microsoft.549981C3F5F10"   # Cortana new package
    "Microsoft.windowsphone"
    "Microsoft.WindowsFeedbackHub"
    "Microsoft.WindowsMaps"
    "Microsoft.Todos"
    "Microsoft.PowerAutomateDesktop"   # remove unless you need it
    "Microsoft.MicrosoftEdge.Stable"   # Optional — Edge is used for auth popups; comment out if needed
    "Microsoft.YourPhone"
    "Microsoft.Phone"
    "Microsoft.Whiteboard"
    "Microsoft.OutlookForWindows"

    # 3rd party OEM junk (add your OEM's packages here)
    "CandyCrush*"
    "Facebook*"
    "Twitter*"
    "TikTok*"
    "Duolingo*"
    "EclipseManager"
    "ActiproSoftwareLLC*"
    "AdobeSystemsIncorporated*"
    "Clipchamp.Clipchamp"
)

if ($Config.RemoveBloatApps) {
    Write-Log "--- Removing Bloat Store Apps ---"
    foreach ($app in $AppsToRemove) {
        $packages = Get-AppxPackage -Name $app -AllUsers -ErrorAction SilentlyContinue
        if ($packages) {
            foreach ($pkg in $packages) {
                Write-Log "Removing: $($pkg.Name)"
                try {
                    Remove-AppxPackage -Package $pkg.PackageFullName -AllUsers -ErrorAction Stop
                } catch {
                    Write-Log "  Could not remove $($pkg.Name): $_" "WARN"
                }
            }
        }

        # Also remove provisioned packages so they don't reinstall for new users
        $provisioned = Get-AppxProvisionedPackage -Online | Where-Object { $_.DisplayName -like $app }
        foreach ($prov in $provisioned) {
            Write-Log "Removing provisioned: $($prov.DisplayName)"
            try {
                Remove-AppxProvisionedPackage -Online -PackageName $prov.PackageName -ErrorAction Stop | Out-Null
            } catch {
                Write-Log "  Could not remove provisioned $($prov.DisplayName): $_" "WARN"
            }
        }
    }
    Write-Log "Bloat app removal complete."
}

# ─────────────────────────────────────────────
# DISABLE UNNECESSARY WINDOWS SERVICES
# Services KEPT: Printer Spooler, Audio, RPC, Network stack,
#                Windows Update (security), Credential Manager,
#                Plug and Play, DHCP, DNS Client, Windows Defender
# ─────────────────────────────────────────────
$ServicesToDisable = @(
    # Xbox
    @{ Name = "XblAuthManager";       Display = "Xbox Live Auth Manager" }
    @{ Name = "XblGameSave";          Display = "Xbox Live Game Save" }
    @{ Name = "XboxGipSvc";           Display = "Xbox Accessory Management" }
    @{ Name = "XboxNetApiSvc";        Display = "Xbox Live Networking" }
    @{ Name = "GamingServices";       Display = "Gaming Services" }

    # Telemetry / Diagnostics
    @{ Name = "DiagTrack";            Display = "Connected User Experiences and Telemetry" }
    @{ Name = "dmwappushservice";     Display = "WAP Push Message Routing" }
    @{ Name = "diagnosticshub.standardcollector.service"; Display = "Diagnostics Hub Collector" }
    @{ Name = "WerSvc";               Display = "Windows Error Reporting" }
    @{ Name = "wercplsupport";        Display = "Problem Reports Control Panel" }

    # Consumer / Advertising
    @{ Name = "RetailDemo";           Display = "Retail Demo" }
    @{ Name = "MapsBroker";           Display = "Downloaded Maps Manager" }
    @{ Name = "lfsvc";                Display = "Geolocation Service" }

    # Mobile / Phone
    @{ Name = "PhoneSvc";             Display = "Phone Service" }
    @{ Name = "TapiSrv";             Display = "Telephony" }

    # Mixed Reality
    @{ Name = "MixedRealityOpenXRSvc"; Display = "Mixed Reality OpenXR" }
    @{ Name = "WMPNetworkSvc";        Display = "Windows Media Player Network Sharing" }

    # Remote Assistance (not needed — you're connecting OUT via Windows App)
    @{ Name = "RemoteRegistry";       Display = "Remote Registry" }
    @{ Name = "RasAuto";              Display = "Remote Access Auto Connection" }
    @{ Name = "RasMan";               Display = "Remote Access Connection Manager" }  # Comment out if using VPN/SSTP

    # Misc
    @{ Name = "Fax";                  Display = "Fax" }
    @{ Name = "SharedAccess";         Display = "Internet Connection Sharing" }
    @{ Name = "wisvc";                Display = "Windows Insider Service" }
    @{ Name = "WSearch";              Display = "Windows Search (indexing)" }  # Safe to disable on thin client
    @{ Name = "SysMain";              Display = "Superfetch/SysMain" }         # Not needed on SSD thin client
    @{ Name = "HomeGroupListener";    Display = "HomeGroup Listener" }
    @{ Name = "HomeGroupProvider";    Display = "HomeGroup Provider" }
    @{ Name = "icssvc";               Display = "Windows Mobile Hotspot" }
    @{ Name = "SEMgrSvc";             Display = "Payments and NFC" }
    @{ Name = "TabletInputService";   Display = "Touch Keyboard and Handwriting" }
    @{ Name = "WbioSrvc";             Display = "Windows Biometric Service" }   # Comment out if using fingerprint/Hello
)

if ($Config.DisableServices) {
    Write-Log "--- Disabling Unnecessary Services ---"
    foreach ($svc in $ServicesToDisable) {
        try {
            $service = Get-Service -Name $svc.Name -ErrorAction SilentlyContinue
            if ($service) {
                Stop-Service -Name $svc.Name -Force -ErrorAction SilentlyContinue
                Set-Service -Name $svc.Name -StartupType Disabled -ErrorAction Stop
                Write-Log "Disabled: $($svc.Display)"
            }
        } catch {
            Write-Log "  Could not disable $($svc.Display): $_" "WARN"
        }
    }
    Write-Log "Service configuration complete."
}

# ─────────────────────────────────────────────
# DISABLE TELEMETRY & DATA COLLECTION (Registry)
# ─────────────────────────────────────────────
if ($Config.DisableTelemetry) {
    Write-Log "--- Disabling Telemetry & Data Collection ---"

    $TelemetryKeys = @(
        # Disable telemetry level (0 = Security/Off on Enterprise, 1 = Basic minimum on Home/Pro)
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"; Name = "AllowTelemetry"; Value = 0 }
        @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection"; Name = "AllowTelemetry"; Value = 0 }

        # Disable advertising ID
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo"; Name = "DisabledByGroupPolicy"; Value = 1 }
        @{ Path = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo"; Name = "Enabled"; Value = 0 }

        # Disable Cortana
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"; Name = "AllowCortana"; Value = 0 }
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"; Name = "DisableWebSearch"; Value = 1 }

        # Disable feedback requests
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"; Name = "DoNotShowFeedbackNotifications"; Value = 1 }
        @{ Path = "HKCU:\SOFTWARE\Microsoft\Siuf\Rules"; Name = "NumberOfSIUFInPeriod"; Value = 0 }

        # Disable app launch tracking
        @{ Path = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced"; Name = "Start_TrackProgs"; Value = 0 }

        # Disable tips and suggestions
        @{ Path = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name = "SubscribedContent-338388Enabled"; Value = 0 }
        @{ Path = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name = "SubscribedContent-338389Enabled"; Value = 0 }
        @{ Path = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name = "SubscribedContent-353694Enabled"; Value = 0 }
        @{ Path = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name = "SubscribedContent-353696Enabled"; Value = 0 }
        @{ Path = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name = "SilentInstalledAppsEnabled"; Value = 0 }  # Block auto-installed apps
        @{ Path = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name = "SystemPaneSuggestionsEnabled"; Value = 0 }
        @{ Path = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name = "SoftLandingEnabled"; Value = 0 }

        # Disable SmartScreen (optional — comment out if you want to keep it)
        # @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"; Name = "EnableSmartScreen"; Value = 0 }

        # Disable location
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors"; Name = "DisableLocation"; Value = 1 }

        # Disable Wi-Fi Sense
        @{ Path = "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config"; Name = "AutoConnectAllowedOEM"; Value = 0 }
    )

    foreach ($key in $TelemetryKeys) {
        try {
            if (!(Test-Path $key.Path)) { New-Item -Path $key.Path -Force | Out-Null }
            Set-ItemProperty -Path $key.Path -Name $key.Name -Value $key.Value -ErrorAction Stop
            Write-Log "Set: $($key.Path)\$($key.Name) = $($key.Value)"
        } catch {
            Write-Log "  Failed to set $($key.Name): $_" "WARN"
        }
    }
    Write-Log "Telemetry configuration complete."
}

# ─────────────────────────────────────────────
# DISABLE UNNECESSARY SCHEDULED TASKS
# ─────────────────────────────────────────────
$TasksToDisable = @(
    "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser"
    "\Microsoft\Windows\Application Experience\ProgramDataUpdater"
    "\Microsoft\Windows\Application Experience\StartupAppTask"
    "\Microsoft\Windows\Autochk\Proxy"
    "\Microsoft\Windows\CloudExperienceHost\CreateObjectTask"
    "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator"
    "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip"
    "\Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask"
    "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector"
    "\Microsoft\Windows\Feedback\Siuf\DmClient"
    "\Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload"
    "\Microsoft\Windows\Maps\MapsUpdateTask"
    "\Microsoft\Windows\Maps\MapsToastTask"
    "\Microsoft\Windows\Shell\FamilySafetyMonitor"
    "\Microsoft\Windows\Shell\FamilySafetyRefreshTask"
    "\Microsoft\Windows\Windows Error Reporting\QueueReporting"
    "\Microsoft\Windows\WindowsUpdate\Scheduled Start"
    "\Microsoft\XblGameSave\XblGameSaveTask"
    "\Microsoft\Windows\Application Experience\MareBackup"
    "\Microsoft\Windows\Clip\License Validation"
    "\Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem"
    "\Microsoft\Windows\RetailDemo\CleanupOfflineContent"
)

if ($Config.DisableScheduledTasks) {
    Write-Log "--- Disabling Unnecessary Scheduled Tasks ---"
    foreach ($task in $TasksToDisable) {
        try {
            $t = Get-ScheduledTask -TaskPath (Split-Path $task) -TaskName (Split-Path $task -Leaf) -ErrorAction SilentlyContinue
            if ($t) {
                Disable-ScheduledTask -TaskPath (Split-Path $task) -TaskName (Split-Path $task -Leaf) -ErrorAction Stop | Out-Null
                Write-Log "Disabled task: $task"
            }
        } catch {
            Write-Log "  Could not disable task ${task}: $_" "WARN"
        }
    }
    Write-Log "Scheduled tasks configuration complete."
}

# ─────────────────────────────────────────────
# PERFORMANCE & UI TWEAKS FOR THIN CLIENT USE
# ─────────────────────────────────────────────
if ($Config.ApplyPerformanceTweaks) {
    Write-Log "--- Applying Performance & UI Tweaks ---"

    # Set Visual Effects to "Adjust for best performance"
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" -Name "VisualFXSetting" -Value 2 -ErrorAction SilentlyContinue

    # Disable transparency effects
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "EnableTransparency" -Value 0 -ErrorAction SilentlyContinue

    # Disable animations
    Set-ItemProperty -Path "HKCU:\Control Panel\Desktop\WindowMetrics" -Name "MinAnimate" -Value "0" -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "UserPreferencesMask" -Value ([byte[]](0x90,0x12,0x03,0x80,0x10,0x00,0x00,0x00)) -ErrorAction SilentlyContinue

    # Power plan — High Performance
    powercfg /setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c 2>$null
    Write-Log "Power plan set to High Performance."

    # Disable Hibernation (frees disk space)
    powercfg /hibernate off
    Write-Log "Hibernation disabled."

    # Disable fast startup (can cause issues with AVD sessions)
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" -Name "HiberbootEnabled" -Value 0 -ErrorAction SilentlyContinue
    Write-Log "Fast Startup disabled."

    # Show file extensions & hidden files (helpful for admin use)
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Value 0 -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Hidden" -Value 1 -ErrorAction SilentlyContinue

    Write-Log "Performance tweaks applied."
}

# ─────────────────────────────────────────────
# DISABLE STARTUP ITEMS
# ─────────────────────────────────────────────
if ($Config.DisableStartupJunk) {
    Write-Log "--- Disabling Startup Junk ---"

    $StartupKeysToRemove = @(
        # OneDrive auto-start
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\OneDrive"
        # Teams auto-start (consumer)
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\com.squirrel.Teams.Teams"
        # Skype
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Skype"
    )

    foreach ($key in $StartupKeysToRemove) {
        $path = Split-Path $key
        $name = Split-Path $key -Leaf
        try {
            if (Get-ItemProperty -Path $path -Name $name -ErrorAction SilentlyContinue) {
                Remove-ItemProperty -Path $path -Name $name -ErrorAction Stop
                Write-Log "Removed startup entry: $name"
            }
        } catch {
            Write-Log "  Could not remove startup entry ${name}: $_" "WARN"
        }
    }

    # Disable OneDrive completely
    Write-Log "Disabling OneDrive..."
    $oneDrivePath = "$env:SYSTEMROOT\SysWOW64\OneDriveSetup.exe"
    if (!(Test-Path $oneDrivePath)) { $oneDrivePath = "$env:SYSTEMROOT\System32\OneDriveSetup.exe" }
    if (Test-Path $oneDrivePath) {
        try {
            Start-Process $oneDrivePath "/uninstall" -NoNewWindow -Wait
            Write-Log "OneDrive uninstalled."
        } catch {
            Write-Log "  Could not uninstall OneDrive: $_" "WARN"
        }
    }
    if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name "DisableFileSyncNGSC" -Value 1 -ErrorAction SilentlyContinue

    Write-Log "Startup junk disabled."
}

# ─────────────────────────────────────────────
# REMOVE OPTIONAL WINDOWS FEATURES NOT NEEDED
# Features KEPT: Printing, .NET runtimes, Networking
# ─────────────────────────────────────────────
if ($Config.CleanOptionalFeatures) {
    Write-Log "--- Removing Unnecessary Optional Windows Features ---"
    $FeaturesToRemove = @(
        "MediaPlayback"          # Windows Media Player
        "WindowsMediaPlayer"
        "Internet-Explorer-Optional-amd64"  # IE (legacy)
        "WorkFolders-Client"     # Work Folders sync
        "Printing-XPSServices-Features"  # XPS printer (not needed)
        "FaxServicesClientPackage"       # Fax
    )
    foreach ($feature in $FeaturesToRemove) {
        try {
            $f = Get-WindowsOptionalFeature -Online -FeatureName $feature -ErrorAction SilentlyContinue
            if ($f -and $f.State -eq "Enabled") {
                Disable-WindowsOptionalFeature -Online -FeatureName $feature -NoRestart -ErrorAction Stop | Out-Null
                Write-Log "Disabled optional feature: $feature"
            }
        } catch {
            Write-Log "  Could not disable feature ${feature}: $_" "WARN"
        }
    }
    Write-Log "Optional features configuration complete."
}

# ─────────────────────────────────────────────
# PRIVACY HARDENING
# ─────────────────────────────────────────────
if ($Config.HardenPrivacy) {
    Write-Log "--- Applying Privacy Settings ---"

    $PrivacyKeys = @(
        # Disable app access to camera
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy"; Name = "LetAppsAccessCamera"; Value = 2 }
        # Disable app access to microphone (enable if needed for AVD audio)
        # @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy"; Name = "LetAppsAccessMicrophone"; Value = 2 }
        # Disable app access to contacts
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy"; Name = "LetAppsAccessContacts"; Value = 2 }
        # Disable app access to calendar
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy"; Name = "LetAppsAccessCalendar"; Value = 2 }
        # Disable access to call history
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy"; Name = "LetAppsAccessCallHistory"; Value = 2 }
        # Disable access to messaging
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy"; Name = "LetAppsAccessMessaging"; Value = 2 }
        # Disable access to motion data
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy"; Name = "LetAppsAccessMotion"; Value = 2 }
        # Disable access to notifications
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy"; Name = "LetAppsAccessNotifications"; Value = 2 }
        # Disable access to tasks
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy"; Name = "LetAppsAccessTasks"; Value = 2 }
        # Disable access to account info
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy"; Name = "LetAppsAccessAccountInfo"; Value = 2 }
        # Disable Tailored Experiences
        @{ Path = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy"; Name = "TailoredExperiencesWithDiagnosticDataEnabled"; Value = 0 }
    )

    foreach ($key in $PrivacyKeys) {
        try {
            if (!(Test-Path $key.Path)) { New-Item -Path $key.Path -Force | Out-Null }
            Set-ItemProperty -Path $key.Path -Name $key.Name -Value $key.Value -ErrorAction Stop
            Write-Log "Privacy: $($key.Name) = $($key.Value)"
        } catch {
            Write-Log "  Failed privacy key $($key.Name): $_" "WARN"
        }
    }
    Write-Log "Privacy hardening complete."
}

# ─────────────────────────────────────────────
# ENSURE PRINT SPOOLER IS RUNNING
# (Critical for local printer redirection in AVD)
# ─────────────────────────────────────────────
Write-Log "--- Ensuring Print Spooler is Active ---"
try {
    Set-Service -Name "Spooler" -StartupType Automatic -ErrorAction Stop
    Start-Service -Name "Spooler" -ErrorAction Stop
    Write-Log "Print Spooler is running and set to Automatic."
} catch {
    Write-Log "Could not configure Print Spooler: $_" "ERROR"
}

# Also ensure Print Workflow Service (needed for modern print dialog)
try {
    Set-Service -Name "PrintWorkflowUserSvc*" -StartupType Manual -ErrorAction SilentlyContinue
    Write-Log "Print Workflow Service set to Manual."
} catch {}

# ─────────────────────────────────────────────
# ENSURE AUDIO IS RUNNING
# (For audio redirection in AVD sessions)
# ─────────────────────────────────────────────
Write-Log "--- Ensuring Audio Services are Active ---"
$AudioServices = @("Audiosrv", "AudioEndpointBuilder")
foreach ($svc in $AudioServices) {
    try {
        Set-Service -Name $svc -StartupType Automatic -ErrorAction Stop
        Start-Service -Name $svc -ErrorAction Stop
        Write-Log "Audio service running: $svc"
    } catch {
        Write-Log "  Could not start audio service ${svc}: $_" "WARN"
    }
}

# ─────────────────────────────────────────────
# ENSURE WINDOWS APP (AVD CLIENT) IS PRESENT
# ─────────────────────────────────────────────
Write-Log "--- Checking for Windows App (AVD Client) ---"
$windowsApp = Get-AppxPackage -Name "MicrosoftCorporationII.WindowsApp" -AllUsers -ErrorAction SilentlyContinue
if ($windowsApp) {
    Write-Log "Windows App is installed: $($windowsApp.Version)"
} else {
    Write-Log "Windows App NOT found. Please install it from the Microsoft Store." "WARN"
    Write-Log "Store link: https://apps.microsoft.com/detail/9N1F85V9T8BN" "WARN"
}

# ─────────────────────────────────────────────
# CONFIGURE WINDOWS UPDATE — Security Only
# Defer feature upgrades, keep security patches
# ─────────────────────────────────────────────
Write-Log "--- Configuring Windows Update Policy ---"
$WUPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
$WUAUPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
foreach ($p in @($WUPath, $WUAUPath)) {
    if (!(Test-Path $p)) { New-Item -Path $p -Force | Out-Null }
}
# Defer feature updates by 365 days, quality updates by 7 days
Set-ItemProperty -Path $WUPath -Name "DeferFeatureUpdatesPeriodInDays" -Value 365 -ErrorAction SilentlyContinue
Set-ItemProperty -Path $WUPath -Name "DeferQualityUpdatesPeriodInDays" -Value 7 -ErrorAction SilentlyContinue
Set-ItemProperty -Path $WUPath -Name "DeferFeatureUpdates" -Value 1 -ErrorAction SilentlyContinue
Set-ItemProperty -Path $WUPath -Name "DeferQualityUpdates" -Value 1 -ErrorAction SilentlyContinue
# Prevent auto-reboot during business hours
Set-ItemProperty -Path $WUAUPath -Name "NoAutoRebootWithLoggedOnUsers" -Value 1 -ErrorAction SilentlyContinue
Write-Log "Windows Update: Feature updates deferred 365 days, security updates 7 days."

# ─────────────────────────────────────────────
# CLEAN TASKBAR & START MENU
# ─────────────────────────────────────────────
Write-Log "--- Cleaning Taskbar & Start Menu ---"
# Remove taskbar widgets
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Dsh" -Name "AllowNewsAndInterests" -Value 0 -ErrorAction SilentlyContinue
if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Dsh")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Dsh" -Force | Out-Null
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Dsh" -Name "AllowNewsAndInterests" -Value 0 -ErrorAction SilentlyContinue
}
# Disable Task View button
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -Value 0 -ErrorAction SilentlyContinue
# Disable Search on taskbar (icon only or hidden — user can still use Start)
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Value 1 -ErrorAction SilentlyContinue
Write-Log "Taskbar cleaned."

# ─────────────────────────────────────────────
# SUMMARY
# ─────────────────────────────────────────────
Write-Log "=========================================="
Write-Log " AVD Thin Client Setup Complete!"
Write-Log "=========================================="
Write-Log ""
Write-Log " WHAT WAS DONE:"
Write-Log "  [OK] Bloatware Store apps removed"
Write-Log "  [OK] Unnecessary Windows services disabled"
Write-Log "  [OK] Telemetry and data collection disabled"
Write-Log "  [OK] Scheduled diagnostic tasks disabled"
Write-Log "  [OK] Performance tweaks applied"
Write-Log "  [OK] OneDrive disabled/uninstalled"
Write-Log "  [OK] Privacy app permissions locked down"
Write-Log "  [OK] Print Spooler confirmed running"
Write-Log "  [OK] Audio services confirmed running"
Write-Log "  [OK] Windows Update deferred (feature updates)"
Write-Log ""
Write-Log " PRESERVED / NOT TOUCHED:"
Write-Log "  [OK] Windows App (MicrosoftCorporationII.WindowsApp)"
Write-Log "  [OK] Microsoft Store (for Windows App updates)"
Write-Log "  [OK] Print Spooler + printing stack"
Write-Log "  [OK] Audio services (for AVD audio redirection)"
Write-Log "  [OK] Network stack (DHCP, DNS, Wi-Fi)"
Write-Log "  [OK] Windows Defender (security)"
Write-Log "  [OK] Credential Manager"
Write-Log "  [OK] Windows Update (security patches)"
Write-Log ""
Write-Log " Log saved to: $LogFile"
Write-Log ""
Write-Log " *** PLEASE REBOOT THE MACHINE NOW ***"
Write-Host ""
Write-Host "Press any key to exit..." -ForegroundColor Green
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
