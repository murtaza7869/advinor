<#
.SYNOPSIS
    Renames the "Canopy Desktop Assistant" folder to "old_Canopy Desktop Assistant" for a specific user.
    Designed for RMM deployment under SYSTEM context.

.DESCRIPTION
    This script takes a username as a parameter and renames the Canopy Desktop Assistant folder
    in that user's AppData\Roaming directory by adding "old_" prefix.
    Runs silently without user intervention and logs all actions.

.PARAMETER UserProfile
    The name of the user profile folder (e.g., "MurtazaKanchwala")

.EXAMPLE
    .\Rename-CanopyFolder.ps1 -UserProfile "MurtazaKanchwala"
    
.EXAMPLE
    .\Rename-CanopyFolder.ps1 "JohnDoe"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true, Position=0, HelpMessage="Enter the user profile folder name")]
    [ValidateNotNullOrEmpty()]
    [string]$UserProfile
)

# Function to write timestamped log entries
function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    Write-Output $logMessage
}

# Script start
Write-Log "========================================" "INFO"
Write-Log "Canopy Desktop Assistant Folder Rename Script Started" "INFO"
Write-Log "========================================" "INFO"
Write-Log "Script Version: 1.0 - RMM Deployment" "INFO"
Write-Log "Execution Context: $(whoami)" "INFO"
Write-Log "Target User Profile: $UserProfile" "INFO"

# Define the source and destination paths
$sourcePath = "C:\Users\$UserProfile\AppData\Roaming\Canopy Desktop Assistant"
$destinationPath = "C:\Users\$UserProfile\AppData\Roaming\old_Canopy Desktop Assistant"

Write-Log "Source Path: $sourcePath" "INFO"
Write-Log "Destination Path: $destinationPath" "INFO"

# Initialize exit code
$exitCode = 0

try {
    # Check if the user profile exists
    $userProfilePath = "C:\Users\$UserProfile"
    if (-not (Test-Path $userProfilePath)) {
        Write-Log "User profile folder not found: $userProfilePath" "ERROR"
        Write-Log "Please verify the username is correct" "ERROR"
        $exitCode = 1
        exit $exitCode
    }

    Write-Log "User profile folder verified: $userProfilePath" "INFO"

    # Check if source folder exists
    if (Test-Path $sourcePath) {
        Write-Log "Canopy Desktop Assistant folder found" "INFO"
        
        # Get folder size and file count for logging
        try {
            $folderInfo = Get-ChildItem -Path $sourcePath -Recurse -ErrorAction SilentlyContinue
            $fileCount = ($folderInfo | Where-Object {!$_.PSIsContainer}).Count
            $folderCount = ($folderInfo | Where-Object {$_.PSIsContainer}).Count
            $totalSize = [math]::Round(($folderInfo | Measure-Object -Property Length -Sum -ErrorAction SilentlyContinue).Sum / 1MB, 2)
            
            Write-Log "Folder statistics - Files: $fileCount, Subfolders: $folderCount, Size: ${totalSize}MB" "INFO"
        }
        catch {
            Write-Log "Could not retrieve folder statistics: $_" "WARN"
        }
        
        # Check if destination already exists
        if (Test-Path $destinationPath) {
            Write-Log "Destination folder already exists, attempting to remove it" "WARN"
            
            try {
                # First try to remove normally
                Remove-Item -Path $destinationPath -Recurse -Force -ErrorAction Stop
                Write-Log "Successfully removed existing destination folder" "INFO"
            }
            catch {
                Write-Log "Failed to remove existing destination folder: $_" "ERROR"
                
                # Try to take ownership and remove (useful when running as SYSTEM)
                try {
                    Write-Log "Attempting to take ownership and remove folder" "INFO"
                    $acl = Get-Acl $destinationPath
                    $adminGroup = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-544")
                    $acl.SetOwner($adminGroup)
                    Set-Acl -Path $destinationPath -AclObject $acl -ErrorAction Stop
                    Remove-Item -Path $destinationPath -Recurse -Force -ErrorAction Stop
                    Write-Log "Successfully removed destination folder after taking ownership" "INFO"
                }
                catch {
                    Write-Log "Failed to remove destination folder even after ownership attempt: $_" "ERROR"
                    $exitCode = 2
                    exit $exitCode
                }
            }
        }
        
        # Check if any process is using the folder
        try {
            $openFiles = @()
            $processes = Get-Process | Where-Object {$_.Path -like "$sourcePath*"} -ErrorAction SilentlyContinue
            if ($processes) {
                foreach ($proc in $processes) {
                    Write-Log "Process using folder: $($proc.Name) (PID: $($proc.Id))" "WARN"
                    $openFiles += $proc.Name
                }
                
                Write-Log "Attempting to stop processes using the folder" "INFO"
                $processes | Stop-Process -Force -ErrorAction SilentlyContinue
                Start-Sleep -Seconds 2
            }
        }
        catch {
            Write-Log "Could not check for processes using the folder: $_" "WARN"
        }
        
        # Perform the rename operation
        try {
            Rename-Item -Path $sourcePath -NewName "old_Canopy Desktop Assistant" -ErrorAction Stop
            Write-Log "Folder renamed successfully" "SUCCESS"
            Write-Log "Operation completed: '$sourcePath' -> '$destinationPath'" "SUCCESS"
            
            # Verify the rename was successful
            if (Test-Path $destinationPath) {
                Write-Log "Rename verification: Destination folder exists" "INFO"
                if (-not (Test-Path $sourcePath)) {
                    Write-Log "Rename verification: Source folder no longer exists" "INFO"
                    Write-Log "Rename operation verified successfully" "SUCCESS"
                }
                else {
                    Write-Log "Rename verification: Source folder still exists - unexpected state" "WARN"
                }
            }
            else {
                Write-Log "Rename verification: Destination folder not found - unexpected state" "WARN"
            }
        }
        catch {
            Write-Log "Failed to rename folder: $_" "ERROR"
            
            # Provide specific error guidance
            if ($_.Exception.Message -like "*being used by another process*") {
                Write-Log "The folder is in use by another process" "ERROR"
                Write-Log "Canopy Desktop Assistant may be running" "ERROR"
                
                # Try to find and kill Canopy processes
                try {
                    $canopyProcesses = Get-Process -Name "*Canopy*" -ErrorAction SilentlyContinue
                    if ($canopyProcesses) {
                        Write-Log "Found Canopy processes, attempting to stop them" "INFO"
                        $canopyProcesses | Stop-Process -Force -ErrorAction SilentlyContinue
                        Start-Sleep -Seconds 3
                        
                        # Retry the rename
                        Rename-Item -Path $sourcePath -NewName "old_Canopy Desktop Assistant" -ErrorAction Stop
                        Write-Log "Folder renamed successfully after stopping Canopy processes" "SUCCESS"
                    }
                }
                catch {
                    Write-Log "Could not stop Canopy processes or retry rename: $_" "ERROR"
                    $exitCode = 3
                }
            }
            elseif ($_.Exception.Message -like "*Access*denied*") {
                Write-Log "Access denied - insufficient permissions" "ERROR"
                Write-Log "Running as: $(whoami)" "ERROR"
                $exitCode = 4
            }
            else {
                Write-Log "Unexpected error during rename operation" "ERROR"
                $exitCode = 5
            }
            
            if ($exitCode -ne 0) {
                exit $exitCode
            }
        }
    }
    else {
        Write-Log "Canopy Desktop Assistant folder not found at: $sourcePath" "ERROR"
        Write-Log "Possible reasons:" "INFO"
        Write-Log "  - Username may be incorrect: $UserProfile" "INFO"
        Write-Log "  - Canopy Desktop Assistant not installed for this user" "INFO"
        Write-Log "  - Folder may be in a different location" "INFO"
        
        # Check for alternative locations
        $altPath1 = "C:\Users\$UserProfile\AppData\Local\Canopy Desktop Assistant"
        $altPath2 = "C:\Users\$UserProfile\AppData\LocalLow\Canopy Desktop Assistant"
        
        if (Test-Path $altPath1) {
            Write-Log "Found Canopy folder at alternative location: $altPath1" "INFO"
        }
        if (Test-Path $altPath2) {
            Write-Log "Found Canopy folder at alternative location: $altPath2" "INFO"
        }
        
        $exitCode = 6
        exit $exitCode
    }
}
catch {
    Write-Log "Unexpected script error: $_" "ERROR"
    Write-Log "Error details: $($_.Exception.Message)" "ERROR"
    Write-Log "Error location: $($_.InvocationInfo.PositionMessage)" "ERROR"
    $exitCode = 99
}
finally {
    Write-Log "========================================" "INFO"
    Write-Log "Script execution completed with exit code: $exitCode" "INFO"
    Write-Log "========================================" "INFO"
    
    # Output final status for RMM tool
    if ($exitCode -eq 0) {
        Write-Output "RESULT: SUCCESS"
    }
    else {
        Write-Output "RESULT: FAILURE - Exit Code: $exitCode"
    }
    
    exit $exitCode
}
