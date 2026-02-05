<#
    Created By: Erwin Uribe & Floyd Kellogg
    Version: 1.0 
    Description: 
        - Fix for when microsoft is blocked in a IL5 GCC High Tenant. Script will go through run as system to disable the store for 45seconds, then run a scheduled task as a user to install Company Portal, after additional portion of the system script will ensure Microsoft Store is Re-Blocked after the 45seconds. 
        - Microsoft was unable to provide any solution other than get a commercial account to download CompanyPortal. This is our solution to this problem.
        - Remediation script for installing Company Portal
        - Will perform following items
            1. Disables Microsoft Store Block
            2. Attempts to install Company Portal via Winget
            3. Always attempts to rebllock Store even if install was unsuccesful
            4. Removes the temp Script and Task that was created.
    Creation Date: 1.16.2026
    Known Bugs:
        - 1 of the 2 options for obtaining the user active session will fail, this is by design. 
#>

$ErrorActionPreference = "Continue"

Write-Output "=== Company Portal Remediation ==="
Write-Output "Script running as: $env:USERNAME"

# Registry paths
$registryBasePath = "HKLM:\Software\FU_Microsoft"
$customPath = "$registryBasePath\Custom"
$installDateKey = "CompanyPortalInstallDate"
$storeRegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore"
$storeBlockKey = "RemoveWindowsStore"

# Logging setup
$logPath = "C:\ProgramData\Microsoft\IntuneManagementExtension\Logs"
$logFile = Join-Path $logPath "CompanyPortal-Remediation-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
$scriptPath = "C:\dodnetrun"

# Create necessary directories
if (-not (Test-Path $logPath)) {
    New-Item -Path $logPath -ItemType Directory -Force | Out-Null
}

if (-not (Test-Path $scriptPath)) {
    New-Item -Path $scriptPath -ItemType Directory -Force | Out-Null
}

# Logging function
function Write-Log {
    param($Message, $Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "$timestamp [$Level] - $Message"
    Write-Output $logMessage
    Add-Content -Path $logFile -Value $logMessage
}

# Function to get version
function Get-CompanyPortalVersion {
    try {
        $windowsAppsPath = "C:\Program Files\WindowsApps"
        $cportalFolder = Get-ChildItem $windowsAppsPath -Directory -ErrorAction SilentlyContinue |
                    Where-Object { $_.Name -like "Microsoft.CompanyPortal*" } |
                    Sort-Object Name -Descending | Select-Object -First 1
        
        if ($cportalFolder) {
            $exePath = Join-Path $cportalFolder.FullName "CompanyPortal.exe"
            if (Test-Path $exePath) {
                return (Get-Item $exePath).VersionInfo.ProductVersion
            }
        }
        return "Unknown"
    } catch {
        return "Unknown"
    }
}

Write-Log "=== Starting Remediation Process ===" "INFO"

try {
    # STEP 1: Create/Update Registry Tracking
    Write-Log "--- STEP 1: Setting up registry tracking ---" "INFO"
    
    if (-not (Test-Path $registryBasePath)) {
        Write-Log "Creating base registry path: $registryBasePath" "INFO"
        New-Item -Path $registryBasePath -Force | Out-Null
    }
    
    if (-not (Test-Path $customPath)) {
        Write-Log "Creating Custom registry path: $customPath" "INFO"
        New-Item -Path $customPath -Force | Out-Null
    }
    
    # Set today's date
    $todayDate = Get-Date -Format "yyyy-MM-dd"
    Set-ItemProperty -Path $customPath -Name $installDateKey -Value $todayDate -Force
    Write-Log "Set install date to: $todayDate" "INFO"

    # STEP 2: Ensure store registry path exists
    if (-not (Test-Path $storeRegistryPath)) {
        Write-Log "Creating store registry path: $storeRegistryPath" "INFO"
        New-Item -Path $storeRegistryPath -Force | Out-Null
    }

    # STEP 3: Unblock Microsoft Store
    Write-Log "--- STEP 3: Unblocking Microsoft Store ---" "INFO"
    
    $currentValue = (Get-ItemProperty -Path $storeRegistryPath -Name $storeBlockKey -ErrorAction SilentlyContinue).$storeBlockKey
    Write-Log "Current registry value: $currentValue" "INFO"
    
    Set-ItemProperty -Path $storeRegistryPath -Name $storeBlockKey -Value 0 -ErrorAction Stop
    Start-Sleep -Seconds 3
    
    $newValue = (Get-ItemProperty -Path $storeRegistryPath -Name $storeBlockKey -ErrorAction SilentlyContinue).$storeBlockKey
    Write-Log "Registry value after unblock: $newValue" "INFO"
    
    if ($newValue -ne 0) {
        Write-Log "Failed to unblock store - value is still $newValue" "ERROR"
        throw "Failed to set registry value to 0"
    }
    Write-Log "SUCCESS: Store unblocked" "INFO"

    # STEP 4: Get logged-in user info
    Write-Log "--- STEP 4: Detecting User Context ---" "INFO"

    $fullUsername = (Get-CimInstance -Class Win32_ComputerSystem).UserName
    Write-Log "Win32_ComputerSystem username: $fullUsername" "INFO"

    if (-not $fullUsername) {
        Write-Log "Could not detect logged-in user" "ERROR"
        throw "No user logged in"
    }

    # STEP 5: Find active session
    Write-Log "--- STEP 5: Finding Active Session ---" "INFO"
    
    $sessionId = $null
    $username = $fullUsername
    
    try {
        $quserOutput = & "$env:SystemRoot\System32\query.exe" user 2>&1
        Write-Log "Query user output: $($quserOutput -join '; ')" "INFO"
        
        foreach ($line in $quserOutput) {
            if ($line -match '^\s*>?(\S+)\s+.*?(\d+)\s+Active') {
                $quserUsername = $Matches[1].Trim()
                $sessionId = $Matches[2].Trim()
                $shortUsername = $fullUsername.Split('\')[-1]
                
                Write-Log "Comparing '$quserUsername' with '$shortUsername'" "INFO"
                
                if ($quserUsername.ToLower() -eq $shortUsername.ToLower()) {
                    Write-Log "MATCH FOUND - User: $username, Session: $sessionId" "INFO"
                    break
                }
            }
        }
        
        if (-not $sessionId) {
            Write-Log "Could not find session ID from query output" "WARN"
            $session = Get-CimInstance -Class Win32_ComputerSystem | Select-Object -ExpandProperty UserName
            if ($session) {
                Write-Log "Using WMI detected user: $session" "INFO"
                $username = $session
            }
        }
        
    } catch {
        Write-Log "Error querying user sessions: $($_.Exception.Message)" "WARN"
        Write-Log "Will proceed with detected username: $username" "INFO"
    }
    
    if (-not $username) {
        Write-Log "CRITICAL: No username available" "ERROR"
        throw "Failed to detect active user"
    }
    
    Write-Log "Proceeding with User: $username, Session: $sessionId" "INFO"

    # STEP 6: Install Company Portal
    Write-Log "--- STEP 6: Installing Company Portal ---" "INFO"
    
    $userScriptPath = Join-Path $scriptPath "InstallCPortal_$(Get-Date -Format 'yyyyMMdd-HHmmss').ps1"
    Write-Log "User script will be created at: $userScriptPath" "INFO"
    
    # Create install script for user context
    $installScriptContent = @"
`$ErrorActionPreference = 'Continue'
Start-Transcript -Path "C:\Windows\Temp\CPortalInstall-`$(Get-Date -Format 'yyyyMMdd-HHmmss').log" -Append

Write-Output "Running as: `$env:USERNAME"
Write-Output "User Profile: `$env:USERPROFILE"

# Find winget
`$wingetPath = Get-ChildItem "C:\Program Files\WindowsApps\Microsoft.DesktopAppInstaller*\winget.exe" -ErrorAction SilentlyContinue | Select-Object -First 1

if (`$wingetPath) {
    Write-Output "Found winget: `$(`$wingetPath.FullName)"
    & `$wingetPath.FullName install --id 9WZDNCRFJ3PZ --source msstore --scope user --accept-package-agreements --accept-source-agreements --silent --force
    `$exitCode = `$LASTEXITCODE
    Write-Output "Winget exit code: `$exitCode"
} else {
    Write-Output "Winget not found in WindowsApps folder"
    try {
        winget install --id 9WZDNCRFJ3PZ --source msstore --scope user --accept-package-agreements --accept-source-agreements --silent --force
        `$exitCode = `$LASTEXITCODE
        Write-Output "Winget (PATH) exit code: `$exitCode"
    } catch {
        Write-Output "ERROR: Could not run winget - `$_"
    }
}

Stop-Transcript
"@
    
    $installScriptContent | Out-File -FilePath $userScriptPath -Encoding UTF8 -Force
    Write-Log "Created user script at: $userScriptPath" "INFO"

    # Create VBS wrapper to completely hide PowerShell window from end users
    $vbsScriptPath = Join-Path $scriptPath "RunHidden_$(Get-Date -Format 'yyyyMMdd-HHmmss').vbs"
    $vbsContent = @"
Set objShell = CreateObject("WScript.Shell")
objShell.Run "powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File ""$userScriptPath""", 0, False
"@
    $vbsContent | Out-File -FilePath $vbsScriptPath -Encoding ASCII -Force
    Write-Log "Created VBS wrapper script at: $vbsScriptPath" "INFO"

    # Create scheduled task
    $taskName = "IntuneInstallCPortal_$(Get-Random)"
    Write-Log "Creating scheduled task: $taskName" "INFO"
    
    schtasks /delete /tn $taskName /f 2>&1 | Out-Null
    
    $startTime = (Get-Date).AddMinutes(1).ToString("HH:mm")
    
    Write-Log "Creating task for user: $username" "INFO"
    
    # Use VBS wrapper via wscript to completely hide window
    $createResult = schtasks /create /tn $taskName /tr "wscript.exe `"$vbsScriptPath`"" /sc once /st $startTime /ru "$username" /rl highest /f 2>&1
    
    if ($createResult -match "ERROR") {
        Write-Log "Task creation failed with full username, trying short username" "WARN"
        $shortUser = $username.Split('\')[-1]

        
        # Use VBS wrapper via wscript to completely hide window
        $createResult = schtasks /create /tn $taskName /tr "wscript.exe `"$vbsScriptPath`"" /sc once /st $startTime /ru "$shortUser" /rl highest /f 2>&1
    }
    
    Write-Log "Task creation result: $($createResult -join '; ')" "INFO"
    
    if ($createResult -match "ERROR") {
        Write-Log "Failed to create scheduled task" "ERROR"
        throw "Scheduled task creation failed"
    }
    
    # Run task immediately
    Write-Log "Running task immediately..." "INFO"
    $runResult = schtasks /run /tn $taskName 2>&1
    Write-Log "Task run result: $($runResult -join '; ')" "INFO"
    
    # Wait for installation
    Write-Log "Waiting 45 seconds for installation to complete..." "INFO"
    Start-Sleep -Seconds 45
    
    # Query task status
    $queryResult = schtasks /query /tn $taskName /fo list 2>&1
    Write-Log "Task status: $($queryResult -join '; ')" "INFO"
    
    # Cleanup task
    schtasks /delete /tn $taskName /f 2>&1 | Out-Null
    
    # Verify installation
    Write-Log "Verifying Company Portal installation..." "INFO"
    Start-Sleep -Seconds 5
    
    $version = Get-CompanyPortalVersion
    if ($version -ne "Unknown") {
        Write-Log "SUCCESS: Company Portal detected - Version: $version" "INFO"
        $statusMessage = "Remediation Status: Updated - Company Portal installed successfully (Version: $version)"
    } else {
        Write-Log "WARNING: Company Portal not detected after installation attempt" "WARN"
        $statusMessage = "Remediation Status: Updated - Installation attempted but verification failed"
    }

} catch {
    Write-Log "CRITICAL ERROR: $($_.Exception.Message)" "ERROR"
    Write-Log "Stack Trace: $($_.ScriptStackTrace)" "ERROR"
    $statusMessage = "Remediation Status: Failed - $($_.Exception.Message)"
    
    if (-not $userScriptPath) {
        $userScriptPath = ""
    }
} finally {
    # STEP 7: Re-block MS Store (ALWAYS RUN)
    Write-Log "--- STEP 7: Re-blocking Microsoft Store ---" "INFO"
    
    try {
        Set-ItemProperty -Path $storeRegistryPath -Name $storeBlockKey -Value 1 -Force -ErrorAction Stop
        Start-Sleep -Seconds 2
        
        $finalValue = (Get-ItemProperty -Path $storeRegistryPath -Name $storeBlockKey -ErrorAction SilentlyContinue).$storeBlockKey
        Write-Log "Final registry value: $finalValue" "INFO"
        
        if ($finalValue -eq 1) {
            Write-Log "SUCCESS: Store blocked" "INFO"
        } else {
            Write-Log "WARNING: Store may not be properly blocked - value is $finalValue" "WARN"
        }
    } catch {
        Write-Log "ERROR blocking store: $($_.Exception.Message)" "ERROR"
    }
    
    # Cleanup temp script
    if ($userScriptPath -and (Test-Path $userScriptPath -ErrorAction SilentlyContinue)) {
        Remove-Item $userScriptPath -Force -ErrorAction SilentlyContinue
        Write-Log "Cleaned up temporary script file" "INFO"
    }
    
    # CHANGE 4: Clean up VBS wrapper script
    if ($vbsScriptPath -and (Test-Path $vbsScriptPath -ErrorAction SilentlyContinue)) {
        Remove-Item $vbsScriptPath -Force -ErrorAction SilentlyContinue
        Write-Log "Cleaned up VBS wrapper script" "INFO"
    }
    
    Write-Log "=== Remediation Process Complete ===" "INFO"
    Write-Log "Log file: $logFile" "INFO"
    
    # Output final status
    if (-not $statusMessage) {
        $version = Get-CompanyPortalVersion
        $statusMessage = "Remediation Status: Updated - Version: $version"
    }
    Write-Host $statusMessage
}

Exit 0
