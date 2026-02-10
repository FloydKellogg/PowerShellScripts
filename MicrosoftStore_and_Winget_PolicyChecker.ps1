# ============================================
# Microsoft Store and Winget Checker
# Version: 1.0
# Author: Floyd K
# ============================================


[CmdletBinding()]
param (
    [string]$LogPath = $(Join-Path -Path $PSScriptRoot -ChildPath ("StoreDiag_{0}.log" -f (Get-Date -Format "yyyyMMdd_HHmmss"))),
    [switch]$JsonOutput,
    [switch]$UseEmoji,
    [switch]$NoColor,
    [int]$OperationTimeoutSeconds = 10
)

$ProgressPreference = 'SilentlyContinue'

# Ensure log directory exists
try {
    $logDir = Split-Path -Path $LogPath -Parent
    if ($logDir -and -not (Test-Path -Path $logDir)) {
        New-Item -ItemType Directory -Path $logDir -Force | Out-Null
    }
} catch {
    Write-Host "[WARNING] Failed to verify/create log directory: $logDir - $($_.Exception.Message)" -ForegroundColor Yellow
}

# Initialize JSON capture if requested
if ($JsonOutput) {
    $global:JsonData = @{}
}

# Global counters for summary
$script:PassCount = 0
$script:WarnCount = 0
$script:FailCount = 0
$script:Issues = @()

function Write-Log {
    param (
        [string]$Message,
        [string]$Color = "White"
    )
    
    if ($NoColor) {
        Write-Host $Message
    } else {
        Write-Host $Message -ForegroundColor $Color
    }
    
    if ($LogPath) {
        try { 
            # Strip ANSI color codes from log file
            $cleanMessage = $Message -replace '\x1b\[[0-9;]*m', ''
            Add-Content -Path $LogPath -Value $cleanMessage -Encoding UTF8 
        } catch {
            Write-Host "[WARNING] Failed to write to log file: $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }
}

function Write-Json {
    param ([string]$Key, [object]$Value)
    if ($JsonOutput) { $global:JsonData[$Key] = $Value }
}

function Write-SectionHeader {
    param ([string]$Title)
    Write-Log ""
    Write-Log ("=" * 80) -Color Cyan
    Write-Log "  $Title" -Color Cyan
    Write-Log ("=" * 80) -Color Cyan
}

function Write-SubSection {
    param ([string]$Title)
    Write-Log ""
    Write-Log ("-" * 80) -Color DarkGray
    Write-Log "  $Title" -Color Gray
    Write-Log ("-" * 80) -Color DarkGray
}

function Write-StatusLine {
    param (
        [string]$Status,
        [string]$Message,
        [string]$Details = ""
    )
    
    $statusText = ""
    $color = "White"
    
    switch ($Status) {
        "PASS" { 
            $statusText = if ($UseEmoji) { "✅ PASS" } else { "[PASS]" }
            $color = "Green"
            $script:PassCount++
        }
        "WARN" { 
            $statusText = if ($UseEmoji) { "⚠️  WARN" } else { "[WARN]" }
            $color = "Yellow"
            $script:WarnCount++
        }
        "FAIL" { 
            $statusText = if ($UseEmoji) { "❌ FAIL" } else { "[FAIL]" }
            $color = "Red"
            $script:FailCount++
            $script:Issues += $Message
        }
        "INFO" {
            $statusText = "[INFO]"
            $color = "Cyan"
        }
        default {
            $statusText = "[$Status]"
        }
    }
    
    $output = "{0,-8} {1}" -f $statusText, $Message
    if ($Details) {
        $output += "`n         $Details"
    }
    
    Write-Log $output -Color $color
}

# ---- Error classification helpers ------------------------------------------

function Get-RootException {
    param([Parameter(Mandatory)][Exception]$Exception)
    $ex = $Exception
    while ($ex.InnerException) { $ex = $ex.InnerException }
    return $ex
}

function Classify-NetworkError {
    param([Parameter(Mandatory)][Exception]$Exception)

    $root = Get-RootException -Exception $Exception

    if ($root -is [System.Net.WebException]) {
        switch ($root.Status) {
            'NameResolutionFailure'       { return "DNS name resolution failure" }
            'ConnectFailure'              { return "TCP connection failed" }
            'ProxyNameResolutionFailure'  { return "Proxy DNS resolution failure" }
            'ProtocolError'               { return "HTTP protocol error (non-2xx status)" }
            'TrustFailure'                { return "TLS/SSL trust failure (certificate not trusted)" }
            'SecureChannelFailure'        { return "TLS handshake failure (secure channel)" }
            'Timeout'                     { return "Network operation timed out" }
            'ConnectionClosed'            { return "Connection closed unexpectedly" }
            default                       { return "Web exception: $($root.Status)" }
        }
    } elseif ($root -is [System.Security.Authentication.AuthenticationException]) {
        return "TLS/SSL authentication failure"
    } elseif ($root -is [System.Net.Sockets.SocketException]) {
        return "Socket error: $($root.SocketErrorCode)"
    } elseif ($root -is [System.Net.Http.HttpRequestException]) {
        return "HTTP request error"
    } else {
        return $root.Message
    }
}

# ---- Timeout wrapper returning structured result ---------------------------

function Invoke-WithTimeout {
    param (
        [Parameter(Mandatory = $true)]
        [scriptblock]$ScriptBlock,
        [int]$TimeoutSeconds = 10,
        [object[]]$ArgumentList
    )

    try {
        $job = Start-Job -ScriptBlock {
            param($inner, $argsArray)
            try {
                $data = & $inner @argsArray
                [pscustomobject]@{
                    Completed     = $true
                    TimedOut      = $false
                    Data          = $data
                    Error         = $null
                    Message       = $null
                    ExceptionType = $null
                }
            } catch {
                [pscustomobject]@{
                    Completed     = $true
                    TimedOut      = $false
                    Data          = $null
                    Error         = $_
                    Message       = $_.Exception.Message
                    ExceptionType = $_.Exception.GetType().FullName
                }
            }
        } -ArgumentList @($ScriptBlock, $ArgumentList)
    } catch {
        Write-StatusLine "FAIL" "Failed to start background job" $_.Exception.Message
        return [pscustomobject]@{
            Completed     = $true
            TimedOut      = $false
            Data          = $null
            Error         = $_
            Message       = $_.Exception.Message
            ExceptionType = $_.Exception.GetType().FullName
        }
    }

    try {
        if (Wait-Job -Job $job -Timeout $TimeoutSeconds) {
            $result = Receive-Job -Job $job -ErrorAction SilentlyContinue
            if (-not $result) {
                $result = [pscustomobject]@{
                    Completed     = $true
                    TimedOut      = $false
                    Data          = $null
                    Error         = $null
                    Message       = $null
                    ExceptionType = $null
                }
            }
            return $result
        } else {
            return [pscustomobject]@{
                Completed     = $false
                TimedOut      = $true
                Data          = $null
                Error         = $null
                Message       = "Operation timed out after $TimeoutSeconds seconds."
                ExceptionType = $null
            }
        }
    } finally {
        try { Stop-Job -Job $job -Force -ErrorAction SilentlyContinue | Out-Null } catch {}
        try { Remove-Job -Job $job -Force -ErrorAction SilentlyContinue | Out-Null } catch {}
    }
}

# ============================================================================
# MAIN SCRIPT START
# ============================================================================

Write-SectionHeader "Microsoft Store & Winget Diagnostics"
Write-Log "  Timestamp: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -Color Gray
Write-Log "  Machine:   $env:COMPUTERNAME" -Color Gray
Write-Log "  User:      $env:USERNAME" -Color Gray
Write-Log "  Log File:  $LogPath" -Color Gray
Write-Log "  Timeout:   ${OperationTimeoutSeconds}s per operation" -Color Gray

Write-Json "Machine" $env:COMPUTERNAME
Write-Json "User" $env:USERNAME
Write-Json "Timestamp" (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
Write-Json "OperationTimeoutSeconds" $OperationTimeoutSeconds

# --- Winget Availability ---
Write-SubSection "Winget Installation Check"

if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
    Write-StatusLine "FAIL" "Winget is not installed or not available in PATH"
    Write-Json "WingetAvailable" $false
    Write-Log ""
    Write-Log "CRITICAL: Cannot proceed without Winget. Please install App Installer from Microsoft Store." -Color Red
    return
} else {
    try {
        $wingetVersion = (winget --version 2>$null) -replace 'v', ''
        Write-StatusLine "PASS" "Winget is available" "Version: $wingetVersion"
        Write-Json "WingetAvailable" $true
        Write-Json "WingetVersion" $wingetVersion
    } catch {
        Write-StatusLine "PASS" "Winget is available" "Version: Unknown"
        Write-Json "WingetAvailable" $true
    }
}

# --- Registry Checks ---
Write-SubSection "Registry Policy Checks"

function Check-RegistryValue {
    param (
        [string]$Hive,
        [string]$Path,
        [string]$Name,
        [string]$Description
    )

    $fullPath = "${Hive}:\$Path"

    try {
        if (Test-Path $fullPath) {
            $value = Get-ItemProperty -Path $fullPath -ErrorAction Stop | Select-Object -ExpandProperty $Name -ErrorAction SilentlyContinue
            if ($null -ne $value) {
                $displayValue = if ($value -is [int]) { $value } else { "'$value'" }
                
                # Check for problematic values
                if ($Name -eq "RemoveWindowsStore" -and $value -eq 1) {
                    Write-StatusLine "WARN" "$Description is ENABLED (Value: $displayValue)" "This blocks Store UI and prevents Winget downloads. Consider using RequirePrivateStoreOnly instead."
                } elseif ($Name -eq "DisableStoreApps" -and $value -eq 1) {
                    Write-StatusLine "WARN" "$Description is ENABLED (Value: $displayValue)" "This may prevent Store apps from running."
                } elseif ($Name -eq "ProxyEnable" -and $value -eq 1) {
                    Write-StatusLine "INFO" "$Description is ENABLED (Value: $displayValue)"
                } else {
                    Write-StatusLine "INFO" "$Description is SET (Value: $displayValue)"
                }
                
                Write-Json "$Hive\$Path\$Name" $value
            } else {
                Write-StatusLine "INFO" "${Description}: Not configured"
            }
        } else {
            Write-StatusLine "INFO" "${Description}: Registry path does not exist"
        }
    } catch {
        Write-StatusLine "WARN" "${Description}: Failed to read" $_.Exception.Message
    }
}

$registryChecks = @(
    @{ Hive = "HKLM"; Path = "SOFTWARE\Policies\Microsoft\WindowsStore"; Name = "DisableStoreApps"; Description = "Store Apps Disabled (HKLM)" },
    @{ Hive = "HKCU"; Path = "Software\Policies\Microsoft\WindowsStore"; Name = "DisableStoreApps"; Description = "Store Apps Disabled (HKCU)" },
    @{ Hive = "HKLM"; Path = "SOFTWARE\Policies\Microsoft\WindowsStore"; Name = "RemoveWindowsStore"; Description = "Remove Windows Store (HKLM)" },
    @{ Hive = "HKCU"; Path = "Software\Policies\Microsoft\WindowsStore"; Name = "RemoveWindowsStore"; Description = "Remove Windows Store (HKCU)" },
    @{ Hive = "HKLM"; Path = "SOFTWARE\Policies\Microsoft\WindowsStore"; Name = "RequirePrivateStoreOnly"; Description = "Require Private Store Only" },
    @{ Hive = "HKLM"; Path = "SOFTWARE\Policies\Microsoft\Windows\Explorer"; Name = "NoUseStoreOpenWith"; Description = "Disable Store in Open With" },
    @{ Hive = "HKLM"; Path = "SOFTWARE\Policies\Microsoft\Windows\DataCollection"; Name = "AllowTelemetry"; Description = "Telemetry Level" },
    @{ Hive = "HKLM"; Path = "SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet"; Name = "EnableActiveProbing"; Description = "Network Connectivity Probing" },
    @{ Hive = "HKLM"; Path = "SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"; Name = "DoNotConnectToWindowsUpdateInternetLocations"; Description = "Block Windows Update Internet" },
    @{ Hive = "HKLM"; Path = "SOFTWARE\Policies\Microsoft\Windows\Appx"; Name = "AllowAllTrustedApps"; Description = "Allow All Trusted Apps" },
    @{ Hive = "HKCU"; Path = "Software\Microsoft\Windows\CurrentVersion\Internet Settings"; Name = "ProxyEnable"; Description = "Proxy Enabled" },
    @{ Hive = "HKCU"; Path = "Software\Microsoft\Windows\CurrentVersion\Internet Settings"; Name = "ProxyServer"; Description = "Proxy Server" }
)

foreach ($check in $registryChecks) {
    Check-RegistryValue -Hive $check.Hive -Path $check.Path -Name $check.Name -Description $check.Description
}

# --- Proxy Detection ---
Write-SubSection "System Proxy Configuration"

try {
    $proxy = [System.Net.WebRequest]::GetSystemWebProxy().GetProxy("https://www.microsoft.com")
    if ($proxy.AbsoluteUri -ne "https://www.microsoft.com/") {
        Write-StatusLine "INFO" "System proxy detected" "Proxy: $($proxy.AbsoluteUri)"
        Write-Json "Proxy" $proxy.AbsoluteUri
    } else {
        Write-StatusLine "INFO" "No system proxy configured"
        Write-Json "Proxy" "None"
    }
} catch {
    Write-StatusLine "WARN" "Proxy check failed" $_.Exception.Message
}

# --- TLS/SSL Connectivity ---
Write-SubSection "HTTPS Connectivity Test"

$responseResult = Invoke-WithTimeout -ScriptBlock {
    param($timeoutSec)
    Invoke-WebRequest -Uri "https://www.microsoft.com" -UseBasicParsing -TimeoutSec $timeoutSec
} -ArgumentList @($OperationTimeoutSeconds) -TimeoutSeconds $OperationTimeoutSeconds

if ($responseResult.TimedOut) {
    Write-StatusLine "FAIL" "HTTPS request to microsoft.com timed out" "Timeout: ${OperationTimeoutSeconds}s"
    Write-Json "TLSConnectivity" "Timeout"
} elseif ($responseResult.Error) {
    $classification = Classify-NetworkError -Exception $responseResult.Error.Exception
    Write-StatusLine "FAIL" "HTTPS request to microsoft.com failed" "Error: $classification"
    Write-Json "TLSConnectivity" "Failed: $classification"
} else {
    $response = $responseResult.Data
    if ($response.StatusCode -eq 200) {
        Write-StatusLine "PASS" "HTTPS connectivity successful" "Status: 200 OK"
        Write-Json "TLSConnectivity" "Success"
    } else {
        Write-StatusLine "WARN" "HTTPS request returned unexpected status" "Status: $($response.StatusCode)"
        Write-Json "TLSConnectivity" "UnexpectedStatus: $($response.StatusCode)"
    }
}

# --- Network Connectivity ---
Write-SubSection "Network Endpoint Connectivity"
Write-Log "  Testing connectivity to Microsoft services (TCP:443)..." -Color Gray
Write-Log "  Note: Some endpoints may block direct TCP probes - this is normal." -Color DarkGray
Write-Log ""

function Test-Endpoint {
    param (
        [string]$Name,
        [string]$ComputerName,
        [int]$Port = 443
    )

    $result = Invoke-WithTimeout -ScriptBlock {
        param($host,$port)
        Test-NetConnection -ComputerName $host -Port $port -WarningAction SilentlyContinue
    } -ArgumentList @($ComputerName,$Port) -TimeoutSeconds $OperationTimeoutSeconds

    if ($result.TimedOut) {
        Write-StatusLine "WARN" "$Name ($ComputerName)" "Timeout (${OperationTimeoutSeconds}s) - endpoint may block probes"
        Write-Json "Connectivity_$Name" "Timeout"
        return
    }

    if ($result.Error) {
        $classification = Classify-NetworkError -Exception $result.Error.Exception
        Write-StatusLine "WARN" "$Name ($ComputerName)" "Error: $classification"
        Write-Json "Connectivity_$Name" "Error: $classification"
        return
    }

    $tnc = $result.Data
    if ($tnc -and $tnc.TcpTestSucceeded) {
        Write-StatusLine "PASS" "$Name ($ComputerName)" "Connected"
        Write-Json "Connectivity_$Name" "Success"
    } else {
        Write-StatusLine "WARN" "$Name ($ComputerName)" "Could not verify (endpoint may block TCP probes)"
        Write-Json "Connectivity_$Name" "Unverified"
    }
}

$networkTargets = @(
    # Core Services
    @{ Name = "Microsoft.com"; Host = "www.microsoft.com" },
    @{ Name = "Live Login"; Host = "login.live.com" },
    @{ Name = "Azure AD Auth"; Host = "login.microsoftonline.com" },
    
    # Winget
    @{ Name = "Winget CDN"; Host = "winget-cdn.azureedge.net" },
    @{ Name = "Widget CDN"; Host = "widgetcdn.azureedge.net" },
    @{ Name = "App Installer CDN"; Host = "prod-azurecdn-akamai-iris.azureedge.net" },
    
    # Store
    @{ Name = "Store Edge"; Host = "storeedgefd.dsx.mp.microsoft.com" },
    @{ Name = "Store Tile Service"; Host = "livetileedge.dsx.mp.microsoft.com" },
    @{ Name = "Store Catalog"; Host = "storecatalogrevocation.storequality.microsoft.com" },
    @{ Name = "Display Catalog"; Host = "displaycatalog.mp.microsoft.com" },
    
    # Windows Update
    @{ Name = "Windows Update"; Host = "windowsupdate.microsoft.com" },
    @{ Name = "WU Download"; Host = "download.windowsupdate.com" },
    @{ Name = "Delivery Optimization"; Host = "dl.delivery.mp.microsoft.com" },
    
    # Other
    @{ Name = "Licensing"; Host = "licensing.mp.microsoft.com" },
    @{ Name = "Push Notifications"; Host = "wns.windows.com" },
    @{ Name = "NCSI Test"; Host = "www.msftconnecttest.com" }
)

foreach ($target in $networkTargets) {
    Test-Endpoint -Name $target.Name -ComputerName $target.Host
}

# --- Winget Source Check ---
Write-SubSection "Winget Source Configuration"

$sourcesResult = Invoke-WithTimeout -ScriptBlock { winget source list 2>&1 } -TimeoutSeconds $OperationTimeoutSeconds

if ($sourcesResult.TimedOut) {
    Write-StatusLine "FAIL" "Winget source list timed out" "Timeout: ${OperationTimeoutSeconds}s"
    Write-Json "WingetSources" "Timeout"
} elseif ($sourcesResult.Error) {
    $classification = Classify-NetworkError -Exception $sourcesResult.Error.Exception
    Write-StatusLine "FAIL" "Winget source list failed" "Error: $classification"
    Write-Json "WingetSources" "Failed: $classification"
} else {
    $sources = $sourcesResult.Data
    if ($sources -match "Name\s+Arg") {
        Write-StatusLine "PASS" "Winget sources configured successfully"
        Write-Log "  Sources:" -Color DarkGray
        $sources | Where-Object { $_ -match '\S' } | ForEach-Object { 
            Write-Log "    $_" -Color Gray
        }
        Write-Json "WingetSources" $sources
    } else {
        Write-StatusLine "WARN" "Winget source list returned unexpected output"
        Write-Json "WingetSources" $sources
    }
}

# --- Winget Search Test ---
Write-SubSection "Winget Package Search Test"

$wingetTests = @(
    @{ Id = "9MSMLRH6LZF3"; Name = "Microsoft.WindowsTerminal" },
    @{ Id = "7zip"; Name = "7-Zip" }
)

foreach ($pkg in $wingetTests) {
    $searchResult = Invoke-WithTimeout -ScriptBlock {
        param($name)
        winget search $name 2>&1
    } -ArgumentList @($pkg.Id) -TimeoutSeconds $OperationTimeoutSeconds

    if ($searchResult.TimedOut) {
        Write-StatusLine "WARN" "Search for '$($pkg.Name)' timed out" "Package: $($pkg.Id)"
        Write-Json "WingetSearch_$($pkg.Id)" "Timeout"
        continue
    } elseif ($searchResult.Error) {
        $classification = Classify-NetworkError -Exception $searchResult.Error.Exception
        Write-StatusLine "FAIL" "Search for '$($pkg.Name)' failed" "Error: $classification"
        Write-Json "WingetSearch_$($pkg.Id)" "Failed: $classification"
        continue
    }

    $wingetSearch = $searchResult.Data | ForEach-Object {
        [System.Text.Encoding]::UTF8.GetString([System.Text.Encoding]::Default.GetBytes($_))
    } | Where-Object { $_ -notmatch "^[\|\\\/\-\s]+$" }

    if ($wingetSearch -match "No package found") {
        Write-StatusLine "WARN" "Search for '$($pkg.Name)' returned no results" "Package: $($pkg.Id)"
        Write-Json "WingetSearch_$($pkg.Id)" "NotFound"
    } elseif ($wingetSearch.Count -gt 0) {
        Write-StatusLine "PASS" "Search for '$($pkg.Name)' successful" "Found $($wingetSearch.Count) lines of results"
        Write-Json "WingetSearch_$($pkg.Id)" $wingetSearch
    } else {
        Write-StatusLine "WARN" "Search for '$($pkg.Name)' returned no output"
        Write-Json "WingetSearch_$($pkg.Id)" "NoOutput"
    }
}

# --- Store App Check ---
Write-SubSection "Microsoft Store Application Status"

$storeAppResult = Invoke-WithTimeout -ScriptBlock { 
    Get-AppxPackage Microsoft.WindowsStore 
} -TimeoutSeconds $OperationTimeoutSeconds

if ($storeAppResult.TimedOut) {
    Write-StatusLine "WARN" "Store app check timed out" "Timeout: ${OperationTimeoutSeconds}s"
    Write-Json "StoreAppInstalled" "Timeout"
} elseif ($storeAppResult.Error) {
    Write-StatusLine "FAIL" "Store app check failed" $storeAppResult.Message
    Write-Json "StoreAppInstalled" "Error"
} else {
    $storeApp = $storeAppResult.Data
    if ($storeApp) {
        Write-StatusLine "PASS" "Microsoft Store app is installed" "Version: $($storeApp.Version)"
        Write-Json "StoreAppInstalled" $true
        Write-Json "StoreAppVersion" $storeApp.Version
    } else {
        Write-StatusLine "WARN" "Microsoft Store app not found"
        Write-Json "StoreAppInstalled" $false
    }
}

$provResult = Invoke-WithTimeout -ScriptBlock {
    Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like "*Store*"
} -TimeoutSeconds $OperationTimeoutSeconds

if ($provResult.TimedOut) {
    Write-StatusLine "WARN" "Provisioned package check timed out"
    Write-Json "ProvisionedStoreApps" "Timeout"
} elseif ($provResult.Error) {
    Write-StatusLine "FAIL" "Provisioned package check failed" $provResult.Message
} else {
    $provisioned = $provResult.Data
    if ($provisioned) {
        Write-StatusLine "PASS" "Provisioned Store apps found" "Count: $($provisioned.Count)"
        Write-Json "ProvisionedStoreApps" $provisioned.Count
    } else {
        Write-StatusLine "INFO" "No provisioned Store apps found"
        Write-Json "ProvisionedStoreApps" 0
    }
}

# --- Group Policy Report ---
Write-SubSection "Group Policy Export"

$gpReportPath = Join-Path -Path $PSScriptRoot -ChildPath "GPReport.html"
$gpResult = Invoke-WithTimeout -ScriptBlock {
    param($path)
    gpresult /h $path /f 2>&1
} -ArgumentList @($gpReportPath) -TimeoutSeconds $OperationTimeoutSeconds

if ($gpResult.TimedOut) {
    Write-StatusLine "WARN" "Group Policy report generation timed out"
} elseif ($gpResult.Error) {
    Write-StatusLine "WARN" "Group Policy report generation failed" $gpResult.Message
} else {
    if (Test-Path -Path $gpReportPath) {
        Write-StatusLine "PASS" "Group Policy report generated" "File: GPReport.html"
    } else {
        Write-StatusLine "WARN" "Group Policy report completed but file not found"
    }
}

# ============================================================================
# SUMMARY & RECOMMENDATIONS
# ============================================================================

Write-SectionHeader "Diagnostic Summary & Recommendations"

Write-Log ""
Write-Log "  Test Results:" -Color Cyan
Write-Log "    Passed:   $script:PassCount" -Color Green
Write-Log "    Warnings: $script:WarnCount" -Color Yellow
Write-Log "    Failed:   $script:FailCount" -Color Red

# Analyze issues and provide recommendations
$recommendations = @()

try {
    $logContent = Get-Content $LogPath -ErrorAction Stop
} catch {
    Write-StatusLine "WARN" "Unable to read log for detailed analysis"
    $logContent = @()
}

# Check for specific issues
$hasRemoveStorePolicy = $logContent -match "Remove Windows Store.*ENABLED"
$hasDNSFailures = $logContent -match "DNS name resolution failure"
$hasTLSFailures = $logContent -match "TLS/SSL|certificate"
$hasProxyIssues = $logContent -match "Proxy"
$hasWingetSourceFail = $logContent -match "Winget source list failed"
$hasWingetSearchFail = $logContent -match "Search for.*failed"

if ($hasRemoveStorePolicy) {
    $recommendations += @{
        Priority = "HIGH"
        Issue = "Windows Store is disabled via Group Policy"
        Solution = "Change 'RemoveWindowsStore' to 'RequirePrivateStoreOnly' if you want to block UI but allow Winget"
    }
}

if ($hasDNSFailures) {
    $recommendations += @{
        Priority = "HIGH"
        Issue = "DNS resolution failures detected"
        Solution = "Check DNS server configuration and firewall rules. Ensure DNS can resolve *.microsoft.com domains"
    }
}

if ($hasTLSFailures) {
    $recommendations += @{
        Priority = "HIGH"
        Issue = "TLS/SSL connection failures detected"
        Solution = "Verify certificate trust chain. Check if corporate proxy is performing SSL inspection. Review TLS settings"
    }
}

if ($hasWingetSourceFail -or $hasWingetSearchFail) {
    $recommendations += @{
        Priority = "MEDIUM"
        Issue = "Winget cannot access package sources"
        Solution = "Run 'winget source reset --force' to reset sources. Verify network connectivity to CDN endpoints"
    }
}

if ($hasProxyIssues) {
    $recommendations += @{
        Priority = "MEDIUM"
        Issue = "Proxy configuration detected"
        Solution = "Verify proxy settings allow access to Microsoft domains. Check proxy authentication if required"
    }
}

if ($script:FailCount -eq 0 -and $script:WarnCount -eq 0) {
    Write-Log ""
    Write-Log "  All checks passed successfully!" -Color Green
    Write-Log "  Your system appears to be properly configured for Microsoft Store and Winget." -Color Green
} elseif ($recommendations.Count -gt 0) {
    Write-Log ""
    Write-Log "  Recommendations:" -Color Yellow
    Write-Log ""
    
    $highPriority = $recommendations | Where-Object { $_.Priority -eq "HIGH" }
    $mediumPriority = $recommendations | Where-Object { $_.Priority -eq "MEDIUM" }
    
    if ($highPriority) {
        Write-Log "  HIGH PRIORITY:" -Color Red
        foreach ($rec in $highPriority) {
            Write-Log "    • Issue:    $($rec.Issue)" -Color Yellow
            Write-Log "      Solution: $($rec.Solution)" -Color White
            Write-Log ""
        }
    }
    
    if ($mediumPriority) {
        Write-Log "  MEDIUM PRIORITY:" -Color Yellow
        foreach ($rec in $mediumPriority) {
            Write-Log "    • Issue:    $($rec.Issue)" -Color Yellow
            Write-Log "      Solution: $($rec.Solution)" -Color White
            Write-Log ""
        }
    }
}

# --- JSON Output ---
if ($JsonOutput) {
    try {
        $JsonPath = $LogPath.Replace(".log", ".json")
        $global:JsonData["Summary"] = @{
            Passed = $script:PassCount
            Warnings = $script:WarnCount
            Failed = $script:FailCount
            Recommendations = $recommendations
        }
        $global:JsonData | ConvertTo-Json -Depth 5 | Out-File -FilePath $JsonPath -Encoding UTF8
        Write-Log ""
        Write-StatusLine "PASS" "JSON output saved" "File: $(Split-Path -Leaf $JsonPath)"
    } catch {
        Write-StatusLine "FAIL" "Failed to write JSON output" $_.Exception.Message
    }
}

# Footer
Write-Log ""
Write-Log ("=" * 80) -Color Cyan
Write-Log "  Log file saved to: $LogPath" -Color Cyan
Write-Log ("=" * 80) -Color Cyan
Write-Log ""
