#Requires -RunAsAdministrator
<#
.SYNOPSIS
    CCDC Service Backdoor Detection & Hardening
.DESCRIPTION
    Detects suspicious services, checks for persistence mechanisms, and hardens critical services
.NOTES
    Critical for finding red team persistence
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$LogPath = "C:\CCDC_Logs",
    
    [Parameter(Mandatory=$false)]
    [switch]$StopSuspicious,
    
    [Parameter(Mandatory=$false)]
    [switch]$DisableSuspicious
)

$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$ReportFile = "$LogPath\ServiceAudit_$Timestamp.txt"

if (!(Test-Path $LogPath)) {
    New-Item -ItemType Directory -Path $LogPath -Force | Out-Null
}

function Write-Report {
    param([string]$Message, [string]$Level = "INFO")
    $output = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message"
    Add-Content -Path $ReportFile -Value $output
    
    $color = switch($Level) {
        "CRITICAL" { "Red" }
        "WARNING" { "Yellow" }
        "SUCCESS" { "Green" }
        default { "White" }
    }
    Write-Host $output -ForegroundColor $color
}

Write-Host "============================================" -ForegroundColor Cyan
Write-Host "CCDC Service Backdoor Detection" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan

# ============================================
# 1. ENUMERATE ALL SERVICES
# ============================================
Write-Host "`n[1] Enumerating all services..." -ForegroundColor Yellow

$allServices = Get-Service
$runningServices = $allServices | Where-Object {$_.Status -eq 'Running'}

Write-Report "Total Services: $($allServices.Count)"
Write-Report "Running Services: $($runningServices.Count)"

# Get detailed service info
$serviceDetails = Get-WmiObject -Class Win32_Service | Select-Object Name, DisplayName, PathName, StartMode, StartName, State, ProcessId

# Export baseline
$serviceDetails | Export-Csv "$LogPath\ServiceBaseline_$Timestamp.csv" -NoTypeInformation

# ============================================
# 2. DETECT SUSPICIOUS SERVICES
# ============================================
Write-Host "`n[2] Detecting suspicious services..." -ForegroundColor Yellow

Write-Report "`n=== SUSPICIOUS SERVICE DETECTION ==="

$suspiciousServices = @()

foreach ($service in $serviceDetails) {
    $flags = @()
    
    # Check for suspicious paths
    if ($service.PathName -match "temp|downloads|appdata|users\\public|programdata|recycler") {
        $flags += "Suspicious path location"
    }
    
    # Check for encoded commands
    if ($service.PathName -match "powershell.*-enc|-e |-nop|-w hidden") {
        $flags += "Encoded/hidden PowerShell command"
    }
    
    # Check for common backdoor names
    if ($service.Name -match "updateservice|windefend[0-9]|svchos[t]|csrss[0-9]|lsas[s]|smss[0-9]") {
        $flags += "Suspicious service name (typosquatting)"
    }
    
    # Check for non-standard paths
    if ($service.PathName -notmatch "^C:\\Windows\\|^C:\\Program Files|^\"C:\\Windows\\|^\"C:\\Program Files") {
        if ($service.PathName -and $service.PathName -ne "") {
            $flags += "Non-standard installation path"
        }
    }
    
    # Check for user context services (non-SYSTEM/LocalService/NetworkService)
    if ($service.StartName -and 
        $service.StartName -notmatch "LocalSystem|NT AUTHORITY|LocalService|NetworkService" -and
        $service.StartName -ne "NULL") {
        $flags += "Running under user account: $($service.StartName)"
    }
    
    # Check for services with no display name or description
    if ([string]::IsNullOrWhiteSpace($service.DisplayName)) {
        $flags += "Missing display name"
    }
    
    if ($flags.Count -gt 0) {
        $suspiciousServices += [PSCustomObject]@{
            Name = $service.Name
            DisplayName = $service.DisplayName
            Path = $service.PathName
            StartMode = $service.StartMode
            State = $service.State
            StartName = $service.StartName
            PID = $service.ProcessId
            Flags = $flags -join "; "
        }
        
        Write-Report "`n[!] SUSPICIOUS: $($service.Name)" "CRITICAL"
        Write-Report "    Display Name: $($service.DisplayName)"
        Write-Report "    Path: $($service.PathName)" "WARNING"
        Write-Report "    Start Mode: $($service.StartMode)"
        Write-Report "    Running As: $($service.StartName)"
        Write-Report "    State: $($service.State)"
        Write-Report "    PID: $($service.ProcessId)"
        foreach ($flag in $flags) {
            Write-Report "    [!] $flag" "CRITICAL"
        }
    }
}

# Export suspicious services
if ($suspiciousServices.Count -gt 0) {
    $suspiciousServices | Export-Csv "$LogPath\SuspiciousServices_$Timestamp.csv" -NoTypeInformation
    Write-Report "`nFound $($suspiciousServices.Count) suspicious services!" "CRITICAL"
} else {
    Write-Report "`nNo obviously suspicious services detected" "SUCCESS"
}

# ============================================
# 3. CHECK CRITICAL SERVICES
# ============================================
Write-Host "`n[3] Checking critical CCDC services..." -ForegroundColor Yellow

Write-Report "`n=== CRITICAL SERVICE STATUS ==="

$criticalServices = @{
    'DNS' = 'DNS Server'
    'W3SVC' = 'World Wide Web Publishing Service'
    'NTDS' = 'Active Directory Domain Services'
    'Netlogon' = 'Netlogon'
    'ADWS' = 'Active Directory Web Services'
    'DFS' = 'DFS Namespace'
    'DFSR' = 'DFS Replication'
    'Kdc' = 'Kerberos Key Distribution Center'
    'LanmanServer' = 'Server (SMB)'
    'WinRM' = 'Windows Remote Management'
    'TermService' = 'Remote Desktop Services'
    'SessionEnv' = 'Remote Desktop Configuration'
}

foreach ($svcName in $criticalServices.Keys) {
    $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
    if ($svc) {
        $detail = $serviceDetails | Where-Object {$_.Name -eq $svcName}
        
        Write-Report "`n$($criticalServices[$svcName]) ($svcName)"
        Write-Report "  Status: $($svc.Status)"
        Write-Report "  Startup Type: $($svc.StartType)"
        Write-Report "  Path: $($detail.PathName)"
        
        if ($svc.Status -ne 'Running') {
            Write-Report "  [!] WARNING: Critical service not running!" "WARNING"
        }
    } else {
        Write-Report "`n$($criticalServices[$svcName]) ($svcName)" "WARNING"
        Write-Report "  [!] Service not found (may not be installed on this system)" "WARNING"
    }
}

# ============================================
# 4. CHECK FOR UNQUOTED SERVICE PATHS
# ============================================
Write-Host "`n[4] Checking for unquoted service paths..." -ForegroundColor Yellow

Write-Report "`n=== UNQUOTED SERVICE PATH VULNERABILITY ==="

$unquotedServices = $serviceDetails | Where-Object {
    $_.PathName -and 
    $_.PathName -notmatch '^".*"' -and 
    $_.PathName -match ' ' -and
    $_.PathName -notmatch '^[A-Z]:\\Windows\\'
}

if ($unquotedServices) {
    Write-Report "Found $($unquotedServices.Count) services with unquoted paths!" "WARNING"
    foreach ($svc in $unquotedServices) {
        Write-Report "`n[!] $($svc.Name)" "WARNING"
        Write-Report "    Path: $($svc.PathName)"
    }
    $unquotedServices | Export-Csv "$LogPath\UnquotedServicePaths_$Timestamp.csv" -NoTypeInformation
} else {
    Write-Report "No unquoted service paths found" "SUCCESS"
}

# ============================================
# 5. CHECK SERVICE PERMISSIONS
# ============================================
Write-Host "`n[5] Checking for weak service permissions..." -ForegroundColor Yellow

Write-Report "`n=== WEAK SERVICE PERMISSIONS ==="

$weakPermissions = @()

foreach ($service in $serviceDetails | Where-Object {$_.State -eq 'Running'}) {
    try {
        $acl = sc.exe sdshow $service.Name 2>$null
        
        # Check for Everyone (WD) or Users (BU) with modify rights
        if ($acl -match "WD.*RP.*WP|BU.*RP.*WP") {
            $weakPermissions += $service
            Write-Report "[!] $($service.Name) - Potentially weak permissions" "WARNING"
        }
    } catch {
        # Silent fail
    }
}

if ($weakPermissions.Count -gt 0) {
    Write-Report "Found $($weakPermissions.Count) services with potentially weak permissions" "WARNING"
}

# ============================================
# 6. DETECT PERSISTENCE MECHANISMS
# ============================================
Write-Host "`n[6] Checking for service-based persistence..." -ForegroundColor Yellow

Write-Report "`n=== SERVICE PERSISTENCE DETECTION ==="

# Check for recently modified services
$recentServices = $serviceDetails | Where-Object {
    if ($_.PathName) {
        $path = $_.PathName -replace '"',''
        $path = ($path -split " ")[0]  # Get executable path
        if (Test-Path $path -ErrorAction SilentlyContinue) {
            $file = Get-Item $path -ErrorAction SilentlyContinue
            if ($file) {
                $age = (Get-Date) - $file.LastWriteTime
                return $age.TotalDays -lt 7
            }
        }
    }
    return $false
}

if ($recentServices) {
    Write-Report "Services with recently modified binaries (last 7 days):" "WARNING"
    foreach ($svc in $recentServices) {
        $path = $svc.PathName -replace '"',''
        $path = ($path -split " ")[0]
        $file = Get-Item $path -ErrorAction SilentlyContinue
        
        Write-Report "`n[!] $($svc.Name)" "WARNING"
        Write-Report "    Path: $path"
        Write-Report "    Last Modified: $($file.LastWriteTime)"
        Write-Report "    File Size: $($file.Length) bytes"
    }
}

# ============================================
# 7. OPTIONAL: STOP SUSPICIOUS SERVICES
# ============================================
if ($StopSuspicious -and $suspiciousServices.Count -gt 0) {
    Write-Host "`n[7] Stopping suspicious services..." -ForegroundColor Yellow
    Write-Report "`n=== STOPPING SUSPICIOUS SERVICES ==="
    
    foreach ($svc in $suspiciousServices) {
        if ($svc.State -eq 'Running') {
            $response = Read-Host "Stop service '$($svc.Name)'? (y/N)"
            if ($response -eq 'y' -or $response -eq 'Y') {
                try {
                    Stop-Service -Name $svc.Name -Force
                    Write-Report "STOPPED: $($svc.Name)" "SUCCESS"
                } catch {
                    Write-Report "Failed to stop $($svc.Name): $_" "WARNING"
                }
            }
        }
    }
}

# ============================================
# 8. OPTIONAL: DISABLE SUSPICIOUS SERVICES
# ============================================
if ($DisableSuspicious -and $suspiciousServices.Count -gt 0) {
    Write-Host "`n[8] Disabling suspicious services..." -ForegroundColor Yellow
    Write-Report "`n=== DISABLING SUSPICIOUS SERVICES ==="
    
    foreach ($svc in $suspiciousServices) {
        $response = Read-Host "Disable service '$($svc.Name)'? (y/N)"
        if ($response -eq 'y' -or $response -eq 'Y') {
            try {
                Set-Service -Name $svc.Name -StartupType Disabled
                Stop-Service -Name $svc.Name -Force -ErrorAction SilentlyContinue
                Write-Report "DISABLED: $($svc.Name)" "SUCCESS"
            } catch {
                Write-Report "Failed to disable $($svc.Name): $_" "WARNING"
            }
        }
    }
}

# ============================================
# 9. CREATE SERVICE MONITORING SCRIPT
# ============================================
Write-Host "`n[9] Creating service monitoring baseline..." -ForegroundColor Yellow

$baseline = @{
    Timestamp = Get-Date
    TotalServices = $allServices.Count
    RunningServices = $runningServices.Count
    SuspiciousCount = $suspiciousServices.Count
    Services = $serviceDetails
}

$baseline | ConvertTo-Json -Depth 3 | Out-File "$LogPath\ServiceBaseline_$Timestamp.json"
Write-Report "Service baseline saved" "SUCCESS"

# ============================================
# SUMMARY
# ============================================
Write-Host "`n============================================" -ForegroundColor Cyan
Write-Host "Service Audit Complete!" -ForegroundColor Green
Write-Host "Report: $ReportFile" -ForegroundColor Cyan
Write-Host "Suspicious Services: $($suspiciousServices.Count)" -ForegroundColor $(if($suspiciousServices.Count -gt 0){"Red"}else{"Green"})
Write-Host "============================================" -ForegroundColor Cyan
