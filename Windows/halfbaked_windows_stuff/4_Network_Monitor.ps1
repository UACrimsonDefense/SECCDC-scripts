#Requires -RunAsAdministrator
<#
.SYNOPSIS
    CCDC Network Connection Monitor
.DESCRIPTION
    Real-time network monitoring to detect suspicious connections and C2 traffic
    Alerts displayed immediately to console AND logged to file
.NOTES
    Run this continuously during competition
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$LogPath = "C:\CCDC_Logs",
    
    [Parameter(Mandatory=$false)]
    [int]$MonitorSeconds = 300,
    
    [Parameter(Mandatory=$false)]
    [switch]$ContinuousMode,
    
    [Parameter(Mandatory=$false)]
    [string[]]$WhitelistedIPs = @()
)

$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$ReportFile = "$LogPath\NetworkMonitor_$Timestamp.txt"

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

# REAL-TIME ALERT FUNCTION - Console + File
function Write-Alert {
    param([string]$Message, [string]$Level = "CRITICAL")
    
    # Write to file
    $output = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [ALERT] [$Level] $Message"
    Add-Content -Path $ReportFile -Value $output
    
    # Write to console with visual separation
    $color = switch($Level) {
        "CRITICAL" { "Red" }
        "WARNING" { "Yellow" }
        default { "Magenta" }
    }
    
    Write-Host ""
    Write-Host "*** ALERT *** " -ForegroundColor $color -NoNewline
    Write-Host $Message -ForegroundColor $color
    
    # Optionally beep for critical alerts
    if ($Level -eq "CRITICAL") {
        [Console]::Beep(1000, 200)
    }
}

function Get-ProcessOwner {
    param([int]$ProcessId)
    try {
        $process = Get-WmiObject -Class Win32_Process -Filter "ProcessId=$ProcessId"
        if ($process) {
            $owner = $process.GetOwner()
            return "$($owner.Domain)\$($owner.User)"
        }
    } catch {
        return "Unknown"
    }
    return "Unknown"
}

Write-Host "============================================" -ForegroundColor Cyan
Write-Host "CCDC Network Connection Monitor" -ForegroundColor Cyan
Write-Host "Real-time alerts enabled" -ForegroundColor Yellow
Write-Host "============================================" -ForegroundColor Cyan

# ============================================
# 1. BASELINE NETWORK STATE
# ============================================
Write-Host "`n[1] Creating network baseline..." -ForegroundColor Yellow

$baselineConnections = Get-NetTCPConnection
$baselineConnections | Export-Csv "$LogPath\NetworkBaseline_$Timestamp.csv" -NoTypeInformation

Write-Report "Baseline connections: $($baselineConnections.Count)"

# Known good services and their ports
$knownGoodPorts = @{
    53 = 'DNS'
    80 = 'HTTP'
    443 = 'HTTPS'
    88 = 'Kerberos'
    135 = 'RPC'
    139 = 'NetBIOS'
    389 = 'LDAP'
    445 = 'SMB'
    636 = 'LDAPS'
    3389 = 'RDP'
    5985 = 'WinRM-HTTP'
    5986 = 'WinRM-HTTPS'
}

# Private IP ranges (RFC 1918)
$privateRanges = @(
    '10.',
    '172.16.', '172.17.', '172.18.', '172.19.', '172.20.', '172.21.', '172.22.', '172.23.',
    '172.24.', '172.25.', '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.',
    '192.168.',
    '127.',
    '169.254.'
)

function Test-PrivateIP {
    param([string]$IP)
    foreach ($range in $privateRanges) {
        if ($IP.StartsWith($range)) {
            return $true
        }
    }
    return $false
}

# ============================================
# 2. MONITORING LOOP
# ============================================
$startTime = Get-Date
$alertedConnections = @{}
$scanCounter = 0

Write-Host "`n[*] Starting real-time monitoring..." -ForegroundColor Green
Write-Host "[*] Whitelisted IPs: $($WhitelistedIPs -join ', ')" -ForegroundColor Cyan
if ($ContinuousMode) {
    Write-Host "[*] Running in CONTINUOUS mode (Ctrl+C to stop)" -ForegroundColor Yellow
} else {
    Write-Host "[*] Will run for $MonitorSeconds seconds" -ForegroundColor Yellow
}
Write-Host ""

do {
    $scanCounter++
    $scanTime = Get-Date
    Write-Host "[Scan #$scanCounter @ $(Get-Date -Format 'HH:mm:ss')]" -ForegroundColor Cyan -NoNewline
    
    # Get current connections
    $currentConnections = Get-NetTCPConnection | Where-Object {$_.State -eq 'Established'}
    
    $newAlertsThisScan = 0
    
    foreach ($conn in $currentConnections) {
        # Skip localhost and same-subnet connections
        if ($conn.RemoteAddress -eq '127.0.0.1' -or $conn.RemoteAddress -eq '::1') {
            continue
        }
        
        # Create unique connection ID
        $connId = "$($conn.LocalAddress):$($conn.LocalPort)-$($conn.RemoteAddress):$($conn.RemotePort)-$($conn.OwningProcess)"
        
        # Skip if already alerted
        if ($alertedConnections.ContainsKey($connId)) {
            continue
        }
        
        # Get process info
        $process = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
        $processPath = if ($process) { $process.Path } else { "Unknown" }
        $processName = if ($process) { $process.Name } else { "Unknown" }
        $owner = Get-ProcessOwner -ProcessId $conn.OwningProcess
        
        $flags = @()
        $alertLevel = "WARNING"
        
        # Check for suspicious indicators
        
        # 1. Non-standard ports for common processes
        if ($processName -match "^(powershell|cmd|wscript|cscript|mshta|regsvr32)$") {
            $flags += "Scripting process with network connection"
            $alertLevel = "CRITICAL"
        }
        
        # 2. Outbound connections to public IPs on non-standard ports
        $isPrivate = Test-PrivateIP -IP $conn.RemoteAddress
        if (-not $isPrivate -and $conn.RemotePort -notin $knownGoodPorts.Keys) {
            $flags += "Public IP on non-standard port ($($conn.RemotePort))"
        }
        
        # 3. Processes running from suspicious locations
        if ($processPath -match "temp|appdata|downloads|public|programdata") {
            $flags += "Process running from suspicious location"
            $alertLevel = "CRITICAL"
        }
        
        # 4. Check for reverse shell indicators (common C2 ports)
        $c2Ports = @(4444, 4445, 8080, 8443, 9001, 9090, 1337, 31337, 12345)
        if ($conn.RemotePort -in $c2Ports) {
            $flags += "CRITICAL: Common C2/reverse shell port detected!"
            $alertLevel = "CRITICAL"
        }
        
        # 5. Connections to whitelisted IPs should not alert
        if ($WhitelistedIPs -contains $conn.RemoteAddress) {
            continue
        }
        
        # Alert if suspicious
        if ($flags.Count -gt 0) {
            $alertedConnections[$connId] = $true
            $newAlertsThisScan++
            
            # IMMEDIATE CONSOLE ALERT
            Write-Alert "SUSPICIOUS CONNECTION - $($conn.RemoteAddress):$($conn.RemotePort)" $alertLevel
            Write-Host "  Process: $processName (PID: $($conn.OwningProcess))" -ForegroundColor Yellow
            Write-Host "  Path: $processPath" -ForegroundColor Yellow
            Write-Host "  Local: $($conn.LocalAddress):$($conn.LocalPort)" -ForegroundColor Yellow
            Write-Host "  Remote: $($conn.RemoteAddress):$($conn.RemotePort)" -ForegroundColor Yellow
            Write-Host "  Owner: $owner" -ForegroundColor Yellow
            
            foreach ($flag in $flags) {
                Write-Host "  [!] $flag" -ForegroundColor Red
            }
            
            # Also write detailed log
            Write-Report "`n[!] SUSPICIOUS CONNECTION DETECTED" "CRITICAL"
            Write-Report "Time: $(Get-Date)" "CRITICAL"
            Write-Report "Local: $($conn.LocalAddress):$($conn.LocalPort)" "WARNING"
            Write-Report "Remote: $($conn.RemoteAddress):$($conn.RemotePort)" "WARNING"
            Write-Report "Process: $processName (PID: $($conn.OwningProcess))" "WARNING"
            Write-Report "Path: $processPath" "WARNING"
            Write-Report "Owner: $owner" "WARNING"
            Write-Report "State: $($conn.State)" "WARNING"
            
            foreach ($flag in $flags) {
                Write-Report "  [!] $flag" "CRITICAL"
            }
            
            # Log to CSV for analysis
            [PSCustomObject]@{
                Timestamp = Get-Date
                LocalAddr = $conn.LocalAddress
                LocalPort = $conn.LocalPort
                RemoteAddr = $conn.RemoteAddress
                RemotePort = $conn.RemotePort
                Process = $processName
                PID = $conn.OwningProcess
                Path = $processPath
                Owner = $owner
                Flags = ($flags -join "; ")
            } | Export-Csv "$LogPath\SuspiciousConnections_$Timestamp.csv" -Append -NoTypeInformation
        }
    }
    
    # Summary stats on same line
    $publicConnections = $currentConnections | Where-Object {
        -not (Test-PrivateIP -IP $_.RemoteAddress) -and 
        $_.RemoteAddress -ne '127.0.0.1' -and 
        $_.RemoteAddress -ne '::1'
    }
    
    $statusColor = if ($newAlertsThisScan -gt 0) { "Red" } else { "Green" }
    Write-Host " Connections: $($currentConnections.Count) | Public: $($publicConnections.Count) | New Alerts: $newAlertsThisScan | Total Alerts: $($alertedConnections.Count)" -ForegroundColor $statusColor
    
    if ($ContinuousMode) {
        Start-Sleep -Seconds 10
    } else {
        $elapsed = ((Get-Date) - $startTime).TotalSeconds
        if ($elapsed -lt $MonitorSeconds) {
            Start-Sleep -Seconds 10
        }
    }
    
} while ($ContinuousMode -or ((Get-Date) - $startTime).TotalSeconds -lt $MonitorSeconds)

# ============================================
# 3. FINAL REPORT
# ============================================
Write-Host "`n[3] Generating final report..." -ForegroundColor Yellow

Write-Report "`n=== FINAL NETWORK SUMMARY ==="
Write-Report "Monitoring Duration: $([math]::Round(((Get-Date) - $startTime).TotalMinutes, 2)) minutes"
Write-Report "Total Scans: $scanCounter"
Write-Report "Total Alerts: $($alertedConnections.Count)"

# Top talkers
Write-Report "`n=== TOP REMOTE IPs ==="
$currentConnections | Where-Object {$_.RemoteAddress -ne '127.0.0.1' -and $_.RemoteAddress -ne '::1'} |
    Group-Object RemoteAddress |
    Sort-Object Count -Descending |
    Select-Object -First 10 |
    ForEach-Object {
        Write-Report "$($_.Name): $($_.Count) connections"
    }

# Listening ports
Write-Report "`n=== LISTENING PORTS ==="
$listening = Get-NetTCPConnection | Where-Object {$_.State -eq 'Listen'}
foreach ($listener in $listening) {
    $process = Get-Process -Id $listener.OwningProcess -ErrorAction SilentlyContinue
    $serviceName = if ($knownGoodPorts.ContainsKey($listener.LocalPort)) {
        $knownGoodPorts[$listener.LocalPort]
    } else {
        "Unknown"
    }
    
    Write-Report "Port $($listener.LocalPort) - $serviceName - $($process.Name)"
}

Write-Host "`n============================================" -ForegroundColor Cyan
Write-Host "Network Monitoring Complete!" -ForegroundColor Green
Write-Host "Report: $ReportFile" -ForegroundColor Cyan
Write-Host "Suspicious Connections: $($alertedConnections.Count)" -ForegroundColor $(if($alertedConnections.Count -gt 0){"Red"}else{"Green"})
Write-Host "============================================" -ForegroundColor Cyan
