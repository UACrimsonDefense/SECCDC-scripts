#Requires -RunAsAdministrator
<#
.SYNOPSIS
    CCDC Event Log Collector & Threat Hunter
.DESCRIPTION
    Collects and analyzes Windows event logs for signs of compromise
    Real-time alerts displayed to console AND logged to file
.NOTES
    Run periodically to catch attacks in progress
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$LogPath = "C:\CCDC_Logs",
    
    [Parameter(Mandatory=$false)]
    [int]$Hours = 1,
    
    [Parameter(Mandatory=$false)]
    [switch]$ExportAll
)

$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$ReportFile = "$LogPath\EventAnalysis_$Timestamp.txt"

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

# REAL-TIME ALERT FUNCTION
function Write-Alert {
    param([string]$Message, [string]$Details = "", [string]$Level = "CRITICAL")
    
    # Write to file
    $output = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [ALERT] [$Level] $Message"
    Add-Content -Path $ReportFile -Value $output
    if ($Details) {
        Add-Content -Path $ReportFile -Value "    $Details"
    }
    
    # Write to console with visual separation
    $color = switch($Level) {
        "CRITICAL" { "Red" }
        "WARNING" { "Yellow" }
        default { "Magenta" }
    }
    
    Write-Host ""
    Write-Host "*** ALERT *** " -ForegroundColor $color -NoNewline
    Write-Host $Message -ForegroundColor $color
    if ($Details) {
        Write-Host "    $Details" -ForegroundColor Yellow
    }
}

Write-Host "============================================" -ForegroundColor Cyan
Write-Host "CCDC Event Log Analysis & Threat Hunting" -ForegroundColor Cyan
Write-Host "Real-time alerts enabled" -ForegroundColor Yellow
Write-Host "============================================" -ForegroundColor Cyan

$startTime = (Get-Date).AddHours(-$Hours)

Write-Report "Analyzing events from last $Hours hour(s)"
Write-Report "Start Time: $startTime"

# ============================================
# 1. FAILED LOGON ATTEMPTS (Brute Force)
# ============================================
Write-Host "`n[1] Checking for failed logon attempts..." -ForegroundColor Yellow

Write-Report "`n=== FAILED LOGON ATTEMPTS (Event ID 4625) ==="

try {
    $failedLogons = Get-WinEvent -FilterHashtable @{
        LogName='Security'
        ID=4625
        StartTime=$startTime
    } -ErrorAction SilentlyContinue
    
    if ($failedLogons) {
        Write-Report "Found $($failedLogons.Count) failed logon attempts!" "WARNING"
        
        # Group by target account
        $groupedFailures = $failedLogons | ForEach-Object {
            $xml = [xml]$_.ToXml()
            [PSCustomObject]@{
                TimeCreated = $_.TimeCreated
                TargetUser = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'TargetUserName'} | Select-Object -ExpandProperty '#text'
                SourceIP = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'IpAddress'} | Select-Object -ExpandProperty '#text'
                FailureReason = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'SubStatus'} | Select-Object -ExpandProperty '#text'
            }
        } | Group-Object TargetUser | Sort-Object Count -Descending
        
        foreach ($group in $groupedFailures) {
            if ($group.Count -gt 5) {
                Write-Alert "BRUTE FORCE ATTEMPT - $($group.Count) failed logons for user: $($group.Name)" "" "CRITICAL"
                Write-Report "[!] $($group.Name): $($group.Count) failed attempts" "CRITICAL"
                $group.Group | Select-Object -First 5 | ForEach-Object {
                    $detail = "From: $($_.SourceIP) at $($_.TimeCreated)"
                    Write-Report "    $detail" "WARNING"
                    Write-Host "    $detail" -ForegroundColor Yellow
                }
            }
        }
        
        if ($ExportAll) {
            $failedLogons | Select-Object TimeCreated, Message | 
                Export-Csv "$LogPath\FailedLogons_$Timestamp.csv" -NoTypeInformation
        }
    } else {
        Write-Report "No failed logon attempts found" "SUCCESS"
    }
} catch {
    Write-Report "Error checking failed logons: $_" "WARNING"
}

# ============================================
# 2. SUCCESSFUL LOGONS (Lateral Movement)
# ============================================
Write-Host "`n[2] Checking successful logons..." -ForegroundColor Yellow

Write-Report "`n=== SUCCESSFUL LOGONS (Event ID 4624) ==="

try {
    $successLogons = Get-WinEvent -FilterHashtable @{
        LogName='Security'
        ID=4624
        StartTime=$startTime
    } -ErrorAction SilentlyContinue | Where-Object {
        # Filter for network logons (type 3) and RDP (type 10)
        $xml = [xml]$_.ToXml()
        $logonType = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'LogonType'} | Select-Object -ExpandProperty '#text'
        $logonType -in @('3','10')
    }
    
    if ($successLogons) {
        Write-Report "Found $($successLogons.Count) network/RDP logons" "WARNING"
        
        $logonDetails = $successLogons | ForEach-Object {
            $xml = [xml]$_.ToXml()
            [PSCustomObject]@{
                TimeCreated = $_.TimeCreated
                User = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'TargetUserName'} | Select-Object -ExpandProperty '#text'
                LogonType = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'LogonType'} | Select-Object -ExpandProperty '#text'
                SourceIP = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'IpAddress'} | Select-Object -ExpandProperty '#text'
                WorkstationName = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'WorkstationName'} | Select-Object -ExpandProperty '#text'
            }
        }
        
        # Group by user to find suspicious patterns
        $userLogons = $logonDetails | Group-Object User | Sort-Object Count -Descending
        
        foreach ($user in $userLogons | Select-Object -First 10) {
            Write-Report "`n$($user.Name): $($user.Count) logons"
            
            # Check for logons from multiple IPs (potential lateral movement)
            $uniqueIPs = $user.Group.SourceIP | Where-Object {$_ -and $_ -ne '-'} | Select-Object -Unique
            if ($uniqueIPs.Count -gt 3) {
                Write-Alert "LATERAL MOVEMENT - User $($user.Name) logged in from $($uniqueIPs.Count) different IPs!" "" "WARNING"
                Write-Report "  [!] WARNING: Logons from $($uniqueIPs.Count) different IPs!" "WARNING"
                $uniqueIPs | ForEach-Object {
                    Write-Report "    - $_" "WARNING"
                }
            }
        }
        
        if ($ExportAll) {
            $logonDetails | Export-Csv "$LogPath\NetworkLogons_$Timestamp.csv" -NoTypeInformation
        }
    }
} catch {
    Write-Report "Error checking successful logons: $_" "WARNING"
}

# ============================================
# 3. ACCOUNT MODIFICATIONS
# ============================================
Write-Host "`n[3] Checking account modifications..." -ForegroundColor Yellow

Write-Report "`n=== ACCOUNT MODIFICATIONS ==="

$accountEventIDs = @{
    4720 = 'User Account Created'
    4722 = 'User Account Enabled'
    4723 = 'User Password Change Attempted'
    4724 = 'Password Reset Attempted'
    4725 = 'User Account Disabled'
    4726 = 'User Account Deleted'
    4738 = 'User Account Changed'
    4732 = 'Member Added to Security-Enabled Local Group'
    4733 = 'Member Removed from Security-Enabled Local Group'
    4728 = 'Member Added to Security-Enabled Global Group'
    4729 = 'Member Removed from Security-Enabled Global Group'
}

foreach ($eventID in $accountEventIDs.Keys) {
    try {
        $events = Get-WinEvent -FilterHashtable @{
            LogName='Security'
            ID=$eventID
            StartTime=$startTime
        } -ErrorAction SilentlyContinue
        
        if ($events) {
            Write-Alert "$($accountEventIDs[$eventID]) - $($events.Count) occurrences" "" "WARNING"
            Write-Report "`n[!] $($accountEventIDs[$eventID]) (Event $eventID): $($events.Count) occurrences" "WARNING"
            
            $events | Select-Object -First 5 | ForEach-Object {
                $xml = [xml]$_.ToXml()
                $targetUser = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'TargetUserName'} | Select-Object -ExpandProperty '#text'
                $subjectUser = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'SubjectUserName'} | Select-Object -ExpandProperty '#text'
                
                $detail = "$($_.TimeCreated): $targetUser (by $subjectUser)"
                Write-Report "  $detail" "WARNING"
                Write-Host "  $detail" -ForegroundColor Yellow
            }
        }
    } catch {
        # Silent continue
    }
}

# ============================================
# 4. POWERSHELL EXECUTION
# ============================================
Write-Host "`n[4] Checking PowerShell execution..." -ForegroundColor Yellow

Write-Report "`n=== POWERSHELL SCRIPT BLOCK LOGGING ==="

try {
    $psEvents = Get-WinEvent -FilterHashtable @{
        LogName='Microsoft-Windows-PowerShell/Operational'
        ID=4104  # Script Block Logging
        StartTime=$startTime
    } -ErrorAction SilentlyContinue
    
    if ($psEvents) {
        Write-Report "Found $($psEvents.Count) PowerShell script block events" "WARNING"
        
        # Look for suspicious commands
        $suspiciousKeywords = @(
            'Invoke-Mimikatz',
            'Invoke-Expression.*Base64',
            'IEX.*downloadstring',
            'Net.WebClient',
            'DownloadString',
            'DownloadFile',
            'bypass',
            'hidden',
            'enc.*command',
            'nop.*command'
        )
        
        foreach ($event in $psEvents) {
            $scriptBlock = $event.Properties[2].Value
            
            foreach ($keyword in $suspiciousKeywords) {
                if ($scriptBlock -match $keyword) {
                    $snippet = $scriptBlock.Substring(0, [Math]::Min(200, $scriptBlock.Length))
                    Write-Alert "MALICIOUS POWERSHELL DETECTED - Pattern: $keyword" "Snippet: $snippet" "CRITICAL"
                    
                    Write-Report "`n[!] SUSPICIOUS PowerShell detected!" "CRITICAL"
                    Write-Report "Time: $($event.TimeCreated)" "CRITICAL"
                    Write-Report "Pattern: $keyword" "CRITICAL"
                    Write-Report "Script Block (truncated): $snippet" "WARNING"
                    break
                }
            }
        }
    }
} catch {
    Write-Report "PowerShell operational log not available or empty" "WARNING"
}

# ============================================
# 5. SERVICE INSTALLATION
# ============================================
Write-Host "`n[5] Checking for new service installations..." -ForegroundColor Yellow

Write-Report "`n=== NEW SERVICE INSTALLATIONS (Event ID 7045) ==="

try {
    $serviceEvents = Get-WinEvent -FilterHashtable @{
        LogName='System'
        ID=7045  # Service installed
        StartTime=$startTime
    } -ErrorAction SilentlyContinue
    
    if ($serviceEvents) {
        Write-Alert "NEW SERVICE INSTALLATIONS - $($serviceEvents.Count) services installed!" "" "WARNING"
        Write-Report "[!] Found $($serviceEvents.Count) new service installations!" "WARNING"
        
        foreach ($event in $serviceEvents) {
            $xml = [xml]$event.ToXml()
            $serviceName = $xml.Event.EventData.Data[0]
            $serviceImagePath = $xml.Event.EventData.Data[1]
            
            Write-Report "`n[!] Service: $serviceName" "WARNING"
            Write-Report "    Time: $($event.TimeCreated)" "WARNING"
            Write-Report "    Path: $serviceImagePath" "WARNING"
            
            Write-Host "  Service: $serviceName" -ForegroundColor Yellow
            Write-Host "  Path: $serviceImagePath" -ForegroundColor Yellow
            
            # Check for suspicious paths
            if ($serviceImagePath -match "temp|appdata|users\\public|downloads") {
                Write-Alert "SUSPICIOUS SERVICE PATH - $serviceName in temp/appdata location!" "Path: $serviceImagePath" "CRITICAL"
                Write-Report "    [!] CRITICAL: Suspicious installation path!" "CRITICAL"
            }
        }
    } else {
        Write-Report "No new services installed" "SUCCESS"
    }
} catch {
    Write-Report "Error checking service events: $_" "WARNING"
}

# ============================================
# 6. SCHEDULED TASK CREATION
# ============================================
Write-Host "`n[6] Checking for scheduled task creation..." -ForegroundColor Yellow

Write-Report "`n=== SCHEDULED TASK CREATION (Event ID 4698) ==="

try {
    $taskEvents = Get-WinEvent -FilterHashtable @{
        LogName='Security'
        ID=4698  # Scheduled task created
        StartTime=$startTime
    } -ErrorAction SilentlyContinue
    
    if ($taskEvents) {
        Write-Alert "SCHEDULED TASKS CREATED - $($taskEvents.Count) new tasks!" "" "WARNING"
        Write-Report "[!] Found $($taskEvents.Count) new scheduled tasks!" "WARNING"
        
        foreach ($event in $taskEvents | Select-Object -First 10) {
            $xml = [xml]$event.ToXml()
            $taskName = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'TaskName'} | Select-Object -ExpandProperty '#text'
            $subjectUser = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'SubjectUserName'} | Select-Object -ExpandProperty '#text'
            
            Write-Report "`n[!] Task: $taskName" "WARNING"
            Write-Report "    Created by: $subjectUser at $($event.TimeCreated)" "WARNING"
            Write-Host "  Task: $taskName (by $subjectUser)" -ForegroundColor Yellow
        }
    } else {
        Write-Report "No new scheduled tasks created" "SUCCESS"
    }
} catch {
    Write-Report "Error checking scheduled task events: $_" "WARNING"
}

# ============================================
# 7. WINDOWS DEFENDER ALERTS
# ============================================
Write-Host "`n[7] Checking Windows Defender alerts..." -ForegroundColor Yellow

Write-Report "`n=== WINDOWS DEFENDER DETECTIONS ==="

try {
    $defenderEvents = Get-WinEvent -FilterHashtable @{
        LogName='Microsoft-Windows-Windows Defender/Operational'
        ID=1116,1117  # Malware detected and action taken
        StartTime=$startTime
    } -ErrorAction SilentlyContinue
    
    if ($defenderEvents) {
        Write-Alert "MALWARE DETECTED - Windows Defender found $($defenderEvents.Count) threats!" "" "CRITICAL"
        Write-Report "[!] CRITICAL: Found $($defenderEvents.Count) malware detections!" "CRITICAL"
        
        foreach ($event in $defenderEvents | Select-Object -First 10) {
            $msg = $event.Message.Split([Environment]::NewLine)[0]
            Write-Report "`n[!] Detection at $($event.TimeCreated)" "CRITICAL"
            Write-Report "    $msg" "CRITICAL"
            Write-Host "  $msg" -ForegroundColor Red
        }
    } else {
        Write-Report "No Windows Defender alerts" "SUCCESS"
    }
} catch {
    Write-Report "Windows Defender log not available" "WARNING"
}

# ============================================
# 8. RDP SESSION ACTIVITY
# ============================================
Write-Host "`n[8] Checking RDP session activity..." -ForegroundColor Yellow

Write-Report "`n=== RDP SESSION ACTIVITY ==="

try {
    # RDP logon events
    $rdpEvents = Get-WinEvent -FilterHashtable @{
        LogName='Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'
        ID=21,25  # Session logon and reconnection
        StartTime=$startTime
    } -ErrorAction SilentlyContinue
    
    if ($rdpEvents) {
        Write-Report "Found $($rdpEvents.Count) RDP session events" "WARNING"
        
        $rdpEvents | Select-Object -First 10 | ForEach-Object {
            $xml = [xml]$_.ToXml()
            $user = $xml.Event.UserData.EventXML.User
            $sourceIP = $xml.Event.UserData.EventXML.Address
            
            Write-Report "$($_.TimeCreated): $user from $sourceIP" "WARNING"
        }
    }
} catch {
    Write-Report "RDP log not available" "WARNING"
}

# ============================================
# 9. FIREWALL RULE CHANGES
# ============================================
Write-Host "`n[9] Checking firewall rule modifications..." -ForegroundColor Yellow

Write-Report "`n=== FIREWALL RULE CHANGES (Event ID 2004, 2005) ==="

try {
    $firewallEvents = Get-WinEvent -FilterHashtable @{
        LogName='Microsoft-Windows-Windows Firewall With Advanced Security/Firewall'
        ID=2004,2005  # Rule added/modified
        StartTime=$startTime
    } -ErrorAction SilentlyContinue
    
    if ($firewallEvents) {
        Write-Alert "FIREWALL RULES MODIFIED - $($firewallEvents.Count) changes!" "" "WARNING"
        Write-Report "[!] Found $($firewallEvents.Count) firewall rule changes!" "WARNING"
        
        $firewallEvents | Select-Object -First 10 | ForEach-Object {
            $msg = $_.Message.Split([Environment]::NewLine)[0]
            Write-Report "$($_.TimeCreated): $msg" "WARNING"
        }
    } else {
        Write-Report "No firewall rule changes detected" "SUCCESS"
    }
} catch {
    Write-Report "Firewall log not available" "WARNING"
}

# ============================================
# SUMMARY
# ============================================
Write-Host "`n============================================" -ForegroundColor Cyan
Write-Host "Event Log Analysis Complete!" -ForegroundColor Green
Write-Host "Report: $ReportFile" -ForegroundColor Cyan
Write-Host "Time Range: Last $Hours hour(s)" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
