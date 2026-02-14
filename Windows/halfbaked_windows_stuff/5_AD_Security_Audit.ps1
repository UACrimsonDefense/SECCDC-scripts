#Requires -RunAsAdministrator
#Requires -Modules ActiveDirectory
<#
.SYNOPSIS
    CCDC Active Directory Hardening & Monitoring
.DESCRIPTION
    Secures AD, detects suspicious objects, monitors for attacks
.NOTES
    Run on Domain Controller
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$LogPath = "C:\CCDC_Logs",
    
    [Parameter(Mandatory=$false)]
    [switch]$QuickMode
)

$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$ReportFile = "$LogPath\AD_Audit_$Timestamp.txt"

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
Write-Host "CCDC Active Directory Security Audit" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan

# Check if running on DC
try {
    Import-Module ActiveDirectory -ErrorAction Stop
} catch {
    Write-Host "[!] ERROR: Active Directory module not available. Run on Domain Controller!" -ForegroundColor Red
    exit 1
}

# ============================================
# 1. DOMAIN INFORMATION
# ============================================
Write-Host "`n[1] Gathering domain information..." -ForegroundColor Yellow

try {
    $domain = Get-ADDomain
    $forest = Get-ADForest
    
    Write-Report "=== DOMAIN INFORMATION ==="
    Write-Report "Domain: $($domain.DNSRoot)"
    Write-Report "Domain SID: $($domain.DomainSID)"
    Write-Report "Forest: $($forest.Name)"
    Write-Report "Domain Functional Level: $($domain.DomainMode)"
    Write-Report "Forest Functional Level: $($forest.ForestMode)"
    Write-Report "Domain Controllers: $($domain.ReplicaDirectoryServers -join ', ')"
    
} catch {
    Write-Report "Error getting domain info: $_" "ERROR"
    exit 1
}

# ============================================
# 2. PRIVILEGED GROUP AUDIT
# ============================================
Write-Host "`n[2] Auditing privileged groups..." -ForegroundColor Yellow

Write-Report "`n=== PRIVILEGED GROUP MEMBERSHIP ==="

$privilegedGroups = @(
    'Domain Admins',
    'Enterprise Admins',
    'Schema Admins',
    'Administrators',
    'Account Operators',
    'Backup Operators',
    'Server Operators',
    'Print Operators',
    'Domain Controllers',
    'Group Policy Creator Owners',
    'DnsAdmins'
)

$allPrivilegedMembers = @()

foreach ($groupName in $privilegedGroups) {
    try {
        $group = Get-ADGroup -Identity $groupName -ErrorAction SilentlyContinue
        if ($group) {
            $members = Get-ADGroupMember -Identity $groupName -Recursive | Select-Object Name, SamAccountName, ObjectClass, DistinguishedName
            
            Write-Report "`nGroup: $groupName"
            if ($members) {
                foreach ($member in $members) {
                    Write-Report "  - $($member.SamAccountName) ($($member.ObjectClass))"
                    $allPrivilegedMembers += [PSCustomObject]@{
                        Group = $groupName
                        Member = $member.SamAccountName
                        Type = $member.ObjectClass
                        DN = $member.DistinguishedName
                    }
                }
                
                # Flag if too many members
                if ($members.Count -gt 5 -and $groupName -match "Domain Admins|Enterprise Admins") {
                    Write-Report "  [!] WARNING: Excessive members in privileged group!" "WARNING"
                }
            } else {
                Write-Report "  (No members)"
            }
        }
    } catch {
        Write-Report "Error checking group $groupName : $_" "WARNING"
    }
}

$allPrivilegedMembers | Export-Csv "$LogPath\AD_PrivilegedMembers_$Timestamp.csv" -NoTypeInformation

# ============================================
# 3. SUSPICIOUS USER ACCOUNTS
# ============================================
Write-Host "`n[3] Detecting suspicious user accounts..." -ForegroundColor Yellow

Write-Report "`n=== SUSPICIOUS USER ACCOUNTS ==="

# Get all users
$allUsers = Get-ADUser -Filter * -Properties *

Write-Report "Total user accounts: $($allUsers.Count)"

$suspiciousUsers = @()

foreach ($user in $allUsers) {
    $flags = @()
    
    # Check for accounts with SPN (potential Kerberoasting targets)
    if ($user.ServicePrincipalNames.Count -gt 0) {
        $flags += "Has SPN set (Kerberoasting risk)"
    }
    
    # Check for never-expiring passwords
    if ($user.PasswordNeverExpires) {
        $flags += "Password never expires"
    }
    
    # Check for accounts that don't require passwords
    if ($user.PasswordNotRequired) {
        $flags += "Password not required"
    }
    
    # Check for disabled accounts (could be re-enabled)
    if (-not $user.Enabled) {
        $flags += "Account disabled (monitor for re-enabling)"
    }
    
    # Check for old passwords
    if ($user.PasswordLastSet) {
        $passwordAge = (Get-Date) - $user.PasswordLastSet
        if ($passwordAge.TotalDays -gt 365) {
            $flags += "Password older than 1 year"
        }
    }
    
    # Check for never-used accounts
    if (-not $user.LastLogonDate -and $user.Enabled) {
        $flags += "Never logged on but enabled"
    }
    
    # Check for suspicious names
    if ($user.SamAccountName -match "admin\$|test|temp|backup|svc|service") {
        $flags += "Suspicious naming pattern"
    }
    
    # Check for accounts with adminCount=1 (privileged)
    if ($user.adminCount -eq 1) {
        $flags += "Has adminCount=1 (current or former privileged account)"
    }
    
    # Check for reversible password encryption
    if ($user.AllowReversiblePasswordEncryption) {
        $flags += "CRITICAL: Reversible password encryption enabled!"
    }
    
    if ($flags.Count -gt 0) {
        $suspiciousUsers += [PSCustomObject]@{
            SamAccountName = $user.SamAccountName
            Name = $user.Name
            Enabled = $user.Enabled
            LastLogon = $user.LastLogonDate
            PasswordLastSet = $user.PasswordLastSet
            Flags = ($flags -join "; ")
        }
        
        Write-Report "`n[!] $($user.SamAccountName)" "WARNING"
        foreach ($flag in $flags) {
            Write-Report "    - $flag" "WARNING"
        }
    }
}

if ($suspiciousUsers.Count -gt 0) {
    $suspiciousUsers | Export-Csv "$LogPath\AD_SuspiciousUsers_$Timestamp.csv" -NoTypeInformation
}

# ============================================
# 4. COMPUTER ACCOUNTS AUDIT
# ============================================
Write-Host "`n[4] Auditing computer accounts..." -ForegroundColor Yellow

Write-Report "`n=== COMPUTER ACCOUNTS ==="

$computers = Get-ADComputer -Filter * -Properties LastLogonDate, OperatingSystem, Created

Write-Report "Total computer accounts: $($computers.Count)"

# Check for stale computer accounts
$staleComputers = $computers | Where-Object {
    $_.LastLogonDate -and ((Get-Date) - $_.LastLogonDate).TotalDays -gt 90
}

if ($staleComputers) {
    Write-Report "`n[!] Found $($staleComputers.Count) stale computer accounts (no logon in 90+ days)" "WARNING"
    $staleComputers | Select-Object Name, LastLogonDate, OperatingSystem | 
        Export-Csv "$LogPath\AD_StaleComputers_$Timestamp.csv" -NoTypeInformation
}

# Check for recently added computers
$recentComputers = $computers | Where-Object {
    ((Get-Date) - $_.Created).TotalDays -lt 7
}

if ($recentComputers) {
    Write-Report "`n[!] Recently added computer accounts (last 7 days):" "WARNING"
    foreach ($comp in $recentComputers) {
        Write-Report "  - $($comp.Name) (Created: $($comp.Created))" "WARNING"
    }
}

# ============================================
# 5. GROUP POLICY OBJECTS (GPOs)
# ============================================
Write-Host "`n[5] Auditing Group Policy Objects..." -ForegroundColor Yellow

Write-Report "`n=== GROUP POLICY OBJECTS ==="

try {
    $gpos = Get-GPO -All
    Write-Report "Total GPOs: $($gpos.Count)"
    
    foreach ($gpo in $gpos) {
        Write-Report "`nGPO: $($gpo.DisplayName)"
        Write-Report "  Created: $($gpo.CreationTime)"
        Write-Report "  Modified: $($gpo.ModificationTime)"
        Write-Report "  Owner: $($gpo.Owner)"
        
        # Check for recently modified GPOs
        if (((Get-Date) - $gpo.ModificationTime).TotalDays -lt 7) {
            Write-Report "  [!] Recently modified!" "WARNING"
        }
    }
    
    $gpos | Select-Object DisplayName, CreationTime, ModificationTime, Owner |
        Export-Csv "$LogPath\AD_GPOs_$Timestamp.csv" -NoTypeInformation
        
} catch {
    Write-Report "Error auditing GPOs: $_" "WARNING"
}

# ============================================
# 6. KERBEROS DELEGATION
# ============================================
Write-Host "`n[6] Checking for Kerberos delegation..." -ForegroundColor Yellow

Write-Report "`n=== KERBEROS DELEGATION AUDIT ==="

# Unconstrained delegation (very dangerous)
$unconstrainedDelegation = Get-ADComputer -Filter {TrustedForDelegation -eq $true} -Properties TrustedForDelegation, servicePrincipalName

if ($unconstrainedDelegation) {
    Write-Report "[!] CRITICAL: Found computers with UNCONSTRAINED delegation!" "CRITICAL"
    foreach ($computer in $unconstrainedDelegation) {
        Write-Report "  - $($computer.Name)" "CRITICAL"
    }
    $unconstrainedDelegation | Export-Csv "$LogPath\AD_UnconstrainedDelegation_$Timestamp.csv" -NoTypeInformation
}

# Constrained delegation
$constrainedDelegation = Get-ADObject -Filter {msDS-AllowedToDelegateTo -like "*"} -Properties msDS-AllowedToDelegateTo, servicePrincipalName

if ($constrainedDelegation) {
    Write-Report "`n[!] Found objects with CONSTRAINED delegation:" "WARNING"
    foreach ($obj in $constrainedDelegation) {
        Write-Report "  - $($obj.Name)" "WARNING"
    }
}

# ============================================
# 7. DOMAIN PASSWORD POLICY
# ============================================
Write-Host "`n[7] Checking password policy..." -ForegroundColor Yellow

Write-Report "`n=== DOMAIN PASSWORD POLICY ==="

$passwordPolicy = Get-ADDefaultDomainPasswordPolicy

Write-Report "Minimum Password Length: $($passwordPolicy.MinPasswordLength)"
Write-Report "Password History Count: $($passwordPolicy.PasswordHistoryCount)"
Write-Report "Max Password Age: $($passwordPolicy.MaxPasswordAge.Days) days"
Write-Report "Min Password Age: $($passwordPolicy.MinPasswordAge.Days) days"
Write-Report "Lockout Threshold: $($passwordPolicy.LockoutThreshold)"
Write-Report "Lockout Duration: $($passwordPolicy.LockoutDuration.Minutes) minutes"

# Flag weak policies
if ($passwordPolicy.MinPasswordLength -lt 14) {
    Write-Report "[!] WARNING: Minimum password length is less than 14!" "WARNING"
}
if ($passwordPolicy.LockoutThreshold -eq 0) {
    Write-Report "[!] WARNING: Account lockout is disabled!" "WARNING"
}

# ============================================
# 8. RECENT AD CHANGES
# ============================================
if (-not $QuickMode) {
    Write-Host "`n[8] Checking recent AD changes..." -ForegroundColor Yellow
    
    Write-Report "`n=== RECENT AD MODIFICATIONS ==="
    
    # Recently created users
    $recentUsers = Get-ADUser -Filter * -Properties Created | Where-Object {
        ((Get-Date) - $_.Created).TotalDays -lt 7
    }
    
    if ($recentUsers) {
        Write-Report "`n[!] Users created in last 7 days:" "WARNING"
        foreach ($user in $recentUsers) {
            Write-Report "  - $($user.SamAccountName) (Created: $($user.Created))" "WARNING"
        }
    }
    
    # Recently modified users
    $modifiedUsers = Get-ADUser -Filter * -Properties Modified | Where-Object {
        ((Get-Date) - $_.Modified).TotalDays -lt 1
    }
    
    if ($modifiedUsers) {
        Write-Report "`n[!] Users modified in last 24 hours:" "WARNING"
        foreach ($user in $modifiedUsers) {
            Write-Report "  - $($user.SamAccountName) (Modified: $($user.Modified))" "WARNING"
        }
    }
}

# ============================================
# 9. KRBTGT ACCOUNT CHECK
# ============================================
Write-Host "`n[9] Checking KRBTGT account..." -ForegroundColor Yellow

Write-Report "`n=== KRBTGT ACCOUNT ==="

$krbtgt = Get-ADUser -Identity krbtgt -Properties PasswordLastSet

Write-Report "KRBTGT Password Last Set: $($krbtgt.PasswordLastSet)"

$krbtgtAge = (Get-Date) - $krbtgt.PasswordLastSet
if ($krbtgtAge.TotalDays -gt 365) {
    Write-Report "[!] CRITICAL: KRBTGT password is over 1 year old! (Golden Ticket risk)" "CRITICAL"
    Write-Report "[!] Recommend rotating KRBTGT password ASAP!" "CRITICAL"
}

# ============================================
# 10. DNS RECORDS CHECK
# ============================================
Write-Host "`n[10] Checking DNS records..." -ForegroundColor Yellow

Write-Report "`n=== DNS RECORDS CHECK ==="

try {
    $dnsZones = Get-DnsServerZone
    Write-Report "DNS Zones: $($dnsZones.Count)"
    
    foreach ($zone in $dnsZones | Where-Object {$_.IsAutoCreated -eq $false}) {
        Write-Report "`nZone: $($zone.ZoneName)"
        Write-Report "  Type: $($zone.ZoneType)"
        Write-Report "  Dynamic Updates: $($zone.DynamicUpdate)"
        
        if ($zone.DynamicUpdate -eq "NonsecureAndSecure") {
            Write-Report "  [!] WARNING: Zone allows insecure dynamic updates!" "WARNING"
        }
    }
} catch {
    Write-Report "DNS check skipped (not a DNS server or insufficient permissions)" "WARNING"
}

# ============================================
# SUMMARY
# ============================================
Write-Host "`n============================================" -ForegroundColor Cyan
Write-Host "Active Directory Audit Complete!" -ForegroundColor Green
Write-Host "Report: $ReportFile" -ForegroundColor Cyan
Write-Host "Domain: $($domain.DNSRoot)" -ForegroundColor Cyan
Write-Host "Suspicious Users: $($suspiciousUsers.Count)" -ForegroundColor $(if($suspiciousUsers.Count -gt 0){"Red"}else{"Green"})
Write-Host "============================================" -ForegroundColor Cyan
