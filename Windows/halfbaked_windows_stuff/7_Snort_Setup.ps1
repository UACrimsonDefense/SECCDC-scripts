#Requires -RunAsAdministrator
<#
.SYNOPSIS
    CCDC Snort IDS Installation & Configuration
.DESCRIPTION
    Downloads, installs, and configures Snort IDS for Windows from web sources or GitHub repo
.NOTES
    For CCDC: Store binaries in your GitHub repo before competition
    Alternatively provide download URLs via parameters
    
.PARAMETER SnortBinaryPath
    Path to snort.exe (local file or URL to download)
    
.PARAMETER NpcapInstallerPath  
    Path to Npcap installer (local file or URL to download)
    
.PARAMETER UseRepoFiles
    If set, looks for binaries in ./snort-binaries/ subdirectory of script location
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$InstallPath = "C:\Snort",
    
    [Parameter(Mandatory=$false)]
    [string]$LogPath = "C:\CCDC_Logs",
    
    [Parameter(Mandatory=$false)]
    [string]$SnortBinaryPath = "",
    
    [Parameter(Mandatory=$false)]
    [string]$NpcapInstallerPath = "https://npcap.com/dist/npcap-1.79.exe",
    
    [Parameter(Mandatory=$false)]
    [switch]$UseRepoFiles
)

$ErrorActionPreference = "Continue"

if (!(Test-Path $LogPath)) {
    New-Item -ItemType Directory -Path $LogPath -Force | Out-Null
}

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $color = switch($Level) {
        "ERROR" { "Red" }
        "WARNING" { "Yellow" }
        "SUCCESS" { "Green" }
        default { "White" }
    }
    Write-Host "[$timestamp] [$Level] $Message" -ForegroundColor $color
}

Write-Host "============================================" -ForegroundColor Cyan
Write-Host "CCDC Snort IDS Setup" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan

# Determine script directory for repo files
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoBinariesDir = Join-Path $scriptDir "snort-binaries"

# ============================================
# 1. CHECK PREREQUISITES
# ============================================
Write-Host "`n[1] Checking prerequisites..." -ForegroundColor Yellow

# Check for WinPcap/Npcap
$npcapInstalled = Test-Path "C:\Windows\System32\Npcap"
$winpcapInstalled = Test-Path "C:\Windows\System32\wpcap.dll"

if (-not ($npcapInstalled -or $winpcapInstalled)) {
    Write-Log "WinPcap/Npcap not found. Installing Npcap..." "WARNING"
    
    $npcapInstaller = "$env:TEMP\npcap-installer.exe"
    
    # Check if using repo files
    if ($UseRepoFiles) {
        $repoNpcap = Join-Path $repoBinariesDir "npcap-installer.exe"
        if (Test-Path $repoNpcap) {
            Write-Log "Using Npcap from repository: $repoNpcap"
            Copy-Item $repoNpcap $npcapInstaller
        } else {
            Write-Log "Npcap not found in repo, will download..." "WARNING"
            $UseRepoFiles = $false
        }
    }
    
    # Download if not using repo or repo file not found
    if (-not $UseRepoFiles -or -not (Test-Path $npcapInstaller)) {
        if ($NpcapInstallerPath) {
            try {
                Write-Log "Downloading Npcap from $NpcapInstallerPath"
                Invoke-WebRequest -Uri $NpcapInstallerPath -OutFile $npcapInstaller -UseBasicParsing
            } catch {
                Write-Log "Error downloading Npcap: $_" "ERROR"
                Write-Log "Please install Npcap manually from https://npcap.com" "WARNING"
            }
        }
    }
    
    # Install if we have the file
    if (Test-Path $npcapInstaller) {
        try {
            Write-Log "Installing Npcap (silent install)..."
            Start-Process -FilePath $npcapInstaller -ArgumentList "/S" -Wait
            Write-Log "Npcap installed successfully" "SUCCESS"
        } catch {
            Write-Log "Error installing Npcap: $_" "ERROR"
        }
    }
} else {
    Write-Log "WinPcap/Npcap already installed" "SUCCESS"
}

# ============================================
# 2. SETUP SNORT DIRECTORIES
# ============================================
Write-Host "`n[2] Setting up Snort directories..." -ForegroundColor Yellow

if (!(Test-Path $InstallPath)) {
    New-Item -ItemType Directory -Path $InstallPath -Force | Out-Null
}

$snortDirs = @(
    "$InstallPath\bin",
    "$InstallPath\etc",
    "$InstallPath\log",
    "$InstallPath\rules",
    "$InstallPath\lib",
    "$InstallPath\dynamicrules",
    "$InstallPath\preproc_rules",
    "$InstallPath\so_rules"
)

foreach ($dir in $snortDirs) {
    if (!(Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
}

Write-Log "Directory structure created" "SUCCESS"

# ============================================
# 3. INSTALL SNORT BINARY
# ============================================
Write-Host "`n[3] Installing Snort binary..." -ForegroundColor Yellow

$snortExe = "$InstallPath\bin\snort.exe"

# Check if using repo files
if ($UseRepoFiles) {
    $repoSnort = Join-Path $repoBinariesDir "snort.exe"
    if (Test-Path $repoSnort) {
        Write-Log "Using Snort from repository: $repoSnort"
        Copy-Item $repoSnort $snortExe -Force
        Write-Log "Snort binary copied from repo" "SUCCESS"
    } else {
        Write-Log "Snort binary not found in repo: $repoSnort" "WARNING"
    }
}

# Download if specified and not already installed
if (-not (Test-Path $snortExe) -and $SnortBinaryPath) {
    if ($SnortBinaryPath -like "http*") {
        try {
            Write-Log "Downloading Snort from $SnortBinaryPath"
            Invoke-WebRequest -Uri $SnortBinaryPath -OutFile $snortExe -UseBasicParsing
            Write-Log "Snort binary downloaded" "SUCCESS"
        } catch {
            Write-Log "Error downloading Snort: $_" "ERROR"
        }
    } elseif (Test-Path $SnortBinaryPath) {
        Copy-Item $SnortBinaryPath $snortExe -Force
        Write-Log "Snort binary copied from: $SnortBinaryPath" "SUCCESS"
    }
}

if (!(Test-Path $snortExe)) {
    Write-Log "Snort binary not installed. Continuing with config creation..." "WARNING"
    Write-Log "Add snort.exe to $InstallPath\bin\ before running" "WARNING"
}

# ============================================
# 4. CREATE SNORT CONFIGURATION
# ============================================
Write-Host "`n[4] Creating Snort configuration..." -ForegroundColor Yellow

$snortConfig = @"
# CCDC Snort Configuration
# Generated: $(Get-Date)

# Configure paths
var RULE_PATH $InstallPath\rules
var SO_RULE_PATH $InstallPath\so_rules
var PREPROC_RULE_PATH $InstallPath\preproc_rules

# Configure network (ADJUST FOR YOUR SUBNET!)
var HOME_NET 10.0.0.0/8
var EXTERNAL_NET !\`$HOME_NET

# Configure ports
var HTTP_PORTS [80,8080,8000,8888]
var HTTPS_PORTS [443,8443]
var SSH_PORTS 22
var TELNET_PORTS 23
var DNS_PORTS 53
var SMTP_PORTS 25
var POP_PORTS [110,995]
var IMAP_PORTS [143,993]
var FTP_PORTS [21,2100]
var SQL_PORTS [1433,1521,3306,5432]

# Configure preprocessors
preprocessor frag3_global: max_frags 65536
preprocessor frag3_engine: policy windows detect_anomalies overlap_limit 10 min_fragment_length 100 timeout 180

preprocessor stream5_global: track_tcp yes, track_udp yes, track_icmp no, max_tcp 262144, max_udp 131072
preprocessor stream5_tcp: policy windows, detect_anomalies, require_3whs 180, overlap_limit 10, small_segments 3 bytes 150, timeout 180
preprocessor stream5_udp: timeout 180

preprocessor http_inspect: global iis_unicode_map unicode.map 1252 compress_depth 65535 decompress_depth 65535
preprocessor http_inspect_server: server default \
    http_methods { GET POST PUT SEARCH MKCOL COPY MOVE LOCK UNLOCK NOTIFY POLL BCOPY BDELETE BMOVE LINK UNLINK OPTIONS HEAD DELETE TRACE TRACK CONNECT SOURCE SUBSCRIBE UNSUBSCRIBE PROPFIND PROPPATCH BPROPFIND BPROPPATCH RPC_CONNECT PROXY_SUCCESS BITS_POST CCM_POST SMS_POST RPC_IN_DATA RPC_OUT_DATA RPC_ECHO_DATA } \
    chunk_length 500000 \
    server_flow_depth 0 \
    client_flow_depth 0 \
    post_depth 65495 \
    oversize_dir_length 500 \
    max_header_length 750 \
    max_headers 100 \
    max_spaces 200 \
    ports { 80 81 311 591 593 901 1220 1414 1741 1830 2301 2381 2809 3037 3128 3702 4343 4848 5250 6988 7000 7001 7144 7145 7510 7777 7779 8000 8008 8014 8028 8080 8085 8088 8090 8118 8123 8180 8181 8243 8280 8300 8800 8888 8899 9000 9060 9080 9090 9091 9443 9999 11371 34443 34444 41080 50002 55555 } \
    non_rfc_char { 0x00 0x01 0x02 0x03 0x04 0x05 0x06 0x07 } \
    enable_cookie \
    extended_response_inspection \
    inspect_gzip \
    normalize_utf \
    unlimited_decompress \
    normalize_javascript \
    apache_whitespace no \
    ascii no \
    bare_byte no \
    directory no \
    double_decode no \
    iis_backslash no \
    iis_delimiter no \
    iis_unicode no \
    multi_slash no \
    utf_8 no \
    u_encode yes \
    webroot no

# Output configuration
output alert_fast: $InstallPath\log\alert.txt
output log_tcpdump: $InstallPath\log\snort.log

# Include classification & reference configs
include $InstallPath\etc\classification.config
include $InstallPath\etc\reference.config

# ============================================
# CCDC CUSTOM RULES
# ============================================

# Alert on potential C2 traffic
alert tcp \`$HOME_NET any -> \`$EXTERNAL_NET any (msg:"CCDC Potential C2 - Outbound connection to suspicious port"; flow:to_server,established; threshold:type threshold, track by_src, count 5, seconds 60; sid:1000001; rev:1;)

# Alert on port scanning
alert tcp any any -> \`$HOME_NET any (msg:"CCDC Port Scan Detected"; flags:S; threshold:type threshold, track by_src, count 10, seconds 5; sid:1000002; rev:1;)

# Alert on SMB exploits
alert tcp any any -> \`$HOME_NET 445 (msg:"CCDC SMB Exploit Attempt"; content:"|FF|SMB"; depth:5; sid:1000003; rev:1;)

# Alert on PowerShell download cradles
alert tcp any any -> \`$HOME_NET any (msg:"CCDC PowerShell Download Cradle"; content:"IEX"; content:"downloadstring"; nocase; distance:0; sid:1000004; rev:1;)

# Alert on Mimikatz strings
alert tcp any any -> any any (msg:"CCDC Mimikatz Detected"; content:"sekurlsa"; nocase; sid:1000005; rev:1;)

# Alert on suspicious DNS queries
alert udp \`$HOME_NET any -> any 53 (msg:"CCDC Suspicious DNS Query - Long subdomain"; content:"|01 00 00 01 00 00 00 00 00 00|"; depth:10; content:"|00 00 01 00 01|"; distance:0; pcre:"/[a-z0-9]{50,}/"; sid:1000006; rev:1;)

# Alert on RDP brute force
alert tcp any any -> \`$HOME_NET 3389 (msg:"CCDC RDP Brute Force Attempt"; flags:S; threshold:type both, track by_src, count 5, seconds 60; sid:1000007; rev:1;)

# Alert on SQL injection attempts
alert tcp any any -> \`$HOME_NET \`$HTTP_PORTS (msg:"CCDC SQL Injection Attempt"; content:"SELECT"; nocase; content:"FROM"; nocase; distance:0; sid:1000008; rev:1;)

# Alert on common reverse shell ports
alert tcp \`$HOME_NET any -> \`$EXTERNAL_NET [4444,4445,31337,1337,12345] (msg:"CCDC Outbound to Common C2 Port"; flow:to_server; sid:1000009; rev:1;)

# Alert on base64 encoded commands
alert tcp any any -> \`$HOME_NET any (msg:"CCDC Base64 Encoded Command Detected"; content:"powershell"; nocase; content:"-enc"; nocase; distance:0; sid:1000010; rev:1;)

# Include downloaded community rules (if available)
# include \`$RULE_PATH/community.rules
# include \`$RULE_PATH/emerging-threats.rules
"@

$snortConfig | Out-File "$InstallPath\etc\snort.conf" -Encoding ASCII
Write-Log "Snort configuration created: $InstallPath\etc\snort.conf" "SUCCESS"

# Create classification.config
$classificationConfig = @"
# Classification config for CCDC
config classification: not-suspicious,Not Suspicious Traffic,3
config classification: unknown,Unknown Traffic,3
config classification: bad-unknown,Potentially Bad Traffic,2
config classification: attempted-recon,Attempted Information Leak,2
config classification: successful-recon-limited,Information Leak,2
config classification: successful-recon-largescale,Large Scale Information Leak,2
config classification: attempted-dos,Attempted Denial of Service,2
config classification: successful-dos,Denial of Service,2
config classification: attempted-user,Attempted User Privilege Gain,1
config classification: unsuccessful-user,Unsuccessful User Privilege Gain,1
config classification: successful-user,Successful User Privilege Gain,1
config classification: attempted-admin,Attempted Administrator Privilege Gain,1
config classification: successful-admin,Successful Administrator Privilege Gain,1
"@

$classificationConfig | Out-File "$InstallPath\etc\classification.config" -Encoding ASCII

# Create reference.config
$referenceConfig = @"
# Reference systems for CCDC
config reference: bugtraq http://www.securityfocus.com/bid/
config reference: cve http://cve.mitre.org/cgi-bin/cvename.cgi?name=
config reference: nessus http://cgi.nessus.org/plugins/dump.php3?id=
"@

$referenceConfig | Out-File "$InstallPath\etc\reference.config" -Encoding ASCII

# ============================================
# 5. CREATE START SCRIPT
# ============================================
Write-Host "`n[5] Creating Snort start script..." -ForegroundColor Yellow

$startScript = @"
# CCDC Snort Start Script
`$snortPath = "$InstallPath\bin\snort.exe"
`$configPath = "$InstallPath\etc\snort.conf"

if (!(Test-Path `$snortPath)) {
    Write-Host "[!] ERROR: Snort binary not found at `$snortPath" -ForegroundColor Red
    Write-Host "[!] Please place snort.exe in $InstallPath\bin\" -ForegroundColor Red
    exit 1
}

# Get network interfaces
Write-Host "Available network interfaces:" -ForegroundColor Yellow
`$interfaces = Get-NetAdapter | Where-Object {`$_.Status -eq 'Up'}
`$i = 1
foreach (`$int in `$interfaces) {
    Write-Host "`$i. `$(`$int.Name) - `$(`$int.InterfaceDescription)" -ForegroundColor Cyan
    `$i++
}

`$choice = Read-Host "Select interface number"
`$selectedInterface = `$interfaces[`$choice - 1].InterfaceIndex

Write-Host "`nStarting Snort on interface `$selectedInterface..." -ForegroundColor Green
Write-Host "Press Ctrl+C to stop" -ForegroundColor Yellow
Write-Host "Alerts will be logged to: $InstallPath\log\alert.txt" -ForegroundColor Cyan

# Start Snort in IDS mode
& `$snortPath -i `$selectedInterface -c `$configPath -l "$InstallPath\log" -A console
"@

$startScript | Out-File "$InstallPath\Start-Snort.ps1" -Encoding ASCII
Write-Log "Start script created: $InstallPath\Start-Snort.ps1" "SUCCESS"

# ============================================
# 6. CREATE LOG MONITORING SCRIPT
# ============================================
Write-Host "`n[6] Creating log monitoring script..." -ForegroundColor Yellow

$monitorScript = @"
# Monitor Snort Alerts in Real-Time with Console Alerts
`$alertFile = "$InstallPath\log\alert.txt"

Write-Host "============================================" -ForegroundColor Cyan
Write-Host "Snort Alert Monitor (Real-Time)" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "Monitoring: `$alertFile" -ForegroundColor Yellow
Write-Host "Press Ctrl+C to stop" -ForegroundColor Yellow
Write-Host ""

if (!(Test-Path `$alertFile)) {
    Write-Host "[!] Alert file not found. Is Snort running?" -ForegroundColor Red
    Write-Host "[!] Start Snort first: .\Start-Snort.ps1" -ForegroundColor Yellow
    exit
}

Get-Content `$alertFile -Wait -Tail 0 | ForEach-Object {
    if (`$_ -match "CRITICAL|Exploit|Mimikatz|C2|Brute") {
        # Critical alerts - beep and red
        Write-Host `$_ -ForegroundColor Red
        [Console]::Beep(1000, 200)
    } elseif (`$_ -match "Priority: 1|HIGH") {
        Write-Host `$_ -ForegroundColor Red
    } elseif (`$_ -match "Priority: 2|MEDIUM") {
        Write-Host `$_ -ForegroundColor Yellow
    } else {
        Write-Host `$_
    }
}
"@

$monitorScript | Out-File "$InstallPath\Monitor-SnortAlerts.ps1" -Encoding ASCII
Write-Log "Alert monitor created: $InstallPath\Monitor-SnortAlerts.ps1" "SUCCESS"

# ============================================
# 7. CREATE QUICK START GUIDE
# ============================================
$quickStart = @"
CCDC SNORT QUICK START GUIDE
=============================

INSTALLATION COMPLETE!

SETUP FOR CCDC:

1. BEFORE COMPETITION (Add to GitHub repo):
   - snort.exe → $InstallPath\bin\
   - (Optional) community rules → $InstallPath\rules\
   - Commit everything to your frozen GitHub repo

2. DURING COMPETITION:

   A. IMPORTANT: Edit $InstallPath\etc\snort.conf
      - Set HOME_NET to match your network!
        Example: var HOME_NET 192.168.10.0/24
   
   B. START SNORT (Interactive Mode):
      PS> cd $InstallPath
      PS> .\Start-Snort.ps1
      Select your network interface when prompted

   C. MONITOR ALERTS (Separate PowerShell Window):
      PS> cd $InstallPath
      PS> .\Monitor-SnortAlerts.ps1
      Real-time alerts will appear with color coding and beeps

3. FILES:
   - Main config: $InstallPath\etc\snort.conf
   - Alert log: $InstallPath\log\alert.txt
   - Packet log: $InstallPath\log\snort.log

4. TROUBLESHOOTING:
   - Test config: snort.exe -T -c $InstallPath\etc\snort.conf
   - List interfaces: Get-NetAdapter | Where Status -eq 'Up'
   - Check logs in $InstallPath\log\

CUSTOM CCDC RULES INCLUDED:
- C2 detection (SID 1000001, 1000009)
- Port scanning (SID 1000002)
- SMB exploits (SID 1000003)
- PowerShell attacks (SID 1000004, 1000010)
- Mimikatz detection (SID 1000005)
- DNS tunneling (SID 1000006)
- RDP brute force (SID 1000007)
- SQL injection (SID 1000008)

GITHUB REPO SETUP:
Your GitHub repo should have this structure:
  ccdc-scripts/
  ├── 1_Master_Initial_Hardening.ps1
  ├── ... (other scripts)
  ├── 7_Snort_Setup.ps1
  └── snort-binaries/
      ├── snort.exe
      └── npcap-installer.exe (optional)

Then run: .\7_Snort_Setup.ps1 -UseRepoFiles

Good luck!
"@

$quickStart | Out-File "$InstallPath\QUICKSTART.txt"

# ============================================
# SUMMARY
# ============================================
Write-Host "`n============================================" -ForegroundColor Cyan
Write-Host "Snort Setup Complete!" -ForegroundColor Green
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "Installation directory: $InstallPath" -ForegroundColor Cyan
Write-Host ""

if (Test-Path $snortExe) {
    Write-Host "[+] Snort binary installed" -ForegroundColor Green
} else {
    Write-Host "[!] Snort binary NOT installed" -ForegroundColor Yellow
    Write-Host "    Add snort.exe to your GitHub repo: snort-binaries/snort.exe" -ForegroundColor Yellow
    Write-Host "    Or download from: https://www.snort.org/downloads" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "NEXT STEPS:" -ForegroundColor Yellow
Write-Host "1. CRITICAL: Edit $InstallPath\etc\snort.conf" -ForegroundColor White
Write-Host "   Set HOME_NET to your actual network!" -ForegroundColor White
Write-Host "2. Run: $InstallPath\Start-Snort.ps1" -ForegroundColor White
Write-Host "3. In another window: $InstallPath\Monitor-SnortAlerts.ps1" -ForegroundColor White
Write-Host ""
Write-Host "See $InstallPath\QUICKSTART.txt for details" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
