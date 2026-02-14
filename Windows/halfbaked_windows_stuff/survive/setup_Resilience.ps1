<#
Initial Setup Script
- Configures service recovery
- Registers scheduled task
- Creates BlueTeam directory
#>

$BaseDir = "C:\BlueTeam"
New-Item -ItemType Directory -Path $BaseDir -Force | Out-Null

$Services = @("TermService","WinRM","sshd","MpsSvc")

foreach ($svc in $Services) {
    sc.exe failure $svc reset= 0 actions= restart/5000/restart/5000/restart/5000 | Out-Null
    sc.exe config $svc start= auto | Out-Null
}

# Create Scheduled Task (runs every 1 minute as SYSTEM)
$action = New-ScheduledTaskAction `
    -Execute "PowerShell.exe" `
    -Argument "-NoProfile -ExecutionPolicy Bypass -File C:\BlueTeam\ServiceResilience.ps1"

$trigger = New-ScheduledTaskTrigger `
    -Once -At (Get-Date) `
    -RepetitionInterval (New-TimeSpan -Minutes 1) `
    -RepetitionDuration ([TimeSpan]::MaxValue)

Register-ScheduledTask `
    -TaskName "BlueTeamServiceResilience" `
    -Action $action `
    -Trigger $trigger `
    -User "SYSTEM" `
    -RunLevel Highest `
    -Force

Write-Host "Blue Team Resilience Setup Complete."
Write-Host "Scheduled Task: BlueTeamServiceResilience"
Write-Host "Log File: C:\BlueTeam\ServiceResilience.log"
