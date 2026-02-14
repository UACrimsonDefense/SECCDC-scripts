######### Sysmon Setup #########
#first download config from https://github.com/applied-cyber/ccdc/blob/main/scripts/windows/logging/aggresive.xml
#aggresive.xml prefered

#OR https://wazuh.com/resources/blog/emulation-of-attack-techniques-and-detection-with-wazuh/sysmonconfig.xml
#which "maps Sysmon rules with MITRE attack techniques"



if ($Env:PROCESSOR_ARCHITECTURE -eq "AMD64") {
    C:\Windows\System32\Sysmon64.exe -accepteula -i
    C:\Windows\System32\Sysmon64.exe -c C:\Windows\System32\smce.xml
    Write-Output "$Env:ComputerName [INFO] Sysmon64 installed and configured"
}
else {
    C:\Windows\System32\Sysmon.exe -accepteula -i 
    C:\Windows\System32\Sysmon.exe -c C:\Windows\System32\smce.xml
    Write-Output "$Env:ComputerName [INFO] Sysmon32 installed and configured"
}