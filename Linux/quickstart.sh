#!/usr/bin/env -S sudo -- bash

cd /tmp

exists() {
    command -v "$1" > /dev/null 2>&1
}

# echo "Running Installs"
# if exists apt; then 
#     apt update
#     apt install -y lynis clamav clamav-daemon ufw neovim aide fail2ban python3-pyinotify wget libmodsecurity3 python3
#     nohup sh -c 'wget "https://download.opensuse.org/repositories/home:/cabelo/Debian_Unstable/amd64/owasp-zap_2.14.0-1_amd64.deb" -O ./zap.deb && apt -y install ./zap.deb' > /var/log/zapinstall.log & 
# elif exists dnf; then 
#     dnf config-manager --set-enabled epel 
#     dnf check-update
#     dnf install -y lynis clamav clamd clamav-update ufw neovim aide fail2ban python-inotify wget libmodsecurity python3
#     nohup sh -c 'wget "https://download.opensuse.org/repositories/home:/cabelo/Fedora_38/noarch/owasp-zap-2.14.0-3.1.noarch.rpm" -O ./zap.rpm && dnf install ./zap.rpm' &
# elif exists pacman; then 
#     pacman -Sy --no-confirm lynis clamav ufw fail2ban python-pyinotify wget libmodsecurity zaproxy python
# fi
# 
# echo "Starting freshclam & lynis in the background"
# nohup sh -c 'freshclam && mkdir /var/quarantine && clamscan -l /var/log/clamscan.log --move /var/quarantine -r /' > /var/log/clamscan.txt & 
# nohup lynis audit system > /var/log/lynis_stdout.txt & 
# 
# clamav_config=$(find /etc -name 'clamd.conf' 2> /dev/null | head -1)
# echo "Configuring clamav at $clamav_config"
# if [ -n $clamav_confg ]; then 
#     sed -i 's/^Example/#Example/' $clamav_config
#     sed -i 's/^#PidFile/PidFile/' $clamav_config
#     sed -i 's/^#LocalSocket /LocalSocket /' $clamav_config
#     sed -i 's@^#LogFile /tmp/clamav.log@LogFile /var/log/clamav/clamav.log@' $clamav_config
#     sed -i 's@^#OnAccessMountPath /$@OnAccessMountPath /@' $clamav_config
#     sed -i 's/^#OnAccessExcludeRootUID no/OnAccessExcludeRootUID yes/' $clamav_config
#     sed -i 's/^#OnAccessExcludeUname clamav/OnAccessExcludeUname clamav/' $clamav_config
#     sed -i 's/^#OnAccessExtraScanning yes/OnAccessExtraScanning yes/' $clamav_config
# else 
#     echo "ERROR: clamd.conf not found" 1>&2
# fi

# Configuring SSH

sshd_config="$(find /etc -name 'sshd_config' 2> /dev/null | head -1)"
echo "Configuring sshd at \"$sshd_config\""
wheel=$(grep -o '^%\w\+' /etc/sudoers | tr -d '%') 

if [ -n "$sshd_config" ]; then
    sed -i 's/^#?PermitRootLogin.*$/PermitRootLogin no/' $sshd_config
    sed -i 's/^#?AllowTcpForwarding.*$/AllowTcpForwarding no/' $sshd_config
    sed -i 's/^#?AllowAgentForwarding.*$/AllowAgentForwarding no/' $sshd_config
    sed -i 's/^#?X11Forwarding.*$/X11Forwarding no/' $sshd_config
    sed -i 's/^#?PermitTunnel.*$/PermitTunnel no/' $sshd_config
    sed -i 's@^#?ChrootDirectory.*$@ChrootDirectory /jail@' $sshd_config
    echo -e "Match Group $wheel\n    ChrootDirectory /" >> $sshd_config
else
    echo "ERROR: sshd_config not found. Is this running dropbear?" 1>&2
fi

echo "Making Jail"
mkdir -p /jail/{bin,home}
cp /bin/bash /jail/bin 

safe_programs=("ls" "pwd" "whoami" "tty" "groups" "sleep" "touch" "rm" "rmdir" "more" "less" "cat" "nl" "wc" "dir" "uniq" "id" "hostid" "uname" "logname" "seq" "test" "uptime")
writeable_programs=("yes" "printenv" "echo" "nano" "mktemp" "stty")
echo "Whitelisting safe programs"
for program in "${safe_programs[@]}"; do
    if [ -f "/usr/bin/$program" ]; then
        ln /usr/bin/$program /jail/bin/
    elif [ -f "/bin/$program" ]; then 
        ln /bin/$program /jail/bin/
    else 
        echo "ERROR: $program not found for adding to jailbin"
    fi
done
    

echo "Starting clamd"

systemctl start clamd
clamonacc > /var/log/clamonacc.txt 

echo "Configuring aide"
if exists aide; then
    nohup sh -c 'aide -c /etc/aide.conf --init && mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db' > /var/log/aide_init.txt & 
else 
    echo "ERROR: aide not found. Might be Arch-based, otherwise this is bad"
fi

echo "Done."
