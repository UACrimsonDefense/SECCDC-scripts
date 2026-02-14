#!/usr/bin/env -S sudo -- sh

cd /tmp

exists() {
    command -v "$1" > /dev/null 2>&1
}

if exists apt; then 
    apt update
    apt install -y lynis clamav clamav-daemon ufw neovim aide fail2ban python-pyinotify wget libmodsecurity3 python3
    wget 'https://download.opensuse.org/repositories/home:/cabelo/Debian_Unstable/amd64/owasp-zap_2.14.0-1_amd64.deb' -O ./zap.deb
    apt install ./zap.deb
elif exists dnf; then 
    dnf config-manager --set-enabled epel 
    dnf check-update
    dnf install -y lynis clamav clamd clamav-update ufw neovim aide fail2ban python-inotify wget libmodsecurity python3
    wget 'https://download.opensuse.org/repositories/home:/cabelo/Fedora_38/noarch/owasp-zap-2.14.0-3.1.noarch.rpm' -O ./zap.rpm
    dnf install ./zap.rpm
elif exists pacman; then 
    pacman -Sy lynis clamav ufw fail2ban python-pyinotify wget libmodsecurity zaproxy python
fi

nohup sh -c 'freshclam && mkdir /var/quarantine && clamscan -l /var/log/clamscan.log --move /var/quarantine -r /' > /var/log/clamscan.txt
nohup lynis audit system > /var/log/lynis_stdout.txt

# Configuring clamav 
clamav_config=$(find /etc -name 'clamd.conf' 2> /dev/null | head -1)
if [ -f $clamav_confg ]; then 
    sed -i 's/^Example/#Example/' $clamav_config
    sed -i 's/^#PidFile/PidFile/' $clamav_config
    sed -i 's/^#LocalSocket /LocalSocket /' $clamav_config
    sed -i 's@^#LogFile /tmp/clamav.log@LogFile /var/log/clamav/clamav.log@' $clamav_config
    sed -i 's@^#OnAccessMountPath /$@OnAccessMountPath /@' $clamav_config
    sed -i 's/^#OnAccessExcludeRootUID no/OnAccessExcludeRootUID yes/' $clamav_config
    sed -i 's/^#OnAccessExcludeUname clamav/OnAccessExcludeUname clamav/' $clamav_config
    sed -i 's/^#OnAccessExtraScanning yes/OnAccessExtraScanning yes/' $clamav_config
else 
    echo "ERROR: clamd.conf not found" 1>&2
fi

# Configuring SSH
mkdir -p /jail/{bin,home}
cp /bin/bash /jail/bin 

sshd_config=$(find /etc -name 'sshd_config' 2> /dev/null | head -1)
wheel=$(grep -o '^%\w\+' /etc/sudoers | tr -d '%') 

if [ -f $sshd_config ]; then
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
#TODO make lists of vital programs
safe_programs="cd ls pwd whoami tty groups sleep touch rm rmdir more less cat nl wc dir uniq arch id hostid uname logname seq test uptime"
writeable_programs="yes printenv echo nano mktemp stty" #in descending order of danger
#TODO configure links and jail
#TODO additional system hardening

systemctl start clamd
clamonacc > /var/log/clamonacc.txt 

if exists aide; then
    nohup sh -c 'aide -c /etc/aide.conf --init && mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db' > /var/log/aide_init.txt
fi
