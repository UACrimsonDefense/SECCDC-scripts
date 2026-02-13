#!/usr/bin/env -S sudo -- sh

cd /tmp

apt update
apt install -y lynis clamav clamav-daemon ufw neovim aide fail2ban python-pyinotify wget libmodsecurity3
wget 'https://download.opensuse.org/repositories/home:/cabelo/Debian_Unstable/amd64/owasp-zap_2.14.0-1_amd64.deb' -O ./zap.deb
dpkg -i ./zap.deb
git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git sqlmap
nohup bash -c 'freshclam && mkdir /var/quarantine && clamscan -l /var/log/clamscan.log --move /var/quarantine -r /' > /var/log/clamscan.txt
nohup lynis audit system > /var/log/lynis_stdout.txt

# Configuring clamav 
sed -i 's/^Example/#Example/' /etc/clamav/clamd.conf
sed -i 's/^#PidFile/PidFile/' /etc/clamav/clamd.conf
sed -i 's/^#LocalSocket /LocalSocket /' /etc/clamav/clamd.conf
sed -i 's@^#LogFile /tmp/clamav.log@LogFile /var/log/clamav/clamav.log@' /etc/clamav/clamd.conf
sed -i 's@^#OnAccessMountPath /$@OnAccessMountPath /@' /etc/clamav/clamd.conf
sed -i 's/^#OnAccessExcludeRootUID no/OnAccessExcludeRootUID yes/' /etc/clamav/clamd.conf
sed -i 's/^#OnAccessExcludeUname clamav/OnAccessExcludeUname clamav/' /etc/clamav/clamd.conf
sed -i 's/^#OnAccessExtraScanning yes/OnAccessExtraScanning yes/' /etc/clamav/clamd.conf

systemctl start clamd
clamonacc & 

aide -c /etc/aide.conf --init
mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
