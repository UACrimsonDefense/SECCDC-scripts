#!/usr/bin/env -S sudo -- sh

yum --enablerepo epel install fail2ban
dnf install -y lynis clamav clamd clamav-update ufw neovim aide fail2ban python-inotify
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
