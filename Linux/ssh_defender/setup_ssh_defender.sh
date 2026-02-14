#!/bin/sh
# This script sets up 'ssh_defender_cronjob.sh' as a cronjob

# If script not run with sudo, tell user that I need sudo
if [ "$(id -u)" -ne 0 ]; then
	echo "This script must be run with sudo"
	exit 1
fi

cp /etc/passwd /tmp/.passwd.copy
cp /etc/shadow /tmp/.shadow.copy

cp ssh_defender_cronjob.sh /usr/local/bin/
chmod 700 /usr/local/bin/ssh_defender_cronjob.sh

touch /etc/cron.d/ssh_defender_caller
echo "* * * * * root /bin/sh /usr/local/bin/ssh_defender_cronjob.sh" > /etc/cron.d/ssh_defender_caller

echo "Success! (probably)"
