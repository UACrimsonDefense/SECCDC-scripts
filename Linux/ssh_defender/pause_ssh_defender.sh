#!/bin/sh
# If script not run with sudo, tell user that I need sudo
if [ "$(id -u)" -ne 0 ]; then
	echo "This script must be run with sudo"
	exit 1
fi

echo "# * * * * * root /bin/sh /usr/local/bin/ssh_defender_cronjob.sh" > /etc/cron.d/ssh_defender_caller
