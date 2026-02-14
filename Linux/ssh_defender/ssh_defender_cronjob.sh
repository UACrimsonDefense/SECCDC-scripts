#!/bin/sh
# This script is meant to be run as a cron job with root privileges every minute. It fixes the passwd and shadow files, kicks out evil people, and restarts the ssh daemon should it not be running.

set -eu # exit on errors

# Kill evil users
tmp1=$(mktemp)
tmp2=$(mktemp)
awk -F: '{print $1}' /etc/passwd | sort > "$tmp1"
awk -F: '{print $1}' /tmp/.passwd.copy | sort > "$tmp2"
comm -23 "$tmp1" "$tmp2" | while IFS= read -r evil_user
do
    [ -n "$evil_user" ] || continue

	echo "Killing ${evil_user} now!"

	# Kill all processes started by evil users
#    ps -eo user=,pid= | awk -v u="$evil_user" '$1==u {print $2}' | \
#    while IFS= read -r pid
#    do
#        kill -9 "$pid" 2>/dev/null || true
#    done


	uid=$(id -u "$evil_user") || continue

	ps -eo uid=,pid= | awk -v u="$uid" '$1==u {print $2}' | \
	while IFS= read -r pid
	do
		kill -9 "$pid" 2>/dev/null || true
	done
done
rm -f "$tmp1" "$tmp2"

# Correct any modifications to the original /etc/passwd & /etc/shadow files
cp /tmp/.passwd.copy /etc/passwd
cp /tmp/.shadow.copy /etc/shadow

# If ssh isn't running, restart ssh
if ! systemctl is-active --quiet ssh; then
	systemctl start ssh
fi
