#!/bin/bash


## Define full path of functions
PATH_FUNCTIONS="/root/scripts/lib/iptables_functions"

## Define full path of blacklist
PATH_BLACKLIST="/root/scripts/misc/blacklist"

## Define full path of init script of iptables
PATH_INIT_SCRIPT="/etc/init.d/iptables"

## Define syslog priority of iptables
SYSLOG_PRIORITY="debug"

#
# Configuration part
#
##############################

## Reset all rules
iptables -F
iptables -X
iptables -Z

## Stop running iptables
${PATH_INIT_SCRIPT} stop

## Default policy
## (These policies will be applied to rules which do not match any rules.)
iptables -P INPUT   DROP   # All discard incoming packets
iptables -P OUTPUT  ACCEPT # All permit outgoing packets
iptables -P FORWARD ACCEPT # All permit forwarding packets
#iptables -P FORWARD DROP   # All discard forwarding packets

## Discard all packets of new sessions which do not start from SYN flag
iptables -A INPUT -p tcp ! --syn -m state --state NEW -j DROP

## Deny all packets of new sessions which start from SYN/ACK flag
iptables -A INPUT -p tcp --tcp-flags SYN,ACK SYN,ACK -m state --state NEW -j REJECT --reject-with tcp-reset

## Discard all fragmented packets after logging
iptables -A INPUT -f -j LOG --log-level ${SYSLOG_PRIORITY} --log-prefix "iptables: [FRAGMENT] : "
iptables -A INPUT -f -j DROP

## Discard all packets which request over 4 times per second after logging
## (*) for TCP SYN Flood attack
iptables -N SYN_FLOOD
iptables -A SYN_FLOOD -m limit --limit 10/s --limit-burst 20 -j RETURN
iptables -A SYN_FLOOD -m limit --limit 1/s  --limit-burst 10 -j LOG \
	--log-level ${SYSLOG_PRIORITY} --log-prefix "iptables: [SYN_FLOOD]: "
iptables -A SYN_FLOOD -j DROP
iptables -A INPUT     -p tcp --syn -j SYN_FLOOD

## Discard all ping packets which request over 4 times per second after logging
## (*) for Ping of Death attack
iptables -N PING_OF_DEATH
iptables -A PING_OF_DEATH -m limit --limit 1/s --limit-burst 4 -j ACCEPT
iptables -A PING_OF_DEATH -j LOG --log-level ${SYSLOG_PRIORITY} --log-prefix "iptables: [PING_OF_DEATH]: "
iptables -A PING_OF_DEATH -j DROP
iptables -A INPUT         -p icmp --icmp-type echo-request -j PING_OF_DEATH

## Discard all packets for all host (broadcast, multicast) without logging
## (*) for not logging unnecessary packets
#iptables -A INPUT -d 255.255.255.255 -j DROP
#iptables -A INPUT -d 224.0.0.1       -j DROP

## Deny all pakcets to port 113 (IDENT)
## (*) for not delaying responses from mail servers
iptables -A INPUT -p tcp --dport 113 -j REJECT --reject-with tcp-reset

#
# Configuration for public servecies [beginning]
#

## Permit all packets to TCP port 22 (SSH)
iptables -A INPUT -p tcp --dport 22 -j ACCEPT

## Permit all packets to TCP port 21 (FTP)
iptables -A INPUT -p tcp --dport 21 -j ACCEPT

## Permit all packets to TCP/UDP port 53 (DNS)
iptables -A INPUT -p tcp --dport 53 -j ACCEPT
iptables -A INPUT -p udp --dport 53 -j ACCEPT

## Permit all packets to TCP port 80 (HTTP)
iptables -A INPUT -p tcp --dport 80 -j ACCEPT

## Permit all packets to TCP port 443 (HTTPS)
iptables -A INPUT -p tcp --dport 443 -j ACCEPT

## Permit all packets to TCP port 110 (POP3)
iptables -A INPUT -p tcp --dport 110 -j ACCEPT

## Permit all packets to TCP port 995 (POP3S)
iptables -A INPUT -p tcp --dport 995 -j ACCEPT

## Permit all packets to TCP port 143 (IMAP)
iptables -A INPUT -p tcp --dport 143 -j ACCEPT

## Permit all packets to TCP port 993 (IMAPS)
iptables -A INPUT -p tcp --dport 993 -j ACCEPT

#
# Configuration for public servecies [end]
#


## Discard all packets from aggressive IP addresses or networks after logging
if [ -s ${PATH_BLACKLIST} ]; then
	iptables -N BLACKLIST
	iptables -A BLACKLIST -j LOG --log-level ${SYSLOG_PRIORITY} --log-prefix "iptables: [BLACKLIST]: "
	iptables -A BLACKLIST -j DROP

	for ADDR in `cat ${PATH_BLACKLIST}`
	do
		iptables -I INPUT -s ${ADDR} -j BLACKLIST
	done
fi

## Discard all packets which did not match any rules above after logging
iptables -A INPUT   -m limit --limit 1/s -j LOG \
	--log-tcp-options --log-ip-options \
	--log-level ${SYSLOG_PRIORITY} --log-prefix "iptables: [DROPPED_INPUT]: "
iptables -A INPUT   -j DROP
#iptables -A FORWARD -m limit --limit 1/s -j LOG \
#	--log-tcp-options --log-ip-options \
#	--log-level ${SYSLOG_PRIORITY} --log-prefix "iptables: [DROPPED_FORWARD]: "
#iptables -A FORWARD -j DROP

## Save rules
${PATH_INIT_SCRIPT} save

## Start iptables
${PATH_INIT_SCRIPT} start

# [EOF]