#!/usr/bin/env -S sudo -- sh
O_5X=89
O_XX=39

DC="10.250.$O_5X.10"
DNS="10.250.$O_5X.250"
INFRA="10.250.250.0/24"
OFF_LIM="10.250.1$O_XX.0/2"
BTA="169.254.169.254"
BTAS="10.250.250.11"

SSH_PORT=22

# What inbound services need to be allowed for this machine?
SCORED=(
#    "DNS"           # DNS
#    "22/tcp"        # FTP
#    "WWW"           # HTTP
#    "WWW Secure"    # HTTPS
#    "LDAP"          # LDAP
#    "LDAPS"         # LDAPS
#    "Kerberos Full" # Kerberos
#    "3389/tcp"      # RDP
#    "CIFS"          # SMB
#    "SSH"           # SSH
#    "5985/tcp"      # WinRM 
#    "5986/tcp"      # WinRM-S
#    "POP3"          # POP3
#    "POP3S"         # POP3S
#    "IMAP"          # IMAP
#    "IMAPS"         # IMAPS
#    "SMTP"          # SMTP
)

# What machines and ports/apps does this need outbound access to?
# Please use only the port syntax and not app syntax, UFW will complain otherwise
DEPS=(
#    "proto tcp to 10.250.$O_5X.10 port 443"
)


echo 'y' | ufw reset 
ufw disable 

ufw default deny incoming
ufw default deny outgoing 
ufw default deny routed

ufw allow   $SSH_PORT/tcp
ufw allow   from $OFF_LIM
ufw allow   from $INFRA

for scored in "${SCORED[@]}"; do 
    ufw allow "$scored"
done

for dep in "${DEPS[@]}"; do 
    ufw allow out $dep
done

ufw allow   out to $OFF_LIM
ufw allow   out to $BTA port 80 
ufw allow   out to $BTAS port 443
ufw deny    out proto tcp to 10.0.0.0/8   port 443
ufw deny    out proto tcp to 10.0.0.0/8   port 80
ufw allow   out proto tcp to any          port 443
ufw allow   out proto tcp to any          port 80

ufw allow out to $DNS app dns
ufw allow out to $DC  app ldap
ufw allow out to $DC  app "Kerberos KDC"

ufw enable 
ufw reload
