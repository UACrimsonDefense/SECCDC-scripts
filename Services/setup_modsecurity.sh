#!/usr/bin/env bash

# Run: systemctl restart apache2
# If there are no errors from the configtest at the end

set -euo pipefail

if [ "$EUID" -ne 0 ]
  then echo "Please run as root"
  exit
fi

apt install -y libapache2-mod-security2

cp /etc/modsecurity/modsecurity.conf-recommended /etc/modsecurity/modsecurity.conf
sed -i "s/SecRuleEngine DetectionOnly/SecRuleEngine On/g" /etc/modsecurity/modsecurity.conf
sed -i "s/SecAuditLogParts [A-Z]*/SecAuditLogParts ABCEFHJKZ/g" /etc/modsecurity/modsecurity.conf


# If we want to send logs to a SIEM then we can make them JSON
# echo "SecAuditLogFormat JSON" >> /etc/modsecurity/modsecurity.conf

# enables Modsecurity module inside apache
a2enmod security2

wget https://github.com/coreruleset/coreruleset/archive/refs/tags/v4.23.0.tar.gz
tar -xvf v4.23.0.tar.gz 
rm v4.23.0.tar.gz
mv coreruleset-4.23.0 /etc/apache2/modsecurity-crs
cp /etc/apache2/modsecurity-crs/crs-setup.conf.example /etc/apache2/modsecurity-crs/crs-setup.conf



SEC2_CONF="/etc/apache2/mods-enabled/security2.conf"

sed -i \
  -e '/IncludeOptional \/usr\/share\/modsecurity-crs\/.*\.load/d' \
  -e '/IncludeOptional \/usr\/share\/modsecurity-crs\/.*\.conf/d' \
  -e '/IncludeOptional \/etc\/apache2\/modsecurity-crs\/crs-setup\.conf/d' \
  -e '/IncludeOptional \/etc\/apache2\/modsecurity-crs\/rules\/\*\.conf/d' \
  "$SEC2_CONF"

if ! grep -qF "IncludeOptional /etc/apache2/modsecurity-crs/crs-setup.conf" "$SEC2_CONF"; then
  sed -i '/<\/IfModule>/i IncludeOptional /etc/apache2/modsecurity-crs/crs-setup.conf' "$SEC2_CONF"
fi

if ! grep -qF "IncludeOptional /etc/apache2/modsecurity-crs/rules/*.conf" "$SEC2_CONF"; then
  sed -i '/<\/IfModule>/i IncludeOptional /etc/apache2/modsecurity-crs/rules/*.conf' "$SEC2_CONF"
fi



# Disables the following rules
# 920350 - Validates HTTP requests
# 942100 - Prevents SQLI attacks
# 931100 - Prevents Remote File Inclusion
# SEC2_CONF="/etc/apache2/mods-enabled/security2.conf"
# if ! grep -qF "SecRuleRemoveById 920350 942100 931100" "$SEC2_CONF"; then
#   sed -i '/<\/IfModule>/i \    SecRuleRemoveById 920350 942100 931100' "$SEC2_CONF"
# fi


# Might block wordpress file upload if this is not removed but we should look at specific rule ids instead
# rm /etc/apache2/modsecurity-crs/rules/REQUEST-922-MULTIPART-ATTACK.conf


apache2ctl configtest
