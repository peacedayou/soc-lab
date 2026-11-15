#!/bin/bash
# Démarre les services journalisés puis inscrit l'agent auprès du gestionnaire Wazuh.
set -e
MANAGER="${WAZUH_MANAGER:-wazuh.manager}"
sed -i "s|<address>.*</address>|<address>${MANAGER}</address>|" /var/ossec/etc/ossec.conf
# Surveillance d'intégrité en temps réel des clés SSH (règle 100140)
if ! grep -q "authorized_keys" /var/ossec/etc/ossec.conf; then
  sed -i "s|<syscheck>|<syscheck>\n    <directories realtime=\"yes\">/root/.ssh,/home</directories>|" /var/ossec/etc/ossec.conf
fi
rsyslogd
service cron start
/usr/sbin/sshd
/var/ossec/bin/agent-auth -m "${MANAGER}" -A "${HOSTNAME}" || echo "Inscription refusée : vérifiez le gestionnaire Wazuh."
/var/ossec/bin/wazuh-control start
echo "Victime prête (agent ${HOSTNAME} → ${MANAGER})."
tail -F /var/log/auth.log /var/log/syslog
