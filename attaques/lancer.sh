#!/usr/bin/env bash
# Rejoue, dans le conteneur « victime », les attaques Linux reliées aux règles (attaques/correspondance.yml).
# Chaque étape reproduit le comportement d'un test Atomic Red Team de la même technique.
# À utiliser UNIQUEMENT dans ce laboratoire isolé.
set -euo pipefail
V=$(docker ps --filter "name=victime" --format '{{.Names}}' | head -1)
[ -n "$V" ] || { echo "Conteneur victime introuvable : lancez d'abord scripts/demarrer.sh"; exit 1; }
run() { echo "▶ $1"; docker exec "$V" bash -c "$2" || true; sleep 2; }

run "T1136.001 : création d'un compte local"        "useradd -m -s /bin/bash socuser"
run "T1098 : ajout au groupe sudo"                  "usermod -aG sudo socuser"
run "T1053.003 : crontab de persistance (alice)"     "su - alice -c \"echo '* * * * * /tmp/x.sh' | crontab -\""
run "T1548.001 : bit setuid via sudo"                "cp /bin/bash /tmp/bash-copie && echo alice-lab | su - alice -c 'sudo -S chmod u+s /tmp/bash-copie'"
run "T1110.001 : 7 mots de passe SSH erronés"        "for i in \$(seq 7); do sshpass -p mauvais ssh -o StrictHostKeyChecking=no -o PreferredAuthentications=password root@127.0.0.1 true 2>/dev/null; done"
run "T1098.004 : clé SSH ajoutée"                    "mkdir -p /root/.ssh && echo 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIL4b soc-lab' >> /root/.ssh/authorized_keys"

echo "Nettoyage…"
docker exec "$V" bash -c "userdel -r socuser 2>/dev/null; su - alice -c 'crontab -r' 2>/dev/null; rm -f /tmp/bash-copie; sed -i '/soc-lab/d' /root/.ssh/authorized_keys" || true
echo "Terminé : les alertes 1001xx apparaissent dans le tableau de bord Wazuh (filtre rule.groups: soc-lab)."
