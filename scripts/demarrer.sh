#!/usr/bin/env bash
# Démarre le laboratoire complet : Wazuh (officiel, version figée), règles du laboratoire, victime.
# Option : --shuffle pour démarrer aussi Shuffle (SOAR). Prévoir 8 Go de RAM libres (16 Go avec Shuffle).
set -euo pipefail
cd "$(dirname "$0")/.."
WAZUH_TAG="v4.9.2"

if [ ! -d .wazuh-docker ]; then
  git clone --depth 1 --branch "$WAZUH_TAG" https://github.com/wazuh/wazuh-docker.git .wazuh-docker
fi
(
  cd .wazuh-docker/single-node
  [ -f config/wazuh_indexer_ssl_certs/root-ca.pem ] \
    || docker compose -f generate-indexer-certs.yml run --rm generator
  docker compose up -d
)
MANAGER=$(docker ps --filter "name=wazuh.manager" --format '{{.Names}}' | head -1)
echo "Gestionnaire Wazuh : $MANAGER ; installation des règles du laboratoire…"
docker cp detections/wazuh/local_rules.xml "$MANAGER":/var/ossec/etc/rules/local_rules.xml
docker exec "$MANAGER" chown wazuh:wazuh /var/ossec/etc/rules/local_rules.xml
docker exec "$MANAGER" /var/ossec/bin/wazuh-control restart

docker compose up -d --build victime

if [ "${1:-}" = "--shuffle" ]; then
  [ -d .shuffle ] || git clone --depth 1 https://github.com/Shuffle/Shuffle.git .shuffle
  (cd .shuffle && docker compose up -d)
  echo "Shuffle : http://localhost:3001 (voir playbooks/README.md pour relier Wazuh)."
fi

echo
echo "Tableau de bord Wazuh : https://localhost (identifiants par défaut de wazuh-docker : changez-les)."
echo "Lancer les attaques : attaques/lancer.sh"
