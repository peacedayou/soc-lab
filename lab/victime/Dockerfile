# Machine « victime » : Ubuntu avec agent Wazuh, journaux syslog, SSH, sudo et cron.
FROM ubuntu:22.04
ARG WAZUH_VERSION=4.9.2-1
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl gnupg rsyslog openssh-server sudo cron sshpass lsb-release procps \
 && curl -fsSL https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --dearmor -o /usr/share/keyrings/wazuh.gpg \
 && echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" > /etc/apt/sources.list.d/wazuh.list \
 && apt-get update && WAZUH_MANAGER=placeholder apt-get install -y wazuh-agent=${WAZUH_VERSION} \
 && rm -rf /var/lib/apt/lists/*
# Compte de démonstration ; mot de passe connu, conteneur isolé sur le réseau du laboratoire seulement.
RUN useradd -m -s /bin/bash alice && echo 'alice:alice-lab' | chpasswd && usermod -aG sudo alice \
 && mkdir -p /run/sshd
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
