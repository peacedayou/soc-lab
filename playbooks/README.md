# Fiche d'intervention automatisée (Shuffle)

Le SIEM Wazuh envoie ses alertes de niveau 10 et plus à Shuffle, qui applique la fiche
`triage-soc-lab` décrite ci-dessous.

## 1. Relier Wazuh à Shuffle

Dans Shuffle, créez un workflow avec un déclencheur **Webhook** et copiez son adresse. Ajoutez
ensuite dans `/var/ossec/etc/ossec.conf` du gestionnaire Wazuh (intégration `shuffle` fournie
par Wazuh), puis redémarrez le gestionnaire :

```xml
<integration>
  <name>shuffle</name>
  <hook_url>http://ADRESSE-DE-SHUFFLE:3001/api/v1/hooks/webhook_IDENTIFIANT</hook_url>
  <level>10</level>
  <group>soc-lab</group>
  <alert_format>json</alert_format>
</integration>
```

## 2. La fiche `triage-soc-lab`

| Étape | Action Shuffle | Détail |
| --- | --- | --- |
| 1 | Webhook | Reçoit l'alerte Wazuh (JSON) |
| 2 | Extraire | `rule.id`, `rule.mitre.id`, `agent.name`, `data.srcip`, `data.dstuser` |
| 3 | Classer | Gravité : `rule.level` ≥ 12 → **P1**, 10–11 → **P2** |
| 4 | Enrichir (facultatif) | Réputation de `data.srcip` (AbuseIPDB ou VirusTotal, clé d'API dans Shuffle, jamais dans le dépôt) |
| 5 | Ouvrir un billet | Titre `[P1] T1548.001 sur victime`, corps : alerte, technique ATT&CK, fiche à suivre ci-dessous |
| 6 | Notifier | Courriel ou message à l'analyste de garde |

## 3. Que faire pour chaque alerte (analyste)

| Règle | Technique | Vérifier | Contenir |
| --- | --- | --- | --- |
| 100100 | T1136.001 | Qui a créé le compte, depuis quelle session ? Changement prévu ? | Verrouiller le compte (`usermod -L`) |
| 100110 | T1053.003 | Contenu de la crontab, propriétaire du script appelé | Retirer l'entrée, conserver le script pour analyse |
| 100120 | T1110.001 | Adresse source, comptes visés, une connexion a-t-elle réussi ensuite ? | Bloquer l'adresse, forcer un changement de mot de passe |
| 100130 | T1548.001 | Fichier visé, utilisateur de sudo | Retirer le bit setuid (`chmod u-s`), revoir les droits sudo |
| 100140 | T1098.004 | Clé ajoutée, compte concerné | Retirer la clé, auditer les connexions récentes |
