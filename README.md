# soc-lab

[![CI](https://github.com/peacedayou/soc-lab/actions/workflows/ci.yml/badge.svg)](https://github.com/peacedayou/soc-lab/actions/workflows/ci.yml)

Laboratoire de **centre des opérations de sécurité (SOC)** en Docker : Wazuh comme SIEM, règles
**Sigma** reliées à **MITRE ATT&CK**, attaques simulées inspirées d'**Atomic Red Team**, et fiche
d'intervention automatisée dans **Shuffle** (SOAR).

**Couverture ATT&CK :** https://peacedayou.github.io/soc-lab/ (avec la couche ATT&CK Navigator).

## Le cycle

1. **Attaquer** : `attaques/lancer.sh` rejoue six techniques Linux dans un conteneur victime ;
   les techniques Windows se jouent sur une VM de test avec `Invoke-AtomicTest`.
2. **Détecter** : l'agent Wazuh de la victime envoie ses journaux ; les règles du laboratoire
   (`1001xx`) s'appliquent et portent leur technique ATT&CK.
3. **Répondre** : Wazuh transmet les alertes à Shuffle, qui classe, enrichit et ouvre un billet
   (`playbooks/README.md`, avec la marche à suivre de l'analyste pour chaque règle).
4. **Mesurer** : `scripts/soclab.py couverture` produit la page et la couche ATT&CK Navigator.

## Détections

| Technique | Règle Sigma | Règle Wazuh |
| --- | --- | --- |
| T1136.001 Création de compte local | `linux/creation_compte_local` | 100100 |
| T1098 Ajout à un groupe privilégié | `linux/ajout_groupe_sudo` | — |
| T1053.003 Crontab | `linux/modification_crontab` | 100110 |
| T1110.001 Force brute SSH | `linux/ssh_echecs_repetes` | 100120 (6 échecs en 2 min, même source) |
| T1548.001 Bit setuid | `linux/setuid_via_sudo` | 100130 |
| T1098.004 Clé SSH ajoutée | — | 100140 (surveillance d'intégrité) |
| T1059.001 PowerShell encodé | `windows/powershell_encodee` | — |
| T1105 Téléchargement certutil | `windows/certutil_telechargement` | — |
| T1490 Suppression des clichés VSS | `windows/suppression_cliches_vss` | — |
| T1053.005 Tâche planifiée | `windows/tache_planifiee_creee` | — |
| T1547.001 Clé Run du registre | `windows/cle_run_registre` | — |

## Tests (CI GitHub Actions)

- **Sigma** : chaque règle est convertie par pySigma, puis exécutée (moteur SQLite) sur ses
  événements d'attaque, qu'elle doit détecter, et sur des événements normaux, qu'elle doit
  ignorer. Le test vérifie aussi les métadonnées : technique ATT&CK, faux positifs documentés,
  attaque de test associée.
- **Wazuh** : les règles sont chargées dans un vrai `wazuh-manager` 4.9.2 et testées avec
  `wazuh-logtest` sur des journaux syslog réalistes, y compris le seuil de la force brute et un
  cas qui ne doit pas déclencher d'alerte. La règle 100140 (intégrité de fichiers) se vérifie
  dans le laboratoire en direct.
- **Laboratoire** : construction de l'image victime et vérification des scripts.

```bash
pip install -r requirements.txt
python scripts/soclab.py tester
```

## Démarrer le laboratoire

Prévoir Docker et 8 Go de RAM libres (16 Go avec Shuffle).

```bash
scripts/demarrer.sh            # Wazuh officiel (v4.9.2) + règles + victime
scripts/demarrer.sh --shuffle  # avec Shuffle
attaques/lancer.sh             # rejoue les attaques Linux, puis nettoie
```

Le SIEM vient du dépôt officiel `wazuh-docker`, à une version figée, plutôt que d'une copie de
sa configuration : on profite de ses certificats et de ses mises à jour. Changez les mots de
passe par défaut avant d'exposer quoi que ce soit, et n'exécutez les attaques que dans ce
laboratoire isolé.

## Licence

MIT
