"""Teste les règles Wazuh avec wazuh-logtest dans un conteneur wazuh-manager.

    python scripts/tester_wazuh.py <nom-du-conteneur>

Chaque cas est envoyé dans une session logtest à part ; la sortie indique la règle déclenchée.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import yaml

CAS = Path(__file__).resolve().parent.parent / "tests" / "wazuh" / "cas.yml"


def logtest(conteneur: str, lignes: list[str]) -> list[str]:
    entree = "\n".join(lignes) + "\n"
    r = subprocess.run(["docker", "exec", "-i", conteneur, "/var/ossec/bin/wazuh-logtest"],
                       input=entree, capture_output=True, text=True, timeout=120)
    sortie = r.stdout + r.stderr
    return re.findall(r"id: '(\d+)'", sortie), sortie


def main(conteneur: str) -> int:
    echecs = 0
    for cas in yaml.safe_load(CAS.read_text(encoding="utf-8")):
        ids, sortie = logtest(conteneur, cas["lignes"])
        if "attendu" in cas:
            # Une règle de corrélation (fréquence) se déclenche sur l'événement qui atteint le seuil,
            # pas forcément sur le dernier envoyé : on vérifie qu'elle apparaît dans la session.
            ok = str(cas["attendu"]) in ids
            print(f"{'OK ' if ok else 'KO '} {cas['nom']} : règles {ids} (attendu {cas['attendu']})")
        else:
            ok = str(cas["interdit"]) not in ids
            print(f"{'OK ' if ok else 'KO '} {cas['nom']} : règles {ids}")
        if not ok:
            echecs += 1
            print(sortie[-2500:])
    print(f"{echecs} échec(s)")
    return 1 if echecs else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1] if len(sys.argv) > 1 else "wazuh-logtest"))
