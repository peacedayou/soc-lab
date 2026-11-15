"""Outils du laboratoire : validation des règles Sigma, tests sur événements, couverture ATT&CK.

    python scripts/soclab.py tester      # convertit chaque règle (pySigma) et la teste sur ses événements
    python scripts/soclab.py couverture  # écrit la couche ATT&CK Navigator et la page de couverture
"""

from __future__ import annotations

import html
import json
import re
import sqlite3
import sys
from pathlib import Path

import yaml
from sigma.backends.sqlite import sqliteBackend
from sigma.collection import SigmaCollection

RACINE = Path(__file__).resolve().parent.parent
SIGMA = RACINE / "detections" / "sigma"
EVENEMENTS = RACINE / "tests" / "sigma" / "evenements.yml"
ATOMIQUES = RACINE / "attaques" / "correspondance.yml"
TECH_RE = re.compile(r"^attack\.t\d{4}(\.\d{3})?$")
NIVEAUX = {"informational", "low", "medium", "high", "critical"}


def regles() -> list[tuple[Path, object]]:
    out = []
    for p in sorted(SIGMA.rglob("*.yml")):
        coll = SigmaCollection.from_yaml(p.read_text(encoding="utf-8"))
        if len(coll.rules) != 1:
            raise SystemExit(f"{p.name} : une seule règle par fichier")
        out.append((p, coll.rules[0]))
    return out


def techniques(regle) -> list[str]:
    return [str(t)[len("attack."):].upper() for t in regle.tags if TECH_RE.match(str(t))]


def verifier_metadonnees(liste) -> list[str]:
    erreurs, ids = [], set()
    atomiques = yaml.safe_load(ATOMIQUES.read_text(encoding="utf-8"))
    for p, r in liste:
        nom = p.stem
        if str(r.id) in ids:
            erreurs.append(f"{nom} : identifiant en double")
        ids.add(str(r.id))
        if not techniques(r):
            erreurs.append(f"{nom} : aucune technique ATT&CK dans les tags")
        if str(r.level.name).lower() not in NIVEAUX:
            erreurs.append(f"{nom} : niveau invalide")
        if not r.falsepositives:
            erreurs.append(f"{nom} : faux positifs non documentés")
        if nom not in atomiques:
            erreurs.append(f"{nom} : aucune attaque Atomic Red Team associée dans attaques/correspondance.yml")
        elif atomiques[nom]["technique"] not in techniques(r):
            erreurs.append(f"{nom} : la technique de l'attaque associée ne correspond pas aux tags")
    return erreurs


def tester() -> int:
    liste = regles()
    erreurs = verifier_metadonnees(liste)
    cas = yaml.safe_load(EVENEMENTS.read_text(encoding="utf-8"))
    backend = sqliteBackend()
    for p, r in liste:
        nom = p.stem
        if nom not in cas:
            erreurs.append(f"{nom} : aucun événement de test")
            continue
        requete = backend.convert(SigmaCollection([r]))[0]
        evts = [(e, True) for e in cas[nom]["positifs"]] + [(e, False) for e in cas[nom].get("negatifs", [])]
        champs = sorted({k for e, _ in evts for k in e})
        db = sqlite3.connect(":memory:")
        db.execute("CREATE TABLE logs (rowid_cas INTEGER, " + ", ".join(f'"{c}" TEXT' for c in champs) + ")")
        for i, (e, _) in enumerate(evts):
            db.execute(f"INSERT INTO logs VALUES ({i}, " + ", ".join("?" for _ in champs) + ")", [e.get(c) for c in champs])
        trouves = {row[0] for row in db.execute(requete.replace("SELECT *", "SELECT rowid_cas", 1))}
        for i, (e, attendu) in enumerate(evts):
            if (i in trouves) != attendu:
                erreurs.append(f"{nom} : {'non détecté' if attendu else 'faux positif'} sur {e}")
        print(f"{'OK ' if not [x for x in erreurs if x.startswith(nom)] else 'KO '} {nom:28} {', '.join(techniques(r)):12} {len(evts)} cas")
    for e in erreurs:
        print("ERREUR", e)
    print(f"{len(liste)} règles, {len(erreurs)} erreur(s)")
    return 1 if erreurs else 0


def couverture(sortie: Path) -> int:
    liste = regles()
    atomiques = yaml.safe_load(ATOMIQUES.read_text(encoding="utf-8"))
    tech = {}
    for p, r in liste:
        for t in techniques(r):
            tech.setdefault(t, []).append((p, r))
    couche = {
        "name": "soc-lab : couverture de détection",
        "versions": {"layer": "4.5", "navigator": "5.1.0", "attack": "16"},
        "domain": "enterprise-attack",
        "description": "Techniques couvertes par au moins une règle Sigma testée du laboratoire.",
        "techniques": [
            {"techniqueID": t, "score": len(v), "color": "#2f9e44",
             "comment": "; ".join(str(r.title) for _, r in v)} for t, v in sorted(tech.items())
        ],
        "gradient": {"colors": ["#ffffff", "#2f9e44"], "minValue": 0, "maxValue": 2},
    }
    sortie.mkdir(parents=True, exist_ok=True)
    (sortie / "couche-attack.json").write_text(json.dumps(couche, ensure_ascii=False, indent=1), encoding="utf-8")
    lignes = []
    for p, r in liste:
        a = atomiques[p.stem]
        t = techniques(r)[0]
        lignes.append(
            f"<tr><td><a href='https://attack.mitre.org/techniques/{t.replace('.', '/')}/'>{t}</a></td>"
            f"<td>{html.escape(str(r.title))}</td><td>{p.parent.name}</td><td>{str(r.level.name).lower()}</td>"
            f"<td><code>{html.escape(a['commande'])}</code></td>"
            f"<td><a href='https://github.com/peacedayou/soc-lab/blob/main/{p.relative_to(RACINE)}'>règle</a></td></tr>")
    page = (RACINE / "docs" / "modele.html").read_text(encoding="utf-8")
    page = page.replace("{{LIGNES}}", "\n".join(lignes)).replace("{{NB_REGLES}}", str(len(liste))).replace("{{NB_TECH}}", str(len(tech)))
    (sortie / "index.html").write_text(page, encoding="utf-8")
    print(f"{len(liste)} règles, {len(tech)} techniques → {sortie}")
    return 0


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "tester"
    if cmd == "tester":
        raise SystemExit(tester())
    if cmd == "couverture":
        raise SystemExit(couverture(Path(sys.argv[2]) if len(sys.argv) > 2 else RACINE / "_site"))
    raise SystemExit(__doc__)
