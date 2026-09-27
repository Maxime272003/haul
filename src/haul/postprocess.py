"""Après les téléchargements : analyse VirusTotal (vtzip) puis extraction WinRAR."""

import io
import json
import logging
import os
import re
import subprocess
import time
import winreg
from dataclasses import dataclass
from pathlib import Path

from .paths import REPORTS_DIR

log = logging.getLogger(__name__)

VOLUME_RE = re.compile(r"\.part(\d+)\.rar$", re.I)

# Niveaux vtzip qui bloquent l'extraction. « unknown » et « generic » ne bloquent pas : un repack
# recompressé est presque toujours inconnu de VirusTotal, et les détections génériques sont le bruit
# attendu sur un crack (voir docs/vtzip.md). « error » bloque : un fichier non vérifié ne passe pas.
BLOCKING_LEVELS = ("malicious", "suspicious", "error")


class ScanError(Exception):
    """L'analyse n'a pas pu avoir lieu (clé API absente, vtzip en erreur…)."""


# --- analyse VirusTotal ---

@dataclass
class ScanReport:
    results: list
    grouped: dict  # nom du 1er volume -> autres volumes du même jeu

    def verdicts(self):
        """{chemin normalisé: (niveau, libellé)}, y compris pour les volumes non analysés d'un jeu."""
        out, by_name = {}, {}
        for r in self.results:
            out[os.path.normcase(str(r.path))] = by_name[r.path.name] = (r.level, r.label)
        # vtzip n'analyse que le 1er volume d'un jeu : les autres prennent son verdict
        for first_name, volumes in self.grouped.items():
            if first_name in by_name:
                for v in volumes:
                    out[os.path.normcase(str(v))] = by_name[first_name]
        return out

    def as_dict(self):
        from vtzip.scanner import worst
        return {
            "results": [r.as_dict() for r in self.results],
            "verdict": worst(r.level for r in self.results),
            "grouped_volumes": {k: [str(v) for v in vs] for k, vs in self.grouped.items()},
        }

    def save(self):
        REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        path = REPORTS_DIR / time.strftime("vt-%Y%m%d-%H%M%S.json")
        path.write_text(json.dumps(self.as_dict(), indent=2, ensure_ascii=False), encoding="utf-8")
        return path

    def render_text(self, width=110):
        """Rapport détaillé de vtzip, en texte brut (pour la fenêtre « Rapport VirusTotal »)."""
        from rich.console import Console

        from vtzip.render import render_results
        buf = io.StringIO()
        console = Console(file=buf, width=width, color_system=None, highlight=False, soft_wrap=False)
        render_results(console, self.results, verbose=True, grouped=self.grouped)
        return buf.getvalue()


def scan(paths, notify=lambda message: None):
    """Analyse `paths` avec vtzip en mode --deep (hash uniquement, rien n'est envoyé)."""
    from vtzip.config import ResultCache, resolve_api_key
    from vtzip.rarscan import group_volume_sets
    from vtzip.scanner import Scanner
    from vtzip.vt import VirusTotalClient

    api_key = resolve_api_key()
    if not api_key:
        raise ScanError("clé API VirusTotal absente (commande : vtzip config set-key)")
    cache = ResultCache()
    client = VirusTotalClient(api_key, rpm=4, cache=cache,
                              on_wait=lambda s: notify(f"Quota VirusTotal atteint, pause de {s:.0f} s…"))
    scanner = Scanner(client, deep=True, notify=notify)
    targets, grouped = group_volume_sets([Path(p) for p in paths])
    try:
        results = [scanner.scan_file(t) for t in targets]
    finally:
        cache.flush()
    log.info("Analyse VirusTotal de %d fichier(s), %d requête(s)", len(targets), client.requests_made)
    return ScanReport(results, grouped)


# --- extraction WinRAR ---

def find_winrar():
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WinRAR") as key:
            path = winreg.QueryValueEx(key, "exe64")[0]
            if os.path.exists(path):
                return path
    except OSError:
        pass
    for path in (r"C:\Program Files\WinRAR\WinRAR.exe", r"C:\Program Files (x86)\WinRAR\WinRAR.exe"):
        if os.path.exists(path):
            return path
    return None


def archive_sets(jobs):
    """Regroupe les jobs .rar par archive : {chemin du premier volume: [jobs]}.

    Un jeu en plusieurs volumes (x.part01.rar, x.part02.rar…) ne s'extrait qu'une fois,
    depuis le premier volume.
    """
    groups = {}
    for job in jobs:
        if not job.name or not job.name.lower().endswith(".rar"):
            continue
        m = VOLUME_RE.search(job.name)
        base = job.name[:m.start()] if m else job.name[:-4]
        groups.setdefault((job.dest, base, bool(m)), []).append(job)
    sets = {}
    for (dest, base, multi), group in groups.items():
        if not multi:
            first = os.path.join(dest, base + ".rar")
        else:
            try:  # le volume 1 peut ne pas être dans la liste (téléchargé lors d'une session précédente)
                first = next(os.path.join(dest, f) for f in sorted(os.listdir(dest))
                             if f.lower().startswith(base.lower()) and (m := VOLUME_RE.search(f))
                             and len(f) - len(m.group(0)) == len(base) and int(m.group(1)) == 1)
            except (OSError, StopIteration):
                continue
        sets[first] = group
    return sets


def extract(winrar, first_volume):
    """Extrait dans le dossier de l'archive. Retourne le code de sortie de WinRAR (0 = succès).

    x : extraire avec les dossiers ; -u : extraire et mettre à jour ; -o+ : remplacer sans demander
    """
    cmd = [winrar, "x", "-u", "-o+", first_volume, os.path.dirname(first_volume) + os.sep]
    log.info("Extraction : %s", subprocess.list2cmdline(cmd))
    return subprocess.run(cmd).returncode
