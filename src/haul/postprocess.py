"""Après les téléchargements : analyse VirusTotal (vtzip) puis extraction WinRAR.

Avant d'extraire, chaque archive est vérifiée : version de WinRAR, chemins de toutes les entrées
(rien hors du dossier de destination), test d'intégrité de tous les volumes.
"""

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

# Versions antérieures : traversée de répertoire à l'extraction (CVE-2025-6218, CVE-2025-8088).
MIN_WINRAR = (7, 13)
NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)


class ScanError(Exception):
    """L'analyse n'a pas pu avoir lieu (clé API absente, vtzip en erreur…)."""


class MissingApiKey(ScanError):
    pass


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
        raise MissingApiKey("clé API VirusTotal absente (bouton « Clé VirusTotal… »)")
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


class ExtractionBlocked(Exception):
    """L'archive ne doit pas être extraite (WinRAR vulnérable, chemin dangereux, archive corrompue…)."""


def file_version(path):
    """Version (majeure, mineure) d'un exécutable Windows, ou None."""
    try:
        import ctypes
        from ctypes import wintypes
        version = ctypes.WinDLL("version")
        size = version.GetFileVersionInfoSizeW(str(path), None)
        if not size:
            return None
        buf = ctypes.create_string_buffer(size)
        if not version.GetFileVersionInfoW(str(path), 0, size, buf):
            return None
        ptr, length = ctypes.c_void_p(), wintypes.UINT()
        if not version.VerQueryValueW(buf, "\\", ctypes.byref(ptr), ctypes.byref(length)) or length.value < 16:
            return None
        ms = ctypes.cast(ptr, ctypes.POINTER(wintypes.DWORD))[2]  # VS_FIXEDFILEINFO.dwFileVersionMS
        return ms >> 16, ms & 0xFFFF
    except (OSError, AttributeError):
        return None


def winrar_problem(winrar):
    """Message si ce WinRAR ne doit pas extraire d'archives téléchargées, sinon None."""
    v = file_version(winrar)
    if v is None:
        return None  # version illisible : on ne bloque pas pour autant
    if v < MIN_WINRAR:
        return (f"WinRAR {v[0]}.{v[1]:02d} a des failles connues à l'extraction (CVE-2025-6218, CVE-2025-8088) : "
                f"installe WinRAR {MIN_WINRAR[0]}.{MIN_WINRAR[1]} ou plus récent")
    return None


def find_unrar(winrar):
    """UnRAR (console, sans fenêtre) livré avec WinRAR."""
    for name in ("UnRAR.exe", "Rar.exe"):
        path = os.path.join(os.path.dirname(winrar), name)
        if os.path.exists(path):
            return path
    return None


def _run_unrar(unrar, *args, timeout=None):
    # -p- : ne jamais demander de mot de passe ; -y : pas de question (volume manquant…)
    return subprocess.run([unrar, *args, "-p-", "-y", "--"], capture_output=True, text=True, errors="replace",
                          stdin=subprocess.DEVNULL, creationflags=NO_WINDOW, timeout=timeout)


def list_entries(unrar, first_volume):
    """Noms de toutes les entrées de l'archive, tous volumes compris."""
    r = _run_unrar(unrar, "lb", "-v", first_volume, timeout=300)
    if r.returncode != 0:
        raise ExtractionBlocked(f"archive illisible ou volume manquant (UnRAR code {r.returncode})")
    return list(dict.fromkeys(line.strip() for line in r.stdout.splitlines() if line.strip()))


def unsafe_entry(name):
    """Chemin qui écrirait hors du dossier d'extraction : absolu, lecteur, « .. », flux NTFS (« : »)."""
    n = name.replace("\\", "/")
    return n.startswith("/") or ":" in n or any(part == ".." for part in n.split("/"))


def archive_base(first_volume):
    name = os.path.basename(first_volume)
    m = VOLUME_RE.search(name)
    return name[:m.start()] if m else os.path.splitext(name)[0]


def extraction_dir(first_volume, entries):
    """Dossier de l'archive si tout son contenu est dans un seul dossier, sinon un sous-dossier à son nom.

    Évite d'éparpiller (et d'écraser) des fichiers en vrac dans le dossier de téléchargement.
    """
    folder = os.path.dirname(first_volume)
    parts = [e.replace("\\", "/").split("/", 1) for e in entries]
    tops = {p[0].lower() for p in parts}
    if len(tops) == 1 and any(len(p) == 2 for p in parts):
        return folder
    return os.path.join(folder, archive_base(first_volume))


def prepare_extraction(winrar, first_volume):
    """Vérifie l'archive avant extraction et retourne le dossier de destination.

    Lève ExtractionBlocked si WinRAR est vulnérable, si un chemin est dangereux ou si le test
    d'intégrité échoue (volume manquant ou corrompu) : rien n'est alors écrit ni écrasé.
    """
    problem = winrar_problem(winrar)
    if problem:
        raise ExtractionBlocked(problem)
    unrar = find_unrar(winrar)
    if not unrar:
        raise ExtractionBlocked("UnRAR introuvable à côté de WinRAR : archive non vérifiable")
    entries = list_entries(unrar, first_volume)
    if not entries:
        raise ExtractionBlocked("archive vide ou illisible")
    bad = [e for e in entries if unsafe_entry(e)]
    if bad:
        raise ExtractionBlocked(f"chemin dangereux dans l'archive ({bad[0][:80]})")
    r = _run_unrar(unrar, "t", "-idq", first_volume)
    if r.returncode != 0:
        detail = (r.stdout.strip() or r.stderr.strip()).splitlines()
        raise ExtractionBlocked(f"archive corrompue ou incomplète (code {r.returncode}"
                                + (f" : {detail[0][:80]}" if detail else "") + ")")
    return extraction_dir(first_volume, entries)


def extract(winrar, first_volume, dest=None):
    """Extrait dans `dest` (par défaut le dossier de l'archive). Retourne le code de sortie de WinRAR.

    x : extraire avec les dossiers ; -u : extraire et mettre à jour ; -o+ : remplacer sans demander
    """
    dest = dest or os.path.dirname(first_volume)
    os.makedirs(dest, exist_ok=True)
    cmd = [winrar, "x", "-u", "-o+", first_volume, dest.rstrip("\\/") + os.sep]
    log.info("Extraction : %s", subprocess.list2cmdline(cmd))
    return subprocess.run(cmd).returncode
