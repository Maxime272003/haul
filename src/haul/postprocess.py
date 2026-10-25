"""Après les téléchargements : analyse VirusTotal (vtzip) puis extraction.

Avant d'extraire, chaque archive est vérifiée : version de WinRAR, chemins et types de toutes les
entrées (rien hors du dossier de destination, pas de lien symbolique), place sur le disque. UnRAR
extrait ensuite dans un dossier temporaire à côté de l'archive (CRC vérifiés au passage, une seule
lecture des volumes), renommé à la fin : rien d'existant n'est écrasé, et un échec ne laisse rien.
"""

import io
import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
import time
import winreg
from dataclasses import dataclass
from pathlib import Path

from .engine import ON_DISK, State
from .links import VOLUME_RE, archive_base, folder_name, human_size
from .paths import REPORTS_DIR

log = logging.getLogger(__name__)

# Niveaux vtzip qui bloquent l'extraction. « unknown » et « generic » ne bloquent pas : un repack
# recompressé est presque toujours inconnu de VirusTotal, et les détections génériques sont le bruit
# attendu sur un crack (voir docs/vtzip.md). « error » bloque : un fichier non vérifié ne passe pas.
BLOCKING_LEVELS = ("malicious", "suspicious", "error")

# Versions antérieures : traversée de répertoire à l'extraction (CVE-2025-6218, CVE-2025-8088).
MIN_WINRAR = (7, 13)
NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)
# Types d'entrées extraits tels quels ; liens symboliques, jonctions, liens durs et références de
# fichier peuvent faire écrire hors du dossier d'extraction : l'archive est refusée.
SAFE_TYPES = ("file", "directory")
DISK_MARGIN = 256 << 20  # espace laissé libre en plus du contenu extrait
PERCENT_RE = re.compile(rb"(\d{1,3})%")


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


# --- quels fichiers traiter ---

def set_key(job):
    """Identifiant du jeu de volumes d'un fichier .rar (dossier, nom commun, multi-volumes), sinon None."""
    base = archive_base(job.name)
    if base is None:
        return None
    return os.path.normcase(job.dest), base.lower(), bool(VOLUME_RE.search(job.name))


def ready_for_postprocess(jobs):
    """Fichiers téléchargés pas encore traités, dont tout le jeu de volumes présent dans la liste est fini.

    Une archive est analysée et extraite dès que ses volumes sont sur le disque, sans attendre le
    reste de la liste ; un volume en cours, en pause ou en échec la fait attendre.
    """
    jobs = list(jobs)
    unfinished = {set_key(j) for j in jobs if j.state not in ON_DISK} - {None}
    return [j for j in jobs if j.state in ON_DISK and j.path and not j.processed and set_key(j) not in unfinished]


# --- extraction ---

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
        base = archive_base(job.name)
        if base is None:
            continue
        groups.setdefault((job.dest, base, bool(VOLUME_RE.search(job.name))), []).append(job)
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


def same_set(first_volume, name):
    """`name` est un volume du même jeu que `first_volume` (même nom commun, même découpage)."""
    first = os.path.basename(first_volume)
    base = archive_base(name)
    return (base is not None and base.lower() == archive_base(first).lower()
            and bool(VOLUME_RE.search(name)) == bool(VOLUME_RE.search(first)))


def set_volumes(first_volume):
    """Chemins de tous les volumes du jeu présents sur le disque."""
    folder = os.path.dirname(first_volume)
    try:
        return [os.path.join(folder, f) for f in sorted(os.listdir(folder))
                if same_set(first_volume, f) and os.path.isfile(os.path.join(folder, f))]
    except OSError:
        return []


class ExtractionBlocked(Exception):
    """L'archive ne doit pas être extraite (WinRAR vulnérable, chemin dangereux, place insuffisante…)."""


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


def unrar_command(unrar, command, archive, *rest, switches=()):
    # -p- : ne jamais demander de mot de passe ; -y : pas de question (volume manquant…) ;
    # -c- : pas de commentaire d'archive (il pourrait imiter des lignes du listage)
    return [unrar, command, *switches, "-p-", "-y", "-c-", "--", archive, *rest]


def _run_unrar(unrar, command, archive, *rest, switches=(), timeout=None):
    return subprocess.run(unrar_command(unrar, command, archive, *rest, switches=switches), capture_output=True,
                          text=True, errors="replace", stdin=subprocess.DEVNULL, creationflags=NO_WINDOW,
                          timeout=timeout)


def list_entries(unrar, first_volume):
    """Noms de toutes les entrées de l'archive, tous volumes compris."""
    r = _run_unrar(unrar, "lb", first_volume, switches=("-v",), timeout=300)
    if r.returncode != 0:
        raise ExtractionBlocked(f"archive illisible ou volume manquant (UnRAR code {r.returncode})")
    return list(dict.fromkeys(line.strip() for line in r.stdout.splitlines() if line.strip()))


def parse_technical_listing(text):
    """{nom: (type en minuscules, taille ou None)} d'après le listage technique d'UnRAR (lt).

    Une entrée coupée entre deux volumes apparaît dans chacun : on garde la plus grande taille.
    """
    entries, name = {}, None
    for line in text.splitlines():
        key, sep, value = line.strip().partition(": ")
        if not sep:
            continue
        if key == "Name":
            name = value
            entries.setdefault(name, ("file", None))
        elif name is not None and key == "Type":
            entries[name] = (value.strip().lower(), entries[name][1])
        elif name is not None and key == "Size" and value.strip().isdigit():
            kind, size = entries[name]
            entries[name] = (kind, max(size or 0, int(value)))
    return entries


def technical_listing(unrar, first_volume):
    """Types et tailles des entrées ({} si le listage n'est pas lisible : UnRAR traduit, ancien format)."""
    r = _run_unrar(unrar, "lt", first_volume, switches=("-v",), timeout=300)
    return parse_technical_listing(r.stdout) if r.returncode == 0 else {}


def unsafe_entry(name):
    """Chemin qui écrirait hors du dossier d'extraction : absolu, lecteur, « .. », flux NTFS (« : »)."""
    n = name.replace("\\", "/")
    return n.startswith("/") or ":" in n or any(part == ".." for part in n.split("/"))


def check_entries(names, details, folder, free_space=None):
    """Lève ExtractionBlocked pour un chemin dangereux, un lien, ou un contenu plus grand que la place libre."""
    if not names:
        raise ExtractionBlocked("archive vide ou illisible")
    bad = [e for e in names if unsafe_entry(e)]
    if bad:
        raise ExtractionBlocked(f"chemin dangereux dans l'archive ({bad[0][:80]})")
    links = [(n, kind) for n, (kind, _) in details.items() if kind not in SAFE_TYPES]
    if links:
        raise ExtractionBlocked(f"lien dans l'archive ({links[0][1]} : {links[0][0][:80]})")
    size = sum(s or 0 for kind, s in details.values() if kind == "file")
    free = shutil.disk_usage(folder).free if free_space is None else free_space
    if size and size + DISK_MARGIN > free:
        raise ExtractionBlocked(f"espace disque insuffisant : {human_size(size)} à extraire, "
                                f"{human_size(free)} libres")


def prepare_extraction(winrar, first_volume):
    """Vérifie l'archive avant extraction et retourne UnRAR.

    Lève ExtractionBlocked si WinRAR est vulnérable, si une entrée est dangereuse ou si la place
    manque : rien n'est alors écrit. L'intégrité (CRC de chaque fichier, volumes manquants ou
    tronqués) est vérifiée par l'extraction elle-même, dans un dossier temporaire.
    """
    problem = winrar_problem(winrar)
    if problem:
        raise ExtractionBlocked(problem)
    unrar = find_unrar(winrar)
    if not unrar:
        raise ExtractionBlocked("UnRAR introuvable à côté de WinRAR : archive non vérifiable")
    check_entries(list_entries(unrar, first_volume), technical_listing(unrar, first_volume),
                  os.path.dirname(first_volume))
    return unrar


def unique_path(path):
    """`path`, ou « path (2) », « path (3) »… s'il existe déjà."""
    candidate, n = path, 2
    while os.path.lexists(candidate):
        candidate, n = f"{path} ({n})", n + 1
    return candidate


def place_extracted(tmp, first_volume):
    """Range le contenu extrait dans `tmp` sans rien écraser ; retourne le dossier où il se trouve.

    - dossier propre au jeu (créé par « Un dossier par jeu », ou qui ne contient que ses volumes) : le
      contenu y va directement, à côté des fichiers bonus (fg-optional-*.bin) téléchargés avec le jeu ;
    - tout le contenu dans un seul dossier : ce dossier, à côté de l'archive ;
    - sinon : un sous-dossier au nom du jeu.
    Un nom déjà pris reçoit un suffixe « (2) » : une version précédente (sauvegardes, réglages) reste intacte.
    """
    folder = os.path.dirname(first_volume)
    name = os.path.basename(first_volume)
    tops = os.listdir(tmp)
    others = [n for n in os.listdir(folder)
              if os.path.join(folder, n) != tmp and not same_set(first_volume, n)]
    dedicated = not others or os.path.basename(folder) == folder_name(name)
    if dedicated and not any(os.path.lexists(os.path.join(folder, t)) for t in tops):
        for t in tops:
            os.replace(os.path.join(tmp, t), os.path.join(folder, t))
        os.rmdir(tmp)
        return folder
    if len(tops) == 1 and os.path.isdir(os.path.join(tmp, tops[0])):
        target = unique_path(os.path.join(folder, tops[0]))
        os.replace(os.path.join(tmp, tops[0]), target)
        os.rmdir(tmp)
        return target
    target = unique_path(os.path.join(folder, folder_name(name) or archive_base(name)))
    os.replace(tmp, target)
    return target


def extract(unrar, first_volume, on_progress=lambda percent: None):
    """Extrait l'archive à côté d'elle, sans rien écraser. Retourne (code UnRAR, dossier ou None).

    UnRAR écrit dans un dossier temporaire caché du même disque (renommage instantané à la fin) ;
    en cas d'échec il est supprimé.
    """
    folder = os.path.dirname(first_volume)
    tmp = tempfile.mkdtemp(prefix=".haul-", dir=folder)
    cmd = unrar_command(unrar, "x", first_volume, tmp + os.sep, switches=("-o+", "-idc"))
    log.info("Extraction : %s", subprocess.list2cmdline(cmd))
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                                creationflags=NO_WINDOW)
        last = None
        while chunk := proc.stdout.read1(4096):
            percents = PERCENT_RE.findall(chunk)
            if percents and percents[-1] != last:
                last = percents[-1]
                on_progress(min(100, int(last)))
        code = proc.wait()
        if code != 0:
            return code, None
        return 0, place_extracted(tmp, first_volume)
    finally:
        if os.path.isdir(tmp):
            shutil.rmtree(tmp, ignore_errors=True)


def recycle(paths):
    """Envoie des fichiers à la corbeille ; True si tout est parti (sinon rien n'est supprimé de force)."""
    if not paths:
        return True
    try:
        import ctypes
        from ctypes import wintypes

        class SHFILEOPSTRUCTW(ctypes.Structure):
            if ctypes.sizeof(ctypes.c_void_p) == 4:
                _pack_ = 1  # shellapi.h : structure compactée en 32 bits
            _fields_ = [("hwnd", wintypes.HWND), ("wFunc", wintypes.UINT), ("pFrom", ctypes.c_void_p),
                        ("pTo", ctypes.c_void_p), ("fFlags", wintypes.WORD), ("fAnyOperationsAborted", wintypes.BOOL),
                        ("hNameMappings", ctypes.c_void_p), ("lpszProgressTitle", ctypes.c_void_p)]

        names = "\0".join(os.path.abspath(p) for p in paths) + "\0\0"
        buf = (ctypes.c_wchar * len(names))(*names)
        op = SHFILEOPSTRUCTW()
        op.wFunc = 3  # FO_DELETE
        op.pFrom = ctypes.cast(buf, ctypes.c_void_p)
        op.fFlags = 0x40 | 0x10 | 0x4 | 0x400  # ALLOWUNDO | NOCONFIRMATION | SILENT | NOERRORUI
        shell32 = ctypes.WinDLL("shell32")  # instance privée : argtypes sans effet sur ctypes.windll
        shell32.SHFileOperationW.argtypes = [ctypes.POINTER(SHFILEOPSTRUCTW)]
        code = shell32.SHFileOperationW(ctypes.byref(op))
        return code == 0 and not op.fAnyOperationsAborted and not any(os.path.exists(p) for p in paths)
    except (OSError, AttributeError):
        log.warning("Corbeille indisponible", exc_info=True)
        return False


# --- enchaînement : analyse puis extraction d'un lot (thread de travail) ---

def process(batch, scan_files, winrar, put, status, delete_archives=False, on_report=lambda report: None,
            on_missing_key=lambda: None):
    """Analyse puis extrait `batch` (jobs sur le disque).

    put(job, **champs) publie un changement de fichier, status(message, done=False, kind=None) un
    message de la barre d'état ; le dernier a done=True. Les jobs ne sont jamais modifiés ici.
    """
    def set_state(job, state, detail=""):
        put(job, state=state, detail=detail)

    if scan_files:
        for job in batch:
            put(job, vt="Analyse…")
        status("Analyse VirusTotal en cours (quota gratuit : 4 requêtes/min, compte quelques minutes)…")
        try:
            report = scan([j.path for j in batch], notify=status)
        except Exception as e:
            log.exception("Analyse VirusTotal impossible")
            for job in batch:
                put(job, vt="non analysé", processed=False)  # à refaire une fois le problème réglé
            if isinstance(e, MissingApiKey):
                on_missing_key()
            return status(f"Analyse VirusTotal impossible : {e}. Extraction non lancée.", done=True, kind="error")
        on_report(report)
        try:
            report.save()
        except OSError:
            log.exception("Rapport VirusTotal non enregistré")
        verdicts = report.verdicts()
        blocking = []
        for job in batch:
            level, label = verdicts.get(os.path.normcase(job.path), ("error", "non analysé"))
            put(job, vt=label)
            if level in BLOCKING_LEVELS:
                blocking.append(f"{job.name} : {label}")
        if blocking:
            log.warning("Extraction bloquée par l'analyse : %s", blocking)
            if winrar:
                for job in batch:
                    if archive_base(job.name) is not None:
                        set_state(job, State.BLOCKED, "Extraction bloquée : analyse VirusTotal")
            more = f" (+{len(blocking) - 1})" if len(blocking) > 1 else ""
            return status(f"Extraction bloquée — {blocking[0]}{more}. Clique « Rapport VirusTotal ».",
                          done=True, kind="error")
        if not winrar:
            return status("Analyse VirusTotal terminée : rien de bloquant.", done=True)

    todo = archive_sets(batch)
    if not todo:
        return status("Rien de bloquant, aucune archive .rar à extraire.", done=True)
    ok, failures, freed = 0, [], 0
    for first, group in todo.items():
        name = os.path.basename(first)
        for job in group:
            set_state(job, State.CHECKING)
        status(f"Vérification de {name} avant extraction…")
        try:
            unrar = prepare_extraction(winrar, first)
        except (ExtractionBlocked, OSError, subprocess.SubprocessError) as e:
            log.warning("Extraction de %s bloquée : %s", first, e)
            for job in group:
                set_state(job, State.BLOCKED, f"Extraction bloquée : {e}")
            failures.append(f"{name} : {e}")
            continue
        for job in group:
            set_state(job, State.EXTRACTING)
        status(f"Extraction de {name}…")

        def progress(percent, group=group):
            for job in group:
                set_state(job, State.EXTRACTING, f"Extraction… {percent} %")

        try:
            code, dest = extract(unrar, first, progress)
        except OSError as e:
            log.exception("Extraction impossible")
            code, dest = str(e), None
        if code != 0:
            failures.append(f"{name} : code {code}")
            for job in group:
                set_state(job, State.EXTRACT_FAILED, f"Échec extraction (code {code}) : archive corrompue ou "
                                                     "incomplète ?")
            continue
        ok += 1
        where = os.path.relpath(dest, os.path.dirname(first))
        detail = "" if where == "." else f"Extrait ✔ dans {where}{os.sep}"
        if delete_archives:
            volumes = set_volumes(first)
            size = sum(os.path.getsize(v) for v in volumes)
            if recycle(volumes):
                freed += size
                detail = (detail or "Extrait ✔") + " · archives à la corbeille"
        for job in group:
            set_state(job, State.EXTRACTED, detail)
    message = ("Analyse OK, " if scan_files else "") + f"extraction : {ok}/{len(todo)} archive(s) extraite(s)."
    if freed:
        message += f" {human_size(freed)} d'archives envoyés à la corbeille."
    if failures:
        message += f" Problème — {failures[0]}" + (f" (+{len(failures) - 1})" if len(failures) > 1 else "")
    status(message, done=True, kind="ok" if ok == len(todo) else "warn" if ok else "error")
