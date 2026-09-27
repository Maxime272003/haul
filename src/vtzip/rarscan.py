"""Inspection d'une archive RAR sans l'extraire, via UnRAR.

Python n'a pas de lecteur RAR dans sa bibliotheque standard : on delegue a
UnRAR.exe (livre avec WinRAR) et on reutilise ensuite exactement les memes
heuristiques que pour un ZIP.

Le listage est parse sur la structure du tableau, pas sur les libelles : UnRAR
est localise (`Nom`/`Taille` en francais, `Name`/`Size` en anglais) et se fier
aux libelles casserait selon la machine. Les lignes de donnees se trouvent entre
les deux separateurs en tirets, avec les colonnes :

    [*] attributs  taille  date  heure  nom

Le `*` en tete de ligne signale une entree dont les donnees sont chiffrees.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

from .zipscan import WARN, ArchiveReport, Entry, Finding, analyze_entries

# Sous Windows, n'ouvre pas de console pour UnRAR quand l'appelant n'en a pas (application graphique).
NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)

# Emplacements usuels de UnRAR sur Windows, en plus du PATH.
UNRAR_CANDIDATES = (
    r"C:\Program Files\WinRAR\UnRAR.exe",
    r"C:\Program Files\WinRAR\Rar.exe",
    r"C:\Program Files (x86)\WinRAR\UnRAR.exe",
    r"C:\Program Files\7-Zip\7z.exe",
    r"C:\Program Files (x86)\7-Zip\7z.exe",
)

SEPARATOR_RE = re.compile(r"^-{5,}")
# Volumes modernes : nom.part01.rar / anciens : nom.rar + nom.r00, nom.r01...
PART_RE = re.compile(r"^(?P<stem>.+)\.part(?P<num>\d+)\.rar$", re.IGNORECASE)
LEGACY_RE = re.compile(r"^(?P<stem>.+)\.r(?P<num>\d{2,3})$", re.IGNORECASE)

# Codes de sortie UnRAR qui nous interessent.
EXIT_WRONG_PASSWORD = 11
EXIT_NO_FILES = 10

_unrar_cache: str | None | bool = False


def find_unrar() -> str | None:
    """Localise UnRAR (ou 7z). Surchargeable via la variable VTZIP_UNRAR."""
    global _unrar_cache
    if _unrar_cache is not False:
        return _unrar_cache  # type: ignore[return-value]

    override = os.environ.get("VTZIP_UNRAR")
    if override and Path(override).is_file():
        _unrar_cache = override
        return override
    for name in ("unrar", "UnRAR", "7z", "rar"):
        found = shutil.which(name)
        if found:
            _unrar_cache = found
            return found
    for candidate in UNRAR_CANDIDATES:
        if Path(candidate).is_file():
            _unrar_cache = candidate
            return candidate
    _unrar_cache = None
    return None


def _is_seven_zip(executable: str) -> bool:
    return Path(executable).stem.lower() in ("7z", "7za", "7zr")


def parse_unrar_listing(output: str) -> list[Entry]:
    """Extrait les entrees du tableau `unrar l`, sans dependre de la langue."""
    entries: list[Entry] = []
    in_table = False
    for line in output.splitlines():
        if SEPARATOR_RE.match(line.strip()):
            if in_table:
                break  # second separateur : fin du tableau
            in_table = True
            continue
        if not in_table or not line.strip():
            continue

        encrypted = line.lstrip().startswith("*")
        row = line.replace("*", " ", 1) if encrypted else line
        fields = row.split(None, 4)
        if len(fields) < 5:
            continue
        attrs, size_text, _date, _time, name = fields
        try:
            size = int(size_text)
        except ValueError:
            continue  # ligne de total ou en-tete localise
        is_dir = "D" in attrs.upper() or attrs.startswith("d")
        entries.append(
            Entry(
                name=name.strip(),
                size=size,
                compressed=size,  # `unrar l` ne donne pas la taille compressee
                encrypted=encrypted,
                is_dir=is_dir,
                crc=0,
            )
        )
    return entries


def parse_7z_listing(output: str) -> list[Entry]:
    """Meme travail pour `7z l` : colonnes Date Time Attr Size Compressed Name."""
    entries: list[Entry] = []
    in_table = False
    for line in output.splitlines():
        if SEPARATOR_RE.match(line.strip()):
            if in_table:
                break
            in_table = True
            continue
        if not in_table or not line.strip():
            continue
        fields = line.split(None, 5)
        if len(fields) < 6:
            continue
        _date, _time, attrs, size_text, _packed, name = fields
        try:
            size = int(size_text)
        except ValueError:
            continue
        entries.append(
            Entry(
                name=name.strip(),
                size=size,
                compressed=size,
                encrypted=False,  # 7z ne marque pas le chiffrement dans `l`
                is_dir=attrs.upper().startswith("D"),
                crc=0,
            )
        )
    return entries


def volume_info(path: Path) -> tuple[str | None, int | None]:
    """Retourne (identifiant du jeu de volumes, numero de volume) ou (None, None)."""
    name = path.name
    match = PART_RE.match(name)
    if match:
        return match.group("stem").lower(), int(match.group("num"))
    match = LEGACY_RE.match(name)
    if match:
        # nom.r00 est le 2e volume : nom.rar est le premier.
        return match.group("stem").lower(), int(match.group("num")) + 2
    if name.lower().endswith(".rar"):
        return name[:-4].lower(), 1
    return None, None


def is_first_volume(path: Path) -> bool:
    _, part = volume_info(path)
    return part is None or part == 1


def count_volumes(path: Path) -> int:
    """Compte les volumes du meme jeu presents dans le dossier."""
    stem, part = volume_info(path)
    if not stem or part is None:
        return 1
    try:
        siblings = list(path.parent.iterdir())
    except OSError:
        return 1
    return sum(1 for candidate in siblings
               if candidate.is_file() and volume_info(candidate)[0] == stem)


def group_volume_sets(paths: list[Path]) -> tuple[list[Path], dict[str, list[Path]]]:
    """Reduit un jeu multi-volumes a son premier volume.

    Hasher les 9 autres volumes d'un repack de 20 Go n'apporte rien : si la
    release est connue de VirusTotal, le premier volume suffit a le dire, et si
    elle ne l'est pas, aucun volume ne le sera. La verification d'integrite des
    parties se fait avec le fichier de somme de controle de la release, pas
    avec VirusTotal.
    """
    sets: dict[str, list[Path]] = {}
    kept: list[Path] = []
    for path in paths:
        stem, part = volume_info(path)
        if stem and part is not None and count_volumes(path) > 1:
            sets.setdefault(stem, []).append(path)
        else:
            kept.append(path)

    dropped: dict[str, list[Path]] = {}
    for volumes in sets.values():
        volumes.sort(key=lambda p: volume_info(p)[1] or 0)
        kept.append(volumes[0])
        if len(volumes) > 1:
            # Cle = nom du volume conserve, directement affichable.
            dropped[volumes[0].name] = volumes[1:]
    return kept, dropped


def inspect_rar(path: Path, timeout: int = 120) -> ArchiveReport:
    report = ArchiveReport(is_archive=True, readable=False, fmt="rar",
                           detected_type="archive RAR")
    _, part = volume_info(path)
    report.volume_part = part
    report.volume_count = count_volumes(path)

    executable = find_unrar()
    if not executable:
        report.error = (
            "UnRAR introuvable : impossible de lister le contenu. Installe WinRAR ou "
            "7-Zip, ou indique le chemin dans la variable VTZIP_UNRAR."
        )
        return report

    seven = _is_seven_zip(executable)
    # -p- : ne jamais demander de mot de passe (sinon le processus attendrait
    # une saisie). -y : pas de question interactive sur les volumes manquants.
    command = ([executable, "l", "-p-", "-y", "--", str(path)] if not seven
               else [executable, "l", "-p-", "-y", str(path)])
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=timeout,
            stdin=subprocess.DEVNULL,
            creationflags=NO_WINDOW,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        report.error = f"Echec du listage RAR : {exc}"
        return report

    output = completed.stdout or ""
    if completed.returncode == EXIT_WRONG_PASSWORD and not seven:
        report.readable = False
        report.encrypted = True
        report.error = "En-tetes chiffres : meme la liste des fichiers est protegee."
        report.findings.append(
            Finding(
                WARN,
                "encrypted_headers",
                "Archive a en-tetes chiffres : ni la liste des fichiers ni leur contenu "
                "ne peuvent etre analyses, par aucun antivirus. Un mot de passe dont le "
                "role est d'empecher l'analyse est un signal en soi.",
            )
        )
        return report

    report.entries = parse_7z_listing(output) if seven else parse_unrar_listing(output)
    if not report.entries:
        report.error = (
            f"Listage impossible (code {completed.returncode}). "
            "Pour un jeu multi-volumes, lance l'analyse sur le premier volume."
        )
        if part and part > 1:
            report.error = (
                f"Ce fichier est le volume {part} d'un jeu : le listage doit partir "
                "du premier volume."
            )
        return report

    report.readable = True
    analyze_entries(report)
    return report


def iter_entry_hashes(
    path: Path,
    entries: list[Entry],
    max_entries: int,
    max_size: int,
    timeout: int = 600,
):
    """Hashe des entrees du RAR en streaming. Yield (Entry, sha256 | None, raison).

    `unrar p` ecrit le contenu decompresse sur stdout : on le hashe au vol, donc
    rien n'est jamais ecrit sur le disque. Sur une archive solide, extraire une
    entree situee loin dans l'archive peut demander de traiter tout ce qui la
    precede, d'ou le garde-fou de duree.
    """
    from .hashing import CHUNK

    executable = find_unrar()
    if not executable:
        for entry in entries[:max_entries]:
            yield entry, None, "UnRAR introuvable"
        return

    seven = _is_seven_zip(executable)
    for entry in entries[:max_entries]:
        if entry.encrypted:
            yield entry, None, "protégé par mot de passe"
            continue
        if entry.size > max_size:
            from .hashing import human_size

            yield entry, None, f"trop volumineux ({human_size(entry.size)})"
            continue

        command = ([executable, "p", "-inul", "-p-", "-y", "--", str(path), entry.name]
                   if not seven
                   else [executable, "e", "-so", "-p-", "-y", str(path), entry.name])
        import hashlib

        digest = hashlib.sha256()
        read = 0
        try:
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                stdin=subprocess.DEVNULL,
                creationflags=NO_WINDOW,
            )
        except OSError as exc:
            yield entry, None, f"extraction impossible ({exc})"
            continue

        try:
            while True:
                block = process.stdout.read(CHUNK)
                if not block:
                    break
                digest.update(block)
                read += len(block)
            process.stdout.close()
            code = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            process.kill()
            yield entry, None, "délai dépassé"
            continue
        finally:
            if process.poll() is None:
                process.kill()

        if code != 0 or read != entry.size:
            yield entry, None, f"extraction incomplète ({read}/{entry.size} octets)"
            continue
        yield entry, digest.hexdigest(), None
