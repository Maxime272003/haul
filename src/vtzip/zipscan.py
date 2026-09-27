"""Inspection d'une archive ZIP sans jamais l'extraire sur le disque.

Tout se fait via zipfile : lecture du central directory pour les metadonnees,
et lecture en streaming (decompression en memoire, par blocs) pour hasher les
entrees quand on demande un scan profond.
"""

from __future__ import annotations

import posixpath
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

from .hashing import hash_stream, human_size

# Extensions qui ne devraient jamais sortir d'un zip "de confiance" sans qu'on
# le sache : executables, scripts, raccourcis, installeurs, images disque.
EXEC_EXTS = {
    ".exe", ".scr", ".com", ".pif", ".bat", ".cmd", ".ps1", ".psm1", ".vbs",
    ".vbe", ".js", ".jse", ".wsf", ".wsh", ".hta", ".lnk", ".msi", ".msp",
    ".jar", ".reg", ".dll", ".ocx", ".cpl", ".msc", ".apk", ".appx", ".msix",
    ".gadget", ".inf", ".scf", ".url", ".chm", ".pyc", ".py", ".sh", ".ade",
    ".adp", ".mst", ".application", ".diagcab", ".theme", ".xll", ".wsc",
}
# Documents pouvant embarquer des macros.
MACRO_EXTS = {
    ".docm", ".dotm", ".xlsm", ".xltm", ".xlam", ".pptm", ".potm", ".ppam",
    ".sldm", ".xls", ".doc", ".ppt", ".rtf",
}
# Archives imbriquees : souvent utilisees pour casser l'analyse automatique.
ARCHIVE_EXTS = {
    ".zip", ".rar", ".7z", ".gz", ".bz2", ".xz", ".tar", ".cab", ".arj",
    ".lzh", ".ace", ".iso", ".img", ".vhd", ".vhdx", ".wim", ".dmg",
}
# Extensions "de facade" dans une double extension (facture.pdf.exe).
DECOY_EXTS = {
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".jpg",
    ".jpeg", ".png", ".gif", ".mp3", ".mp4", ".avi", ".csv", ".rtf", ".htm",
    ".html", ".json", ".xml", ".zip", ".rar", ".log", ".msg",
}
WINDOWS_RESERVED = {
    "con", "prn", "aux", "nul", *(f"com{i}" for i in range(1, 10)),
    *(f"lpt{i}" for i in range(1, 10)),
}
# Caracteres de controle bidirectionnel (RTLO & co) : masquage d'extension.
BIDI_CHARS = {"\u202a", "\u202b", "\u202c", "\u202d", "\u202e", "\u2066",
              "\u2067", "\u2068", "\u2069", "\u200e", "\u200f"}

def display_name(name: str) -> str:
    """Neutralise un nom d'entree avant affichage.

    Un nom contenant un caractere bidirectionnel (RTLO) inverserait visuellement
    le texte du terminal -- c'est exactement le but de l'attaque. On l'echappe
    donc, tout comme les caracteres de controle.
    """
    out = []
    for char in name:
        code = ord(char)
        if char in BIDI_CHARS or code < 0x20 or code == 0x7F:
            out.append(f"\\u{code:04x}")
        else:
            out.append(char)
    return "".join(out)


ZIP_MAGICS = (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")
OTHER_MAGICS = {
    b"Rar!\x1a\x07": "archive RAR",
    b"7z\xbc\xaf\x27\x1c": "archive 7-Zip",
    b"\x1f\x8b": "archive GZIP",
    b"MZ": "executable Windows (PE)",
    b"\x7fELF": "executable Linux (ELF)",
    b"%PDF": "document PDF",
    b"\xd0\xcf\x11\xe0": "document Office (OLE2)",
}

DANGER = "danger"
WARN = "warn"
INFO = "info"

ZIP_BOMB_RATIO = 150.0
ZIP_BOMB_MIN_UNCOMPRESSED = 512 * 1024 * 1024  # 512 Mo


@dataclass
class Finding:
    level: str
    code: str
    message: str

    def as_dict(self) -> dict:
        return {"level": self.level, "code": self.code, "message": self.message}


@dataclass
class Entry:
    name: str
    size: int
    compressed: int
    encrypted: bool
    is_dir: bool
    crc: int

    @property
    def basename(self) -> str:
        return posixpath.basename(self.name.replace("\\", "/"))

    @property
    def ext(self) -> str:
        return posixpath.splitext(self.basename)[1].lower()

    @property
    def safe_name(self) -> str:
        """Nom complet echappe, sur pour l'affichage terminal."""
        return display_name(self.name)

    @property
    def safe_basename(self) -> str:
        return display_name(self.basename)


@dataclass
class ArchiveReport:
    is_archive: bool
    readable: bool
    fmt: str | None = None  # "zip" ou "rar"
    entries: list[Entry] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    total_size: int = 0
    total_compressed: int = 0
    encrypted: bool = False
    error: str | None = None
    detected_type: str | None = None
    volume_part: int | None = None  # numero de volume dans un jeu multi-parties
    volume_count: int | None = None

    @property
    def worst_level(self) -> str | None:
        for level in (DANGER, WARN, INFO):
            if any(f.level == level for f in self.findings):
                return level
        return None

    def as_dict(self) -> dict:
        return {
            "is_archive": self.is_archive,
            "format": self.fmt,
            "readable": self.readable,
            "entry_count": len([e for e in self.entries if not e.is_dir]),
            "total_size": self.total_size,
            "total_compressed": self.total_compressed,
            "encrypted": self.encrypted,
            "detected_type": self.detected_type,
            "error": self.error,
            "volume_part": self.volume_part,
            "volume_count": self.volume_count,
            "findings": [f.as_dict() for f in self.findings],
        }


def sniff_type(path: Path) -> tuple[bool, str | None]:
    """Retourne (est_un_zip, type_detecte_si_autre) d'apres les magic bytes."""
    try:
        with path.open("rb") as fh:
            head = fh.read(8)
    except OSError:
        return False, None
    if any(head.startswith(m) for m in ZIP_MAGICS):
        return True, "archive ZIP"
    for magic, label in OTHER_MAGICS.items():
        if head.startswith(magic):
            return False, label
    return False, None


def _is_unsafe_path(name: str) -> bool:
    normalized = name.replace("\\", "/")
    if normalized.startswith("/") or normalized.startswith("../"):
        return True
    if len(normalized) > 1 and normalized[1] == ":":  # C:\...
        return True
    return any(part == ".." for part in normalized.split("/"))


def inspect_zip(path: Path) -> ArchiveReport:
    is_zip, detected = sniff_type(path)
    ext = path.suffix.lower()

    if not is_zip:
        report = ArchiveReport(is_archive=False, readable=False, detected_type=detected)
        if ext in ARCHIVE_EXTS or ext == ".zip":
            label = detected or "type inconnu"
            report.findings.append(
                Finding(
                    DANGER if detected and "executable" in detected else WARN,
                    "type_mismatch",
                    f"L'extension annonce \"{ext}\" mais le contenu réel est : {label}.",
                )
            )
        else:
            report.error = f"Pas une archive ZIP ({detected or 'type inconnu'})."
        return report

    report = ArchiveReport(is_archive=True, readable=True, fmt="zip", detected_type=detected)
    try:
        with zipfile.ZipFile(path) as zf:
            for info in zf.infolist():
                report.entries.append(
                    Entry(
                        name=info.filename,
                        size=info.file_size,
                        compressed=info.compress_size,
                        encrypted=bool(info.flag_bits & 0x1),
                        is_dir=info.is_dir(),
                        crc=info.CRC,
                    )
                )
            comment = zf.comment
    except (zipfile.BadZipFile, OSError, RuntimeError) as exc:
        report.readable = False
        report.error = f"Archive illisible : {exc}"
        report.findings.append(
            Finding(WARN, "corrupt", "Archive corrompue ou tronquée : impossible de lire le contenu.")
        )
        return report

    analyze_entries(report)
    if comment and len(comment) > 200:
        report.findings.append(
            Finding(INFO, "long_comment",
                    f"Commentaire d'archive inhabituellement long ({len(comment)} octets).")
        )
    return report


def analyze_entries(report: ArchiveReport) -> None:
    """Calcule totaux et signalements a partir de la liste d'entrees.

    Independant du format : la meme analyse sert pour un ZIP lu par zipfile et
    pour un RAR liste par UnRAR.
    """
    files = [e for e in report.entries if not e.is_dir]
    report.total_size = sum(e.size for e in files)
    report.total_compressed = sum(e.compressed for e in files)
    report.encrypted = any(e.encrypted for e in files)

    add = report.findings.append

    if not files:
        add(Finding(WARN, "empty", "Archive vide (aucun fichier)."))
        return

    if report.encrypted:
        n = sum(1 for e in files if e.encrypted)
        add(
            Finding(
                WARN,
                "encrypted",
                f"{n} entrée(s) protégée(s) par mot de passe : le contenu ne peut pas être "
                "analysé, ni par VirusTotal ni par ton antivirus. C'est la technique "
                "classique de contournement.",
            )
        )

    execs = [e for e in files if e.ext in EXEC_EXTS]
    if execs:
        listing = ", ".join(e.safe_basename for e in execs[:5])
        more = f" (+{len(execs) - 5})" if len(execs) > 5 else ""
        # WARN et non DANGER : c'est du contexte, pas un defaut. Une archive
        # d'installation contient forcement un installeur.
        add(Finding(WARN, "executable",
                    f"Contient des exécutables/scripts : {listing}{more}. "
                    "Leur verdict VirusTotal est ce qui compte, pas leur présence."))

    macros = [e for e in files if e.ext in MACRO_EXTS]
    if macros:
        listing = ", ".join(e.safe_basename for e in macros[:5])
        add(Finding(WARN, "macro_doc", f"Documents pouvant contenir des macros : {listing}."))

    nested = [e for e in files if e.ext in ARCHIVE_EXTS]
    if nested:
        listing = ", ".join(e.safe_basename for e in nested[:5])
        add(Finding(WARN, "nested_archive", f"Archives imbriquées : {listing}."))

    for entry in files:
        name = entry.basename
        safe = entry.safe_basename
        stem, ext = posixpath.splitext(name)
        inner_ext = posixpath.splitext(stem)[1].lower()
        if ext.lower() in EXEC_EXTS and inner_ext in DECOY_EXTS:
            add(
                Finding(
                    DANGER,
                    "double_extension",
                    f"Double extension trompeuse : \"{safe}\" est en réalité un {ext.lower()}.",
                )
            )
        if any(ch in name for ch in BIDI_CHARS):
            real_ext = posixpath.splitext(display_name(name).rstrip())[1].lower() or ext.lower()
            add(
                Finding(
                    DANGER,
                    "bidi_override",
                    f"Le nom \"{safe}\" contient un caractère bidirectionnel : l'extension "
                    f"affichée par l'explorateur est truquée (réelle : {real_ext or '?'}).",
                )
            )
        if _is_unsafe_path(entry.name):
            add(
                Finding(
                    DANGER,
                    "zip_slip",
                    f"Chemin dangereux \"{entry.safe_name}\" : écrirait hors du dossier "
                    "de destination (Zip Slip).",
                )
            )
        if name != name.strip() or name.endswith("."):
            add(Finding(WARN, "odd_name", f"Nom avec espaces ou points en fin : \"{safe}\"."))
        if stem.lower() in WINDOWS_RESERVED:
            add(Finding(WARN, "reserved_name", f"Nom réservé Windows : \"{safe}\"."))
        if len(entry.name) > 200:
            add(Finding(WARN, "long_name",
                        f"Nom de chemin très long ({len(entry.name)} caractères)."))

    hidden = [e for e in files if e.basename.startswith(".") or "/__MACOSX" in e.name]
    if len(hidden) > 0 and len(hidden) == len(files):
        add(Finding(INFO, "hidden_only",
                    "L'archive ne contient que des fichiers cachés ou des métadonnées."))

    if report.total_compressed > 0:
        ratio = report.total_size / report.total_compressed
        if ratio > ZIP_BOMB_RATIO and report.total_size > ZIP_BOMB_MIN_UNCOMPRESSED:
            add(
                Finding(
                    DANGER,
                    "zip_bomb",
                    f"Ratio de compression x{ratio:.0f} pour {human_size(report.total_size)} "
                    "décompressés : possible zip bomb.",
                )
            )
        elif ratio > ZIP_BOMB_RATIO * 4:
            add(
                Finding(
                    WARN,
                    "high_ratio",
                    f"Ratio de compression très élevé (x{ratio:.0f}) : "
                    f"{human_size(report.total_size)} une fois décompressé.",
                )
            )


def iter_entry_hashes(
    path: Path,
    entries: list[Entry],
    max_entries: int,
    max_size: int,
):
    """Hashe les entrees en streaming. Yield (Entry, sha256 | None, raison)."""
    with zipfile.ZipFile(path) as zf:
        for entry in entries[:max_entries]:
            if entry.encrypted:
                yield entry, None, "protégé par mot de passe"
                continue
            if entry.size > max_size:
                yield entry, None, f"trop volumineux ({human_size(entry.size)})"
                continue
            try:
                with zf.open(entry.name, "r") as fh:
                    yield entry, hash_stream(fh), None
            except (RuntimeError, zipfile.BadZipFile, OSError) as exc:
                yield entry, None, f"illisible ({exc})"


def deep_candidates(report: ArchiveReport) -> list[Entry]:
    """Entrées à vérifier en priorité sur VT lors d'un scan profond."""
    files = [e for e in report.entries if not e.is_dir and e.size > 0]

    def priority(entry: Entry) -> int:
        if entry.ext in EXEC_EXTS:
            return 0
        if entry.ext in MACRO_EXTS:
            return 1
        if entry.ext in ARCHIVE_EXTS:
            return 2
        return 3

    return sorted(files, key=lambda e: (priority(e), -e.size))
