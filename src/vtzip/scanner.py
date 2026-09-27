"""Orchestration d'un scan : hash local -> lookup VT -> inspection archive."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path

from .hashing import hash_file
from .rarscan import inspect_rar, is_first_volume, volume_info
from .rarscan import iter_entry_hashes as iter_rar_hashes
from .threats import ThreatSummary, summarize
from .vt import ERROR, KNOWN, SKIPPED, UNKNOWN, FileVerdict, QuotaExceeded, VirusTotalClient, VTError
from .zipscan import (
    ARCHIVE_EXTS,
    EXEC_EXTS,
    MACRO_EXTS,
    ArchiveReport,
    Entry,
    deep_candidates,
    inspect_zip,
    iter_entry_hashes,
    sniff_type,
)

# Niveaux de verdict, du pire au meilleur.
L_MALICIOUS = "malicious"
L_SUSPICIOUS = "suspicious"
L_GENERIC = "generic"
L_UNKNOWN = "unknown"
L_CLEAN = "clean"
L_ERROR = "error"

LEVEL_ORDER = {
    L_MALICIOUS: 0, L_SUSPICIOUS: 1, L_GENERIC: 2,
    L_UNKNOWN: 3, L_ERROR: 4, L_CLEAN: 5,
}

LEVEL_LABELS = {
    L_MALICIOUS: "MALVEILLANT",
    L_SUSPICIOUS: "SUSPECT",
    L_GENERIC: "DÉTECTIONS GÉNÉRIQUES",
    L_UNKNOWN: "INCONNU DE VT",
    L_CLEAN: "PROPRE",
    L_ERROR: "ERREUR",
}

# Extensions interessantes lors du scan d'un dossier deja extrait : on ne hashe
# pas 40 Go de donnees de jeu, seulement ce qui peut s'executer.
# .bin est inclus parce que les repacks y stockent leurs donnees : le fichier ne
# s'execute pas, mais son hash est souvent deja connu de VirusTotal.
RISKY_EXTS = EXEC_EXTS | MACRO_EXTS | ARCHIVE_EXTS | {".bin"}
SCANNABLE_ARCHIVE_EXTS = {".zip"}

# Signalements d'archive qui font monter le verdict, par opposition a ceux qui
# sont seulement affiches comme contexte.
#
# "contient des executables" n'en fait deliberement PAS partie : une archive
# d'installation de jeu contient un installeur, c'est vrai de 100 % des cas et
# ca n'informe donc de rien. Ce qui compte, c'est la TROMPERIE (un exe deguise
# en PDF, un nom retourne par RTLO, un chemin qui s'echappe du dossier) ou
# l'impossibilite d'analyser (archive chiffree). Le verdict sur les executables
# eux-memes vient de VirusTotal via --deep, pas de leur simple presence.
ESCALATING_FINDINGS = {
    "double_extension",
    "bidi_override",
    "zip_slip",
    "zip_bomb",
    "type_mismatch",
    "encrypted",
    "encrypted_headers",
}


def worst(levels: Iterable[str]) -> str:
    levels = [lvl for lvl in levels if lvl]
    if not levels:
        return L_CLEAN
    return min(levels, key=lambda lvl: LEVEL_ORDER.get(lvl, 9))


def verdict_level(verdict: FileVerdict, threat: ThreatSummary | None) -> str:
    """Traduit un rapport VirusTotal en niveau de verdict.

    La NATURE des detections prime sur leur nombre : 30 moteurs qui disent
    "HackTool" sur un keygen restent du bruit attendu, alors que 2 moteurs qui
    nomment RedLine suffisent a condamner le fichier. Les compteurs bruts ne
    servent que si VirusTotal ne nous a pas donne le detail par moteur.
    """
    if verdict.status == ERROR:
        return L_ERROR
    if verdict.status in (UNKNOWN, SKIPPED):
        return L_UNKNOWN

    if threat and threat.detections:
        if threat.critical:
            # Famille non corroboree (un seul moteur, et VirusTotal ne la reprend
            # pas dans son etiquette) : serieux, mais pas de quoi condamner.
            return L_MALICIOUS if threat.corroborated else L_SUSPICIOUS
        if threat.other:
            # Detections nommees mais non repertoriees : le consensus fait foi.
            return L_MALICIOUS if len(threat.other) >= 5 else L_SUSPICIOUS
        return L_GENERIC

    # Aucun detail par moteur disponible : on retombe sur les compteurs.
    if verdict.malicious >= 5:
        return L_MALICIOUS
    if verdict.malicious >= 1 or verdict.suspicious >= 2:
        return L_SUSPICIOUS
    if verdict.flagged > 0:
        return L_GENERIC
    return L_CLEAN


@dataclass
class InnerResult:
    entry: Entry
    sha256: str | None = None
    skipped: str | None = None
    verdict: FileVerdict | None = None
    threat: ThreatSummary | None = None
    level: str = L_UNKNOWN

    def as_dict(self) -> dict:
        return {
            "name": self.entry.name,
            "size": self.entry.size,
            "sha256": self.sha256,
            "skipped": self.skipped,
            "level": self.level,
            "vt": self.verdict.as_dict() if self.verdict else None,
            "threat": self.threat.as_dict() if self.threat else None,
        }


@dataclass
class ScanResult:
    path: Path
    size: int = 0
    sha256: str | None = None
    verdict: FileVerdict = field(default_factory=FileVerdict)
    threat: ThreatSummary | None = None
    archive: ArchiveReport | None = None
    inner: list[InnerResult] = field(default_factory=list)
    level: str = L_UNKNOWN
    error: str | None = None
    notes: list[str] = field(default_factory=list)

    @property
    def label(self) -> str:
        return LEVEL_LABELS.get(self.level, self.level)

    def as_dict(self) -> dict:
        return {
            "path": str(self.path),
            "name": self.path.name,
            "size": self.size,
            "sha256": self.sha256,
            "level": self.level,
            "label": self.label,
            "error": self.error,
            "notes": self.notes,
            "vt": self.verdict.as_dict(),
            "threat": self.threat.as_dict() if self.threat else None,
            "archive": self.archive.as_dict() if self.archive else None,
            "inner": [i.as_dict() for i in self.inner],
        }


class Scanner:
    def __init__(
        self,
        client: VirusTotalClient | None,
        deep: bool = False,
        deep_max_entries: int = 12,
        deep_max_size: int = 256 * 1024 * 1024,
        upload: bool = False,
        wait: bool = False,
        notify: Callable[[str], None] | None = None,
        on_hash_start: Callable[[str, int], None] | None = None,
        on_hash_chunk: Callable[[int], None] | None = None,
    ):
        self.client = client
        self.deep = deep
        self.deep_max_entries = deep_max_entries
        self.deep_max_size = deep_max_size
        self.upload = upload
        self.wait = wait
        self.notify = notify or (lambda msg: None)
        self.on_hash_start = on_hash_start
        self.on_hash_chunk = on_hash_chunk
        self.quota_hit = False
        self.quota_message: str | None = None

    # -- helpers ---------------------------------------------------------
    def _lookup(self, sha256: str) -> tuple[FileVerdict, ThreatSummary | None]:
        if self.quota_hit:
            # Distinct de "pas de client" : ici la verification a ete interrompue
            # en cours de route, il faut le dire au lieu de degrader en silence.
            return FileVerdict(
                status=SKIPPED,
                message="Quota VirusTotal épuisé : vérification non effectuée.",
            ), None
        if self.client is None:
            return FileVerdict(status=SKIPPED, message="Non soumis à VirusTotal."), None
        try:
            verdict = self.client.lookup_hash(sha256)
        except QuotaExceeded as exc:
            self.quota_hit = True
            self.quota_message = str(exc)
            return FileVerdict(status=ERROR, message=str(exc)), None
        except VTError as exc:
            return FileVerdict(status=ERROR, message=str(exc)), None
        threat = summarize(verdict.engine_hits, verdict.labels)
        return verdict, threat

    def _maybe_upload(self, result: ScanResult) -> None:
        if not self.upload or self.client is None or self.quota_hit:
            return
        if result.verdict.status != UNKNOWN:
            return
        try:
            self.notify(f"Envoi de {result.path.name} à VirusTotal...")
            analysis_id = self.client.upload(result.path)
        except VTError as exc:
            result.notes.append(f"Envoi impossible : {exc}")
            return
        result.notes.append("Fichier envoyé à VirusTotal pour analyse.")
        if not self.wait:
            result.notes.append(
                "Relance le scan dans quelques minutes pour lire le rapport (--wait pour attendre ici)."
            )
            return
        try:
            self.notify("Analyse en cours chez VirusTotal...")
            self.client.wait_for_analysis(analysis_id)
        except VTError as exc:
            result.notes.append(f"Attente interrompue : {exc}")
            return
        verdict, threat = self._lookup(result.sha256)
        if verdict.status == KNOWN:
            result.verdict, result.threat = verdict, threat

    # -- scan principal --------------------------------------------------
    def scan_file(self, path: Path) -> ScanResult:
        result = ScanResult(path=path)
        try:
            result.size = path.stat().st_size
        except OSError as exc:
            result.level, result.error = L_ERROR, f"Fichier inaccessible : {exc}"
            return result

        if self.on_hash_start:
            self.on_hash_start(f"SHA-256 de {path.name}", result.size)
        else:
            self.notify(f"Calcul du SHA-256 de {path.name}...")
        try:
            result.sha256 = hash_file(path, on_chunk=self.on_hash_chunk)
        except OSError as exc:
            result.level, result.error = L_ERROR, f"Lecture impossible : {exc}"
            return result

        result.verdict, result.threat = self._lookup(result.sha256)
        self._maybe_upload(result)
        self._inspect_archive(result)

        if self.deep and result.archive and result.archive.readable:
            self._scan_inner(result)

        _finalize(result)
        return result

    def _inspect_archive(self, result: ScanResult) -> None:
        """Choisit l'inspecteur d'apres le contenu reel, pas d'apres l'extension."""
        path = result.path
        is_zip, detected = sniff_type(path)
        suffix = path.suffix.lower()

        if is_zip or suffix in SCANNABLE_ARCHIVE_EXTS:
            result.archive = inspect_zip(path)
            return

        if detected == "archive RAR" or suffix == ".rar" or volume_info(path)[1]:
            # Sur un jeu multi-volumes, seul le premier volume peut etre liste :
            # les autres n'ont pas d'en-tete d'archive complet.
            if not is_first_volume(path):
                _, part = volume_info(path)
                result.archive = None
                result.notes.append(
                    f"Volume {part} d'un jeu multi-parties : le contenu se lit depuis "
                    "le premier volume, qui est analysé séparément."
                )
                return
            self.notify(f"Listage de {path.name}...")
            result.archive = inspect_rar(path)

    def _scan_inner(self, result: ScanResult) -> None:
        archive = result.archive
        candidates = deep_candidates(archive)
        if not candidates:
            return
        selected = candidates[: self.deep_max_entries]
        dropped = len(candidates) - len(selected)
        if dropped > 0:
            result.notes.append(
                f"Scan profond limité à {len(selected)} entrées sur {len(candidates)} "
                f"({dropped} non vérifiées, ajuste avec --deep-max)."
            )

        hasher = iter_rar_hashes if archive.fmt == "rar" else iter_entry_hashes
        seen: dict[str, InnerResult] = {}
        for entry, sha256, reason in hasher(
            result.path, selected, len(selected), self.deep_max_size
        ):
            inner = InnerResult(entry=entry, sha256=sha256, skipped=reason)
            if sha256 is None:
                inner.level = L_UNKNOWN
            elif sha256 in seen:
                source = seen[sha256]
                inner.verdict, inner.threat, inner.level = source.verdict, source.threat, source.level
            else:
                self.notify(f"Verification de {entry.safe_basename}…")
                inner.verdict, inner.threat = self._lookup(sha256)
                inner.level = verdict_level(inner.verdict, inner.threat)
                seen[sha256] = inner
            result.inner.append(inner)

    def scan_path(self, path: Path, recursive: bool = True, risky_only: bool = True) -> list[ScanResult]:
        if path.is_file():
            return [self.scan_file(path)]
        if not path.is_dir():
            missing = ScanResult(path=path, level=L_ERROR, error="Chemin introuvable.")
            return [missing]
        return [self.scan_file(f) for f in collect_files(path, recursive, risky_only)]


def collect_files(directory: Path, recursive: bool = True, risky_only: bool = True) -> list[Path]:
    """Liste les fichiers a scanner dans un dossier.

    Avec risky_only (defaut), on ne garde que les fichiers executables, documents
    a macros et archives : c'est la que se cache la charge utile, et ca evite de
    hasher des dizaines de Go de donnees de jeu pour rien.
    """
    pattern = "**/*" if recursive else "*"
    files = [p for p in directory.glob(pattern) if p.is_file()]
    if risky_only:
        files = [p for p in files if p.suffix.lower() in RISKY_EXTS]
    files.sort(key=lambda p: (p.suffix.lower() not in EXEC_EXTS, str(p).lower()))
    return files


def _finalize(result: ScanResult) -> None:
    levels = [verdict_level(result.verdict, result.threat)]
    levels += [inner.level for inner in result.inner]

    archive = result.archive
    if archive:
        escalating = {f.code for f in archive.findings} & ESCALATING_FINDINGS
        if escalating:
            levels.append(L_SUSPICIOUS)

        # Un "0 detection" sur une archive chiffree ou non lisible ne prouve rien :
        # les moteurs n'ont pas pu regarder a l'interieur.
        if archive.encrypted and result.verdict.status == KNOWN and result.verdict.flagged == 0:
            result.notes.append(
                "Archive protégée par mot de passe : le \"0 détection\" de VirusTotal ne "
                "signifie rien ici, les moteurs n'ont pas pu lire le contenu."
            )
        if archive.readable and not result.inner and archive.entries:
            result.notes.append(
                "Utilise --deep pour vérifier chaque fichier à l'intérieur de l'archive."
            )

    if result.threat and result.threat.critical and not result.threat.corroborated:
        result.notes.append(
            f"Un seul moteur nomme \"{result.threat.families[0]}\" et l'étiquette "
            "agrégée de VirusTotal ne la reprend pas : à confirmer avec l'onglet "
            "Behavior du rapport avant d'en conclure quoi que ce soit."
        )

    result.level = worst(levels)
    if result.error:
        result.level = L_ERROR


EXIT_CODES = {
    L_MALICIOUS: 2,
    L_SUSPICIOUS: 3,
    L_GENERIC: 4,
    L_UNKNOWN: 5,
    L_ERROR: 6,
    L_CLEAN: 0,
}


def exit_code(results: list[ScanResult]) -> int:
    if not results:
        return 1
    return EXIT_CODES.get(worst(r.level for r in results), 1)
