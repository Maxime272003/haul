"""Affichage terminal (rich)."""

from __future__ import annotations

import datetime as _dt
import sys

from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .hashing import human_size
from .scanner import (
    L_CLEAN,
    L_ERROR,
    L_GENERIC,
    L_MALICIOUS,
    L_SUSPICIOUS,
    L_UNKNOWN,
    LEVEL_LABELS,
    ScanResult,
    worst,
)
from .threats import explain_kinds
from .vt import ERROR, KNOWN, SKIPPED, UNKNOWN
from .zipscan import DANGER, INFO, WARN

LEVEL_STYLE = {
    L_MALICIOUS: "bold white on red",
    L_SUSPICIOUS: "bold black on yellow",
    L_GENERIC: "bold black on yellow3",
    L_UNKNOWN: "bold black on bright_cyan",
    L_CLEAN: "bold white on green",
    L_ERROR: "bold white on grey37",
}
LEVEL_COLOR = {
    L_MALICIOUS: "red",
    L_SUSPICIOUS: "yellow",
    L_GENERIC: "yellow3",
    L_UNKNOWN: "cyan",
    L_CLEAN: "green",
    L_ERROR: "grey62",
}
LEVEL_ICON = {
    L_MALICIOUS: "X",
    L_SUSPICIOUS: "!",
    L_GENERIC: "~",
    L_UNKNOWN: "?",
    L_CLEAN: "OK",
    L_ERROR: "--",
}
FINDING_STYLE = {DANGER: "red", WARN: "yellow", INFO: "cyan"}
FINDING_ICON = {DANGER: "X", WARN: "!", INFO: "i"}

ADVICE = {
    L_MALICIOUS: "Ne dézippe pas et n'exécute rien. Supprime le fichier.",
    L_SUSPICIOUS: "À ne pas exécuter sans vérification manuelle approfondie.",
    L_GENERIC: "Aucune famille de malware nommée, uniquement des détections génériques. "
               "Deux causes habituelles : un crack ou un keygen, qui patche légitimement "
               "un exécutable, ou un faux positif sur un petit utilitaire ancien et non "
               "signé. Vérifie l'onglet Behavior du rapport VirusTotal (connexions "
               "sortantes, clés Run, tâches planifiées) avant d'exécuter.",
    L_UNKNOWN: "Aucune information : une absence de résultat n'est pas un gage de sécurité.",
    L_CLEAN: "Rien de signalé. Le moment risqué reste l'exécution de l'installeur en admin.",
    L_ERROR: "Scan incomplet.",
}


def make_console() -> Console:
    # Un nom de fichier hostile peut contenir n'importe quel caractere Unicode.
    # Sur une console Windows en cp1252, l'ecriture leverait UnicodeEncodeError :
    # on degrade en '?' plutot que de planter au milieu d'un rapport.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")
        except (AttributeError, ValueError, OSError):
            pass
    return Console(highlight=False, soft_wrap=False)


def _timestamp(value: int | None) -> str:
    if not value:
        return "-"
    try:
        return _dt.datetime.fromtimestamp(value).strftime("%Y-%m-%d %H:%M")
    except (OverflowError, OSError, ValueError):
        return "-"


def _stats_text(result_verdict, compact: bool = False) -> Text:
    v = result_verdict
    if v.status == UNKNOWN:
        return Text("inconnu de VT" if compact else "inconnu de VirusTotal", style="cyan")
    if v.status == SKIPPED:
        return Text("non vérifié", style="grey62")
    if v.status == ERROR:
        return Text(v.message or "erreur", style="grey62")
    color = "red" if v.malicious else ("yellow" if v.suspicious else "green")
    text = Text()
    text.append(f"{v.flagged}/{v.engines}", style=f"bold {color}")
    if compact:
        return text
    text.append(" moteurs")
    if v.malicious or v.suspicious:
        text.append(f"  (malicious {v.malicious}, suspicious {v.suspicious})", style="dim")
    return text


def _bullets(items: list[tuple[str, str, str]]) -> Table:
    """Liste a puces dont les retours a la ligne restent alignes. (icone, texte, style)"""
    grid = Table.grid(padding=(0, 1))
    grid.add_column(no_wrap=True, width=3, justify="right")
    grid.add_column(overflow="fold")
    for icon, message, style in items:
        grid.add_row(Text(icon, style=style), Text(message, style=style))
    return grid


def _threat_bullets(threat) -> list[tuple[str, str, str]]:
    items: list[tuple[str, str, str]] = []
    if not threat:
        return items
    if threat.critical:
        families = ", ".join(threat.families) or "?"
        if threat.corroborated:
            items.append(("X", f"Famille de malware identifiée : {families}", "bold red"))
        else:
            items.append((
                "!",
                f"Famille nommée par un seul moteur, non corroborée : {families}",
                "bold yellow",
            ))
        for explanation in explain_kinds(threat.kinds):
            items.append(("", explanation, "red"))
        for det in threat.critical[:6]:
            items.append(("", f"{det.engine}: {det.result}", "red"))
        if len(threat.critical) > 6:
            items.append(("", f"(+{len(threat.critical) - 6} autres moteurs concordants)", "dim red"))
    if threat.other:
        items.append(("!", f"{len(threat.other)} détection(s) nommée(s) non classée(s) :", "yellow"))
        for det in threat.other[:4]:
            items.append(("", f"{det.engine}: {det.result}", "yellow"))
    if threat.generic:
        sample = ", ".join(sorted({d.result for d in threat.generic})[:3])
        items.append(
            (
                "~",
                f"{len(threat.generic)} détection(s) générique(s), bruit attendu sur un "
                f"crack ou un packer : {sample}",
                "yellow3",
            )
        )
    return items


def render_result(console: Console, result: ScanResult, show_all_inner: bool = False) -> None:
    body: list = []

    header = Table.grid(padding=(0, 1))
    header.add_column(style="bold cyan", no_wrap=True)
    header.add_column(overflow="fold")
    header.add_row("Fichier", str(result.path))
    header.add_row("Taille", human_size(result.size))
    v = result.verdict
    if result.sha256:
        header.add_row("SHA-256", result.sha256)
        header.add_row("VirusTotal", _stats_text(v))
    if v.status == KNOWN:
        details = []
        if v.type_description:
            details.append(v.type_description)
        if v.last_analysis_date:
            details.append(f"analysé le {_timestamp(v.last_analysis_date)}")
        if v.times_submitted:
            details.append(f"{v.times_submitted} soumission(s)")
        if v.reputation:
            details.append(f"réputation {v.reputation:+d}")
        if details:
            header.add_row("", Text(" | ".join(details), style="dim"))
        if v.labels:
            header.add_row("Étiquette", Text(", ".join(v.labels), style="bold red"))
    if v.permalink and result.sha256:
        header.add_row("Rapport", Text(v.permalink, style="blue underline"))
    body.append(header)

    threat_bullets = _threat_bullets(result.threat)
    if threat_bullets:
        body.append(Text())
        body.append(_bullets(threat_bullets))

    archive = result.archive
    if archive:
        body.append(Text())
        if archive.is_archive and archive.readable:
            files = [e for e in archive.entries if not e.is_dir]
            label = (archive.fmt or "archive").upper()
            summary = (
                f"Contenu du {label} : {len(files)} fichier(s), "
                f"{human_size(archive.total_size)} décompressés"
            )
            if archive.volume_count and archive.volume_count > 1:
                summary += f", reparti sur {archive.volume_count} volumes"
            body.append(Text(summary, style="bold"))
        elif archive.detected_type or archive.error:
            body.append(Text(f"Archive : {archive.error or archive.detected_type}", style="bold"))
        if archive.findings:
            body.append(
                _bullets(
                    [
                        (
                            FINDING_ICON.get(f.level, "-"),
                            f.message,
                            FINDING_STYLE.get(f.level, "white"),
                        )
                        for f in archive.findings
                    ]
                )
            )

    if result.inner:
        table = Table(
            title="Fichiers à l'intérieur (vérifiés sans extraction)",
            title_style="bold",
            title_justify="left",
            box=None,
            pad_edge=False,
            expand=False,
        )
        table.add_column("", no_wrap=True)
        table.add_column("Entrée", overflow="fold", min_width=18, max_width=52, ratio=2)
        table.add_column("Taille", justify="right", no_wrap=True)
        table.add_column("VT", justify="right", no_wrap=True)
        table.add_column("Détail", overflow="fold", max_width=38, ratio=1)

        shown = result.inner if show_all_inner else [
            i for i in result.inner if i.level != L_CLEAN
        ] or result.inner[:5]
        for inner in shown:
            detail = ""
            if inner.skipped:
                detail = inner.skipped
            elif inner.threat and inner.threat.critical:
                families = ", ".join(inner.threat.families)
                detail = f"{families} : {inner.threat.critical[0].result}"
            elif inner.threat and (inner.threat.other or inner.threat.generic):
                # Montrer les libelles reels : un "4/70" n'est pas jugeable sans
                # savoir si les moteurs disent "Keygen" ou "RedLine".
                named = inner.threat.other or inner.threat.generic
                labels = sorted({d.result for d in named})[:3]
                detail = ", ".join(labels)
            table.add_row(
                Text(LEVEL_ICON.get(inner.level, "?"), style=LEVEL_COLOR.get(inner.level, "white")),
                inner.entry.safe_name,
                human_size(inner.entry.size),
                _stats_text(inner.verdict, compact=True) if inner.verdict
                else Text("-", style="dim"),
                Text(detail, style=LEVEL_COLOR.get(inner.level, "white")),
            )
        hidden = len(result.inner) - len(shown)
        body.append(Text())
        body.append(table)
        if hidden > 0:
            body.append(
                Text(f"  ({hidden} entrée(s) propre(s) masquée(s), --all pour tout voir)", style="dim")
            )

    if result.notes:
        body.append(Text())
        body.append(_bullets([("i", note, "dim") for note in result.notes]))

    if result.error:
        body.append(Text())
        body.append(_bullets([("--", result.error, "bold grey62")]))

    advice = ADVICE.get(result.level)
    if advice:
        body.append(Text())
        body.append(Text(advice, style=f"bold {LEVEL_COLOR.get(result.level, 'white')}"))

    console.print(
        Panel(
            Group(*body),
            title=Text(f" {result.label} ", style=LEVEL_STYLE.get(result.level, "bold")),
            title_align="left",
            subtitle=Text(result.path.name, style="dim"),
            subtitle_align="right",
            border_style=LEVEL_COLOR.get(result.level, "white"),
            padding=(1, 2),
        )
    )


def needs_detail(result: ScanResult) -> bool:
    """Un panneau complet n'a d'interet que si le fichier demande une decision."""
    if result.level in (L_MALICIOUS, L_SUSPICIOUS, L_GENERIC):
        return True
    if result.error:
        return True
    return bool(result.archive and result.archive.findings)


def render_results(console: Console, results: list[ScanResult], show_all_inner: bool = False,
                   verbose: bool = False, grouped: dict[str, list] | None = None) -> None:
    detailed = results if (verbose or len(results) == 1) else [r for r in results if needs_detail(r)]
    for result in detailed:
        render_result(console, result, show_all_inner=show_all_inner)
    skipped = len(results) - len(detailed)
    if skipped and not verbose:
        console.print(
            Text(
                f"{skipped} fichier(s) sans signalement, détails avec --verbose.",
                style="dim",
            )
        )
    render_summary(console, results, grouped=grouped)


def render_summary(console: Console, results: list[ScanResult],
                   grouped: dict[str, list] | None = None) -> None:
    if len(results) <= 1 and not grouped:
        return
    table = Table(box=None, pad_edge=False, title="Récapitulatif", title_style="bold", title_justify="left")
    table.add_column("", no_wrap=True)
    table.add_column("Fichier", overflow="fold")
    table.add_column("Verdict", no_wrap=True)
    table.add_column("VirusTotal", no_wrap=True)
    for result in sorted(results, key=lambda r: (r.level != L_MALICIOUS, r.path.name.lower())):
        color = LEVEL_COLOR.get(result.level, "white")
        table.add_row(
            Text(LEVEL_ICON.get(result.level, "?"), style=color),
            result.path.name,
            Text(result.label, style=color),
            _stats_text(result.verdict),
        )
    console.print()
    console.print(table)

    # Rappel du regroupement ICI, et pas seulement avant les panneaux : c'est en
    # bas que l'on lit le bilan, et un recap a 3 lignes pour un dossier de 12
    # fichiers donne sinon l'impression que le scan s'est arrete en route.
    if grouped:
        skipped = sum(len(volumes) for volumes in grouped.values())
        total = len(results) + skipped
        console.print()
        console.print(
            Text(
                f"{total} fichiers dans la cible : {len(results)} hashé(s), "
                f"{skipped} volume(s) regroupé(s) dans leur jeu.",
                style="dim",
            )
        )
        console.print(
            _bullets(
                [
                    ("i", f"Le listage de {first_volume} couvre les "
                          f"{len(volumes) + 1} volumes du jeu.", "dim")
                    for first_volume, volumes in grouped.items()
                ]
            )
        )

    overall = worst(r.level for r in results)
    console.print()
    console.print(
        Text(f" Verdict global : {LEVEL_LABELS.get(overall, overall)} ", style=LEVEL_STYLE.get(overall, "bold"))
    )


def render_no_key(console: Console) -> None:
    console.print(
        Panel(
            Group(
                Text("Aucune clé API VirusTotal configurée.", style="bold yellow"),
                Text(),
                Text("1. Crée un compte gratuit sur https://www.virustotal.com, puis copie ta clé"),
                Text("   (menu profil > API key)."),
                Text("2. Enregistre-la :", style="bold"),
                Text("     vtzip config set-key", style="cyan"),
                Text("   ou définis la variable d'environnement VT_API_KEY.", style="dim"),
                Text(),
                Text("L'API publique est limitée à 4 requêtes par minute et 500 par jour.", style="dim"),
                Text("Sans clé, --offline fait tourner l'analyse locale de l'archive seule.", style="dim"),
            ),
            title=" Configuration requise ",
            border_style="yellow",
            padding=(1, 2),
        )
    )
