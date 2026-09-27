"""Interface en ligne de commande de vtzip."""

from __future__ import annotations

import argparse
import getpass
import json
import shutil
import sys
import time
from pathlib import Path

from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeRemainingColumn,
)

from . import __version__
from .config import ResultCache, config_path, load_config, resolve_api_key, save_config
from .hashing import human_size
from .rarscan import group_volume_sets
from .render import make_console, render_no_key, render_results
from .scanner import (
    L_MALICIOUS,
    L_SUSPICIOUS,
    Scanner,
    collect_files,
    exit_code,
    worst,
)
from .vt import VirusTotalClient

WATCH_EXTS = {".zip", ".rar", ".7z", ".exe", ".msi", ".iso", ".gz", ".cab"}
COMMANDS = {"scan", "watch", "config", "hash"}


class Notifier:
    """Statut ephemere : spinner pour les etapes courtes, barre pour les gros hash.

    Un repack se compte en dizaines de Go : sans barre de progression, l'app
    aurait l'air figee pendant plusieurs minutes.
    """

    BAR_THRESHOLD = 64 * 1024 * 1024  # au-dela, on affiche une vraie barre

    def __init__(self, console, enabled: bool = True):
        self.console = console
        self.enabled = enabled and console.is_terminal
        self._progress: Progress | None = None
        self._task = None

    def _ensure(self) -> Progress:
        if self._progress is None:
            self._progress = Progress(
                SpinnerColumn(),
                TextColumn("[dim]{task.description}[/dim]"),
                BarColumn(bar_width=24),
                TaskProgressColumn(),
                TimeRemainingColumn(),
                console=self.console,
                transient=True,
            )
            self._progress.start()
        return self._progress

    def __call__(self, message: str) -> None:
        """Message sans progression mesurable."""
        if not self.enabled:
            return
        progress = self._ensure()
        if self._task is None:
            self._task = progress.add_task(message, total=None)
        else:
            progress.reset(self._task, total=None, description=message)

    def start_file(self, description: str, total: int) -> None:
        if not self.enabled:
            return
        if total < self.BAR_THRESHOLD:
            self(description)
            return
        progress = self._ensure()
        if self._task is None:
            self._task = progress.add_task(description, total=total)
        else:
            progress.reset(self._task, total=total, description=description)

    def advance(self, amount: int) -> None:
        if self.enabled and self._progress is not None and self._task is not None:
            self._progress.advance(self._task, amount)

    def stop(self) -> None:
        if self._progress is not None:
            self._progress.stop()
            self._progress = None
            self._task = None


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vtzip",
        description="Vérifie tes téléchargements sur VirusTotal AVANT de les dézipper.",
        epilog=(
            "Codes de sortie : 0 propre, 2 malveillant, 3 suspect, 4 détections génériques, "
            "5 inconnu de VirusTotal, 6 erreur."
        ),
    )
    parser.add_argument("--version", action="version", version=f"vtzip {__version__}")
    sub = parser.add_subparsers(dest="command")

    def add_common(p: argparse.ArgumentParser) -> None:
        p.add_argument("--api-key", help="Clé API VirusTotal (sinon VT_API_KEY, sinon la config).")
        p.add_argument("--rpm", type=int, default=4,
                       help="Requêtes par minute autorisées (0 = illimité, clé premium). Défaut : 4.")
        p.add_argument("--no-cache", action="store_true", help="Ignore le cache local des résultats.")
        p.add_argument("--cache-ttl", type=int, default=24,
                       help="Durée de vie du cache, en heures. Défaut : 24.")
        p.add_argument("--json", action="store_true", help="Sortie JSON brute, sans mise en forme.")
        p.add_argument("--offline", action="store_true",
                       help="Aucune requête réseau : hash et analyse locale de l'archive seulement.")

    def add_scan_opts(p: argparse.ArgumentParser) -> None:
        p.add_argument("--deep", action="store_true",
                       help="Vérifie chaque fichier À L'INTÉRIEUR du zip, sans jamais l'extraire.")
        p.add_argument("--deep-max", type=int, default=12,
                       help="Nombre max d'entrées vérifiées en scan profond. Défaut : 12.")
        p.add_argument("--all", action="store_true",
                       help="Affiche aussi les entrées internes propres.")
        p.add_argument("--verbose", "-v", action="store_true",
                       help="Panneau détaillé pour chaque fichier, même sans signalement.")
        p.add_argument("--upload", action="store_true",
                       help="Envoie le fichier à VirusTotal s'il est inconnu "
                            "(attention : le fichier quitte ta machine).")
        p.add_argument("--wait", action="store_true",
                       help="Avec --upload : attend le résultat de l'analyse.")
        p.add_argument("--quarantine", metavar="DOSSIER",
                       help="Déplace les fichiers malveillants ou suspects dans ce dossier.")

    p_scan = sub.add_parser("scan", help="Scanne un ou plusieurs fichiers ou dossiers.")
    p_scan.add_argument("paths", nargs="+", type=Path, help="Fichiers ou dossiers à vérifier.")
    p_scan.add_argument("--all-files", action="store_true",
                        help="Pour un dossier : scanne tous les fichiers, pas seulement "
                             "les exécutables et archives.")
    p_scan.add_argument("--no-recursive", action="store_true",
                        help="Ne descend pas dans les sous-dossiers.")
    p_scan.add_argument("--all-parts", action="store_true",
                        help="Hashe tous les volumes d'un jeu multi-parties. Par défaut, "
                             "seul le premier est analysé : les suivants n'apportent "
                             "aucune information de plus.")
    add_scan_opts(p_scan)
    add_common(p_scan)

    p_watch = sub.add_parser("watch",
                             help="Surveille un dossier et scanne les nouveaux téléchargements.")
    p_watch.add_argument("directory", nargs="?", type=Path, default=None,
                         help="Dossier à surveiller. Défaut : ton dossier Téléchargements.")
    p_watch.add_argument("--interval", type=float, default=3.0,
                         help="Intervalle de scrutation, en secondes.")
    p_watch.add_argument("--existing", action="store_true",
                         help="Scanne aussi les fichiers déjà présents.")
    add_scan_opts(p_watch)
    add_common(p_watch)

    p_hash = sub.add_parser("hash", help="Affiche seulement le SHA-256 (aucun accès réseau).")
    p_hash.add_argument("paths", nargs="+", type=Path)

    p_config = sub.add_parser("config", help="Gère la clé API.")
    config_sub = p_config.add_subparsers(dest="config_command")
    config_sub.add_parser("set-key", help="Enregistre ta clé API VirusTotal.")
    config_sub.add_parser("show", help="Affiche la configuration courante.")
    config_sub.add_parser("path", help="Affiche le chemin du fichier de config.")

    return parser


def downloads_dir() -> Path:
    for candidate in (Path.home() / "Downloads", Path.home() / "Telechargements"):
        if candidate.is_dir():
            return candidate
    return Path.home() / "Downloads"


def build_scanner(args, console, notifier: Notifier) -> Scanner | None:
    client = None
    if not args.offline:
        api_key = resolve_api_key(getattr(args, "api_key", None))
        if not api_key:
            if args.json:
                print(json.dumps({"error": "no_api_key"}))
            else:
                render_no_key(console)
            return None
        cache = ResultCache(ttl_seconds=int(args.cache_ttl * 3600), enabled=not args.no_cache)
        client = VirusTotalClient(
            api_key,
            rpm=args.rpm,
            cache=cache,
            on_wait=lambda wait: notifier(
                f"Limite de l'API publique atteinte, pause de {wait:.0f}s..."
            ),
        )
    return Scanner(
        client,
        deep=getattr(args, "deep", False),
        deep_max_entries=getattr(args, "deep_max", 12),
        upload=getattr(args, "upload", False),
        wait=getattr(args, "wait", False),
        notify=notifier,
        on_hash_start=notifier.start_file,
        on_hash_chunk=notifier.advance,
    )


def quarantine_file(path: Path, target_dir: Path) -> str:
    target_dir.mkdir(parents=True, exist_ok=True)
    destination = target_dir / path.name
    counter = 1
    while destination.exists():
        destination = target_dir / f"{path.stem}.{counter}{path.suffix}"
        counter += 1
    shutil.move(str(path), str(destination))
    return str(destination)


def handle_results(args, console, results, notifier: Notifier, grouped=None) -> None:
    notifier.stop()
    if args.json:
        payload = {
            "results": [r.as_dict() for r in results],
            "verdict": worst(r.level for r in results),
            "grouped_volumes": {
                first: [str(path) for path in volumes]
                for first, volumes in (grouped or {}).items()
            },
        }
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        return
    render_results(
        console,
        results,
        show_all_inner=getattr(args, "all", False),
        verbose=getattr(args, "verbose", False),
        grouped=grouped,
    )


def apply_quarantine(args, console, results) -> None:
    target = getattr(args, "quarantine", None)
    if not target:
        return
    target_dir = Path(target)
    for result in results:
        if result.level not in (L_MALICIOUS, L_SUSPICIOUS):
            continue
        try:
            moved = quarantine_file(result.path, target_dir)
        except OSError as exc:
            console.print(
                f"[red]Mise en quarantaine impossible pour {result.path.name} : {exc}[/red]"
            )
            continue
        console.print(f"[yellow]Déplacé en quarantaine :[/yellow] {moved}")


def cmd_scan(args) -> int:
    console = make_console()
    notifier = Notifier(console, enabled=not args.json)
    scanner = build_scanner(args, console, notifier)
    if scanner is None:
        return 6

    targets: list[Path] = []
    for raw in args.paths:
        path = raw.expanduser()
        if path.is_dir():
            found = collect_files(
                path,
                recursive=not args.no_recursive,
                risky_only=not args.all_files,
            )
            if not found and not args.json:
                console.print(
                    f"[dim]{path} : aucun exécutable ni archive trouvé "
                    f"(--all-files pour tout scanner).[/dim]"
                )
            targets.extend(found)
        else:
            targets.append(path)

    if not targets:
        console.print("[yellow]Rien à scanner.[/yellow]")
        return 1

    dropped: dict = {}
    if not getattr(args, "all_parts", False):
        targets, dropped = group_volume_sets(targets)
        for first_volume, volumes in dropped.items():
            if not args.json:
                console.print(
                    f"[dim]Jeu de {len(volumes) + 1} volumes : seul {first_volume} est "
                    f"hashé, son listage couvrant tout le jeu "
                    f"({human_size(sum(v.stat().st_size for v in volumes))} de hash évités). "
                    f"--all-parts pour hasher chaque volume.[/dim]"
                )

    results = []
    try:
        for path in targets:
            results.append(scanner.scan_file(path))
    except KeyboardInterrupt:
        notifier.stop()
        console.print("[yellow]Interrompu.[/yellow]")
    finally:
        notifier.stop()
        if scanner.client and scanner.client.cache:
            scanner.client.cache.flush()

    handle_results(args, console, results, notifier, grouped=dropped)
    if scanner.quota_hit and not args.json:
        console.print()
        console.print(
            f"[bold yellow]Quota VirusTotal épuisé en cours de scan.[/bold yellow] "
            f"Les fichiers marqués \"vérification non effectuée\" n'ont pas été contrôlés.\n"
            f"[dim]{scanner.quota_message}\n"
            f"Relance plus tard : les résultats déjà obtenus sont en cache "
            f"et ne recompteront pas.[/dim]"
        )
    apply_quarantine(args, console, results)
    return exit_code(results)


def wait_until_stable(path: Path, timeout: float = 600.0) -> bool:
    """Attend que la taille du fichier cesse de changer (téléchargement terminé)."""
    deadline = time.monotonic() + timeout
    last = -1
    stable = 0
    while time.monotonic() < deadline:
        try:
            size = path.stat().st_size
        except OSError:
            return False
        if size == last and size > 0:
            stable += 1
            if stable >= 2:
                return True
        else:
            stable = 0
            last = size
        time.sleep(1.0)
    return False


def cmd_watch(args) -> int:
    console = make_console()
    notifier = Notifier(console, enabled=not args.json)
    scanner = build_scanner(args, console, notifier)
    if scanner is None:
        return 6

    directory = (args.directory or downloads_dir()).expanduser()
    if not directory.is_dir():
        console.print(f"[red]Dossier introuvable : {directory}[/red]")
        return 6

    seen: set[Path] = set()
    if not args.existing:
        seen = {p for p in directory.iterdir() if p.is_file()}

    console.print(
        f"[bold cyan]Surveillance de[/bold cyan] {directory}\n"
        f"[dim]Extensions suivies : {', '.join(sorted(WATCH_EXTS))}. "
        f"Ctrl+C pour arrêter.[/dim]\n"
    )

    try:
        while True:
            for path in sorted(directory.iterdir()):
                if not path.is_file() or path in seen:
                    continue
                if path.suffix.lower() not in WATCH_EXTS:
                    continue
                if path.name.endswith((".part", ".crdownload", ".tmp", ".download")):
                    continue
                seen.add(path)
                console.print(
                    f"[cyan]Nouveau fichier :[/cyan] {path.name} "
                    f"[dim](attente de la fin du téléchargement...)[/dim]"
                )
                if not wait_until_stable(path):
                    console.print(
                        f"[yellow]{path.name} : téléchargement toujours en cours, ignoré.[/yellow]"
                    )
                    seen.discard(path)
                    continue
                result = scanner.scan_file(path)
                notifier.stop()
                if scanner.client and scanner.client.cache:
                    scanner.client.cache.flush()
                handle_results(args, console, [result], notifier)
                apply_quarantine(args, console, [result])
            time.sleep(args.interval)
    except KeyboardInterrupt:
        notifier.stop()
        console.print("\n[dim]Surveillance arrêtée.[/dim]")
        return 0


def cmd_hash(args) -> int:
    from .hashing import hash_file

    status = 0
    for raw in args.paths:
        path = raw.expanduser()
        try:
            # print() et non rich : la sortie doit rester copiable/pipe-able telle quelle.
            print(f"{hash_file(path)}  {path}")
        except OSError as exc:
            print(f"{path} : {exc}", file=sys.stderr)
            status = 6
    return status


def cmd_config(args) -> int:
    console = make_console()
    command = getattr(args, "config_command", None) or "show"

    if command == "path":
        console.print(str(config_path()))
        return 0

    if command == "set-key":
        console.print("[dim]Clé API VirusTotal (menu profil > API key sur virustotal.com) :[/dim]")
        try:
            key = getpass.getpass("Clé (masquée) : ").strip()
        except (EOFError, KeyboardInterrupt):
            console.print("\n[yellow]Annulé.[/yellow]")
            return 1
        if len(key) < 32:
            console.print("[red]Clé invalide (une clé VirusTotal fait 64 caractères).[/red]")
            return 1
        data = load_config()
        data["api_key"] = key
        path = save_config(data)
        console.print(f"[green]Clé enregistrée dans[/green] {path}")
        return 0

    data = load_config()
    key = resolve_api_key()
    source = "non configurée"
    if key:
        import os

        if os.environ.get("VT_API_KEY") or os.environ.get("VIRUSTOTAL_API_KEY"):
            source = "variable d'environnement"
        elif data.get("api_key"):
            source = str(config_path())
    console.print(f"Clé API   : {'*' * 8 + key[-4:] if key else '-'}  ({source})")
    console.print(f"Config    : {config_path()}")
    from .config import cache_path

    console.print(f"Cache     : {cache_path()}")
    return 0


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    # Raccourci : `vtzip fichier.zip` equivaut a `vtzip scan fichier.zip`
    # (y compris avec des options en tete : `vtzip --deep fichier.zip`).
    if argv and not any(arg in COMMANDS for arg in argv) and argv[0] not in ("-h", "--help", "--version"):
        argv.insert(0, "scan")

    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        return 1
    if args.command == "scan":
        return cmd_scan(args)
    if args.command == "watch":
        return cmd_watch(args)
    if args.command == "hash":
        return cmd_hash(args)
    if args.command == "config":
        return cmd_config(args)
    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
