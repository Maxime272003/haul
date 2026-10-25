"""Fenêtre principale (Tkinter)."""

import json
import logging
import os
import queue
import subprocess
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from . import __version__, clipboard, config, desktop, dialogs, notify, postprocess, updater
from .engine import ACTIVE, NO_SCRIPT, ON_DISK, Engine, Job, State, remove_partial
from .links import (
    DL_RE,
    FILE_HINT_RE,
    LINK_RE,
    archive_base,
    duration,
    folder_name,
    human_size,
    is_page_url,
    name_from_url,
    page_key,
    safe_name,
)
from .paths import ICON_PATH, QUEUE_PATH
from .server import PORT, USERSCRIPT_URL, LinkServer, bundled_script_version
from .theme import Theme
from .widgets import CellTooltip, ChoiceStepper, Flow, Stepper

log = logging.getLogger(__name__)

HINT = "Sélectionne les liens fuckingfast.co sur la page web et fais Ctrl+C."
STATUS_DOTS = {"info": "faint", "ok": "green", "warn": "amber", "error": "red"}
SPEED_CHOICES = (0, 1, 2, 5, 10, 20, 50, 100)  # débit total maximal, Mo/s (0 = illimité)
CAPTCHA_ALERT_AFTER = 10  # secondes dans le navigateur sans lien reçu : on prévient
NOTIFICATION_LIFETIME = 30_000  # ms avant de retirer l'icône de notification
LINK_MAX_AGE = 24 * 3600  # s pendant lesquelles un lien direct sauvegardé vaut la peine d'être essayé
UPDATE_FIRST_CHECK = 10_000  # ms après le lancement avant de chercher une mise à jour
UPDATE_INTERVAL = 6 * 3600 * 1000  # ms entre deux recherches

KINDS = {
    State.WAITING: "wait", State.QUEUED: "wait", State.RETRY: "wait", State.BROWSER: "browser",
    State.PAUSED: "paused", State.CONNECTING: "busy", State.CHECKING: "busy", State.EXTRACTING: "busy",
    State.DOWNLOADING: "download", State.DONE: "done", State.PRESENT: "done", State.EXTRACTED: "done",
    State.ERROR: "error", State.EXTRACT_FAILED: "error", State.BLOCKED: "error",
}
# Ordre des familles pour le tri par statut et l'icône d'un groupe (la plus importante d'abord)
KIND_ORDER = ("error", "browser", "download", "busy", "paused", "wait", "done")
# Repris tels quels au lancement suivant ; les autres (en cours à la fermeture) passent en pause.
RESTORED = frozenset({State.DONE, State.PRESENT, State.EXTRACTED, State.EXTRACT_FAILED, State.BLOCKED,
                      State.ERROR, State.PAUSED})
COLUMNS = ("#0", "status", "progress", "speed", "vt")
HEADINGS = {"#0": "FICHIER", "status": "STATUT", "progress": "PROGRESSION", "speed": "VITESSE",
            "vt": "VIRUSTOTAL"}


def status_kind(state):
    """Famille d'un état : wait, browser, paused, busy, download, done ou error."""
    return KINDS[state]


plural = dialogs.plural


def speed_label(mb):
    return f"{mb} Mo/s" if mb else "illimité"


def progress_label(done, total):
    if total and done >= total:
        return human_size(total)
    if total:
        done_text, total_text = human_size(done), human_size(total)
        if done_text.split()[-1] == total_text.split()[-1]:
            done_text = done_text.split()[0]  # « 312.0 / 500.0 Mo »
        return f"{done * 100 // total} %  ·  {done_text} / {total_text}"
    return human_size(done) if done else ""


def eta(done, total, speed):
    """Temps restant en secondes, ou None si on ne peut pas l'estimer."""
    if not total or speed <= 0 or done >= total:
        return None
    return (total - done) / speed


def sort_key(column):
    """Clé de tri d'un fichier pour une colonne de la liste."""
    return {
        "#0": lambda j: (j.name or j.url).lower(),
        "status": lambda j: (KIND_ORDER.index(KINDS[j.state]), j.status.lower()),
        "progress": lambda j: j.done / j.total if j.total else -1,
        "speed": lambda j: j.speed if j.state == State.DOWNLOADING else -1,
        "vt": lambda j: j.vt.lower(),
    }[column]


# --- sauvegarde de la liste entre deux lancements ---

def dump_jobs(jobs, now=None):
    now = time.time() if now is None else now
    return [{"url": j.url, "dest": j.dest, "name": j.name, "state": j.state.value, "detail": j.detail,
             "done": j.done, "total": j.total, "vt": j.vt, "processed": j.processed,
             # lien direct gardé : la reprise n'a pas à rouvrir la page s'il est encore valable
             **({"dl_url": j.dl_url, "user_agent": j.user_agent, "saved": now}
                if j.dl_url and j.state not in ON_DISK else {})}
            for j in jobs]


def load_jobs(items, first_id=1, now=None):
    """Jobs sauvegardés par dump_jobs ; ce qui était en cours revient en pause."""
    now = time.time() if now is None else now
    jobs = []
    for item in items if isinstance(items, list) else []:
        try:
            state, url, dest = State(item["state"]), item["url"], item["dest"]
        except (KeyError, TypeError, ValueError):
            continue
        if not isinstance(url, str) or not isinstance(dest, str):
            continue
        detail = item.get("detail") if isinstance(item.get("detail"), str) else ""
        processed = bool(item.get("processed"))
        if state in (State.CHECKING, State.EXTRACTING):  # traitement interrompu : à refaire
            state, detail, processed = State.DONE, "", False
        elif state not in RESTORED:
            state, detail = State.PAUSED, ""
        name = item.get("name")
        total = item.get("total")
        done = item.get("done")
        dl_url, user_agent, saved = item.get("dl_url"), item.get("user_agent"), item.get("saved")
        if not (isinstance(dl_url, str) and DL_RE.fullmatch(dl_url) and isinstance(saved, (int, float))
                and 0 <= now - saved < LINK_MAX_AGE):
            dl_url = None
        if not (dl_url and isinstance(user_agent, str) and len(user_agent) <= 512 and user_agent.isprintable()):
            user_agent = None
        jobs.append(Job(id=first_id + len(jobs), url=url, dest=dest,
                        name=safe_name(name) if isinstance(name, str) else None, state=state, detail=detail,
                        done=done if isinstance(done, int) else 0, total=total if isinstance(total, int) else None,
                        dl_url=dl_url, user_agent=user_agent,
                        vt=item.get("vt") if isinstance(item.get("vt"), str) else "", processed=processed))
    return jobs


def group_summary(jobs):
    """Ligne de groupe (volumes d'un même jeu) : (famille, fraction, statut, progression, vitesse, verdict)."""
    kinds = {}
    for job in jobs:
        kinds[KINDS[job.state]] = kinds.get(KINDS[job.state], 0) + 1
    kind = next(k for k in KIND_ORDER if k in kinds)
    if len(kinds) == 1 and len({j.status for j in jobs}) == 1:
        status = jobs[0].status
    else:
        names = {"error": ("erreur", "erreurs"), "browser": ("dans le navigateur", "dans le navigateur"),
                 "download": ("en cours", "en cours"), "busy": ("en cours", "en cours"),
                 "paused": ("en pause", "en pause"), "wait": ("en attente", "en attente"),
                 "done": ("terminé", "terminés")}
        counts = {}
        for k in KIND_ORDER:
            if k in kinds:
                label = names[k][kinds[k] > 1]
                counts[label] = counts.get(label, 0) + kinds[k]
        status = "  ·  ".join(f"{n} {label}" for label, n in counts.items())
    sized = [j for j in jobs if j.total]
    done, total = sum(min(j.done, j.total) for j in sized), sum(j.total for j in sized)
    progress = progress_label(done, total) if len(sized) == len(jobs) else ""
    speed = sum(j.speed for j in jobs if j.state == State.DOWNLOADING)
    left = eta(done, total, speed) if len(sized) == len(jobs) else None
    speed_text = f"{human_size(speed)}/s" + (f"  ·  {duration(left)}" if left else "") if speed > 0 else ""
    vts = {j.vt for j in jobs}
    fraction = done / total if total and kind in ("download", "paused") else None
    return kind, fraction, status, progress, speed_text, vts.pop() if len(vts) == 1 else ""


class App:
    def __init__(self, root, minimized=False):
        self.root = root
        self.cfg = config.load()
        self.events = queue.Queue()    # (job.id, {champ: valeur}) ou (None, {"message": …, "done": bool, "kind": …})
        self.incoming = queue.Queue()  # liens reçus pour des pages ouvertes à la main dans le navigateur
        self.calls = queue.Queue()     # fonctions à exécuter dans le thread de l'interface
        self.engine = Engine(self.events, lambda *link: self.incoming.put(link))
        self.engine.set_parallel(self.cfg["parallel"])
        self.engine.set_connections(self.cfg["connections"])
        self.engine.set_max_speed(self.cfg["max_speed"] << 20)
        self.jobs = {}          # job.id -> Job, dans l'ordre de la file (priorité)
        self.seen = set()
        self.next_id = 1
        self.busy = False       # analyse / extraction en cours
        self.suspended = False  # « Tout suspendre » : les nouveaux liens arrivent en pause
        self.last_report = None
        self.tick = 0           # animation des icônes « en cours »
        self.queue_dirty = False
        self.last_queue_save = 0.0
        self.browser_since = {}  # job.id -> début de l'attente dans le navigateur
        self.captcha_alerted = set()
        self.no_script_warned = False
        self.was_active = False
        self.notification_timer = None
        self.sort = None        # (colonne, décroissant) ou None : ordre de la file
        self.groups = {}        # postprocess.set_key -> iid de la ligne de groupe
        self.next_group = 1
        self.layout_dirty = True
        self.tray = None
        self.script_seen = None  # version du userscript qui s'est manifesté pendant cette session
        self.update = None  # {"version", "path"} : nouvelle version téléchargée, installée en quittant
        self.update_busy = False  # recherche ou téléchargement en cours
        root.report_callback_exception = self._on_tk_error

        self.theme = Theme(root, self.cfg["theme"])
        px = self.theme.px
        root.title(f"Haul {__version__}")
        if ICON_PATH.exists():
            root.iconbitmap(default=str(ICON_PATH))
        self._build()
        root.update_idletasks()
        root.minsize(max(root.winfo_reqwidth(), px(880)), px(560))
        width = max(root.winfo_reqwidth(), min(px(1240), root.winfo_screenwidth() * 92 // 100))
        root.geometry(f"{width}x{min(px(760), root.winfo_screenheight() * 85 // 100)}")
        self.theme.decorate(root)
        self.hwnd = notify.window_handle(root)
        self.taskbar = notify.TaskbarProgress(self.hwnd)
        self.notifier = notify.Notifier(self.hwnd, ICON_PATH if ICON_PATH.exists() else None)
        self.drop = desktop.FileDrop(root, lambda paths: self.calls.put(lambda: self._add_from_files(paths)))
        if self.cfg["tray"]:
            self._start_tray()
        root.bind("<Unmap>", self._on_unmap, add="+")
        self._restore_queue()
        self.last_seq = clipboard.sequence()
        self.timers = {"clipboard": root.after(700, self._poll_clipboard),
                       "events": root.after(200, self._drain_events)}
        if self.cfg["auto_update"]:
            self.timers["update"] = root.after(UPDATE_FIRST_CHECK, self._check_update)
        root.protocol("WM_DELETE_WINDOW", self._on_close)
        try:
            self.server = LinkServer(
                self.engine, self.cfg["token"],
                on_bad_token=lambda kind: self.calls.put(lambda: self._script_outdated(kind)),
                on_script=lambda version: self.calls.put(lambda: self._script_active(version)),
                on_show=lambda: self.calls.put(self._show_window))
            threading.Thread(target=self.server.serve_forever, daemon=True).start()
        except OSError:
            self.server = None
            self._port_busy()
        self._refresh_script_label()
        if minimized:
            if self.tray and self.tray.hwnd:
                root.withdraw()
            else:
                root.iconify()

    # --- configuration ---

    def _save_config(self):
        speed = SPEED_CHOICES[self.speed_stepper.index()]
        self.cfg.update(folder=self.folder_var.get(), parallel=self._spin_value(self.parallel_var, 1, 6),
                        connections=self._spin_value(self.conn_var, 1, 16), max_speed=speed,
                        watch=self.watch_var.get(), scan=self.scan_var.get(), extract=self.extract_var.get(),
                        notify=self.notify_var.get(), subfolders=self.subfolders_var.get(),
                        delete_archives=self.delete_var.get(), tray=self.tray_var.get(),
                        auto_update=self.update_var.get())
        config.save(self.cfg)

    @staticmethod
    def _spin_value(var, lo, hi):
        try:
            return max(lo, min(hi, int(var.get())))
        except ValueError:
            return lo

    def _settings_changed(self):
        self._save_config()
        self.engine.set_parallel(self.cfg["parallel"])
        self.engine.set_connections(self.cfg["connections"])
        self.engine.set_max_speed(self.cfg["max_speed"] << 20)

    def _refresh_pipeline(self):
        """Résumé, sous les options, de ce que Haul fait des fichiers téléchargés (détails dans Réglages)."""
        scan, extract = self.scan_var.get(), self.extract_var.get()
        steps = (["analyse VirusTotal"] if scan else []) + (["extraction WinRAR"] if extract else [])
        text = "Après le téléchargement : " + (", puis ".join(steps) if steps else "rien, fichiers laissés tels quels")
        if extract and self.delete_var.get():
            text += ", archives à la corbeille"
        if self.subfolders_var.get():
            text += " · un dossier par jeu"
        self.pipeline_var.set(text + ".")

    def _switch_changed(self):
        self._refresh_pipeline()
        self._save_config()
        if self.tray_var.get() and not self.tray:
            self._start_tray()
        elif not self.tray_var.get() and self.tray:
            self.tray.stop()
            self.tray = None
            self._show_window()
        if self.update_var.get() and not self.timers.get("update"):
            self._check_update()
        self._postprocess()  # analyse / extraction activée alors que des fichiers attendent

    def _autostart_changed(self):
        on = self.autostart_var.get()
        if desktop.set_autostart(on):
            self._status("Haul démarrera avec Windows, réduit dans la zone de notification." if on
                         else "Haul ne démarrera plus avec Windows.", "ok")
        else:
            self.autostart_var.set(desktop.autostart_enabled())
            self._status("Impossible de modifier le démarrage avec Windows.", "error")

    # --- interface ---

    def _build(self):
        px = self.theme.px
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        body = ttk.Frame(self.root, padding=(px(24), px(18), px(24), px(14)))
        body.grid(row=0, column=0, sticky="nsew")
        body.columnconfigure(0, weight=1)
        body.rowconfigure(3, weight=1)

        self._build_header(body).grid(row=0, column=0, sticky="ew", pady=(0, px(16)))
        self._build_settings(body).grid(row=1, column=0, sticky="ew", pady=(0, px(20)))
        self._build_list_header(body).grid(row=2, column=0, sticky="ew", pady=(0, px(8)))
        self._build_list(body).grid(row=3, column=0, sticky="nsew")
        self._build_actions(body).grid(row=4, column=0, sticky="ew", pady=(px(12), 0))
        self._build_statusbar().grid(row=1, column=0, sticky="ew")

        self.root.bind("<Control-v>", self._paste_shortcut)
        self.root.bind("<Control-V>", self._paste_shortcut)
        self.root.bind("<Control-f>", lambda e: self.filter_entry.focus_set())

    def _build_header(self, parent):
        px = self.theme.px
        header = ttk.Frame(parent)
        header.columnconfigure(1, weight=1)
        if ICON_PATH.with_suffix(".png").exists():
            icon = tk.PhotoImage(master=self.root, file=str(ICON_PATH.with_suffix(".png")))
            self.logo = icon.subsample(max(1, round(icon.width() / px(40))))
            ttk.Label(header, image=self.logo).grid(row=0, column=0, rowspan=2, padx=(0, px(12)))
        ttk.Label(header, text="Haul", style="Title.TLabel").grid(row=0, column=1, sticky="sw")
        self.script_var = tk.StringVar()
        subtitle = ttk.Label(header, textvariable=self.script_var, style="Muted.TLabel", justify="left")
        subtitle.grid(row=1, column=1, sticky="nw", padx=(0, px(16)))
        buttons = ttk.Frame(header)
        buttons.grid(row=0, column=2, rowspan=2, sticky="e")

        def wrap(_event=None):
            # Le sous-titre passe à la ligne au lieu de passer sous les boutons ; fenêtre étroite :
            # les boutons passent sous le titre.
            width = header.winfo_width()
            if width <= 1:
                return
            free = width - buttons.winfo_reqwidth() - subtitle.winfo_x() - px(16)
            below = free < px(300)
            if below != self.header_buttons_below:
                self.header_buttons_below = below
                if below:
                    buttons.grid(row=2, column=0, columnspan=3, sticky="w", pady=(px(12), 0))
                else:
                    buttons.grid(row=0, column=2, rowspan=2, columnspan=1, sticky="e", pady=0)
            subtitle.configure(wraplength=max(px(160), width - subtitle.winfo_x() - px(16) if below else free))
        self.header_buttons_below = False
        header.bind("<Configure>", wrap)
        buttons.bind("<Configure>", wrap)
        # affiché quand une nouvelle version est téléchargée (voir _update_ready)
        self.update_btn = ttk.Button(buttons, style="Accent.TButton", command=lambda: self._on_close(restart=True))
        self.script_btn = ttk.Button(buttons, text="Installer le script navigateur",
                                     command=lambda: os.startfile(USERSCRIPT_URL))
        self.script_btn.pack(side="left")
        ttk.Button(buttons, text="Ajouter des liens…", command=lambda: dialogs.links_dialog(self)).pack(
            side="left", padx=(px(8), 0))
        ttk.Button(buttons, text="Ajouter depuis le presse-papier", style="Accent.TButton",
                   command=self._add_from_clipboard).pack(side="left", padx=(px(8), 0))
        return header

    def _build_settings(self, parent):
        px = self.theme.px
        card = ttk.Frame(parent, style="Card.TFrame", padding=(px(18), px(14), px(18), px(16)))
        card.columnconfigure(0, weight=1)
        ttk.Label(card, text="DOSSIER DE DESTINATION", style="Caption.TLabel").grid(
            row=0, column=0, columnspan=3, sticky="w", pady=(0, px(6)))
        self.folder_var = tk.StringVar(value=self.cfg["folder"])
        folder = ttk.Entry(card, textvariable=self.folder_var)
        folder.grid(row=1, column=0, sticky="ew")
        folder.bind("<FocusOut>", lambda e: self._save_config())
        folder.bind("<Return>", lambda e: self._save_config())
        ttk.Button(card, text="Parcourir…", command=self._choose_folder).grid(
            row=1, column=1, sticky="ns", padx=(px(8), 0))
        ttk.Button(card, text="Ouvrir", command=self._open_folder).grid(row=1, column=2, sticky="ns", padx=(px(8), 0))
        ttk.Frame(card, style="Line.TFrame", height=1).grid(row=2, column=0, columnspan=3, sticky="ew",
                                                             pady=px(14))

        opts = Flow(card, gap=px(28), row_gap=px(10), style="Surface.TFrame")
        opts.grid(row=3, column=0, columnspan=2, sticky="ew")
        # le reste (analyse, extraction, application) est dans la fenêtre Réglages
        ttk.Button(card, text="Réglages…", command=lambda: dialogs.settings_dialog(self)).grid(
            row=3, column=2, sticky="ne", padx=(px(8), 0))
        self.watch_var = tk.BooleanVar(value=self.cfg["watch"])
        self.parallel_var = tk.StringVar(value=str(self.cfg["parallel"]))
        self.conn_var = tk.StringVar(value=str(self.cfg["connections"]))
        speed = min(SPEED_CHOICES, key=lambda v: abs(v - self.cfg["max_speed"]))
        self.speed_var = tk.StringVar(value=speed_label(speed))
        self.scan_var = tk.BooleanVar(value=self.cfg["scan"])
        self.extract_var = tk.BooleanVar(value=self.cfg["extract"])
        self.notify_var = tk.BooleanVar(value=self.cfg["notify"])
        self.subfolders_var = tk.BooleanVar(value=self.cfg["subfolders"])
        self.delete_var = tk.BooleanVar(value=self.cfg["delete_archives"])
        self.tray_var = tk.BooleanVar(value=self.cfg["tray"])
        self.autostart_var = tk.BooleanVar(value=desktop.autostart_enabled())
        self.update_var = tk.BooleanVar(value=self.cfg["auto_update"])


        def labelled(text, make):
            box = ttk.Frame(opts, style="Surface.TFrame")
            ttk.Label(box, text=text, style="Surface.TLabel").pack(side="left", padx=(0, px(10)))
            widget = make(box)
            widget.pack(side="left")
            return box, widget

        parallel, _ = labelled("Fichiers simultanés", lambda box: Stepper(
            box, self.parallel_var, 1, 6, command=self._settings_changed, style="Surface.TFrame"))
        conns, _ = labelled("Connexions par fichier", lambda box: Stepper(
            box, self.conn_var, 1, 16, command=self._settings_changed, style="Surface.TFrame"))
        speed_box, self.speed_stepper = labelled("Débit max", lambda box: ChoiceStepper(
            box, self.speed_var, [speed_label(v) for v in SPEED_CHOICES], command=self._settings_changed,
            style="Surface.TFrame"))
        watch = ttk.Checkbutton(opts, text="Surveiller le presse-papier", variable=self.watch_var,
                                style="Switch.TCheckbutton", command=self._switch_changed)
        opts.add(watch, parallel, conns, speed_box)
        self.pipeline_var = tk.StringVar()
        pipeline = ttk.Label(card, textvariable=self.pipeline_var, style="SurfaceMuted.TLabel", justify="left")
        pipeline.grid(row=4, column=0, columnspan=3, sticky="w", pady=(px(12), 0))
        card.bind("<Configure>", lambda e: pipeline.configure(wraplength=max(px(200), e.width - px(40))), add="+")
        self._refresh_pipeline()
        return card

    def _build_list_header(self, parent):
        px = self.theme.px
        bar = ttk.Frame(parent)
        bar.columnconfigure(1, weight=1)
        ttk.Label(bar, text="Téléchargements", style="Heading.TLabel").grid(row=0, column=0, sticky="w")
        self.summary_var = tk.StringVar()
        ttk.Label(bar, textvariable=self.summary_var, style="Muted.TLabel").grid(
            row=0, column=1, sticky="w", padx=(px(12), 0))
        self.total_var = tk.StringVar()
        ttk.Label(bar, textvariable=self.total_var, style="Speed.TLabel").grid(row=0, column=2, sticky="e")
        ttk.Label(bar, text="Filtrer", style="Muted.TLabel").grid(row=0, column=3, sticky="e", padx=(px(16), px(6)))
        self.filter_var = tk.StringVar()
        self.filter_var.trace_add("write", lambda *_: self._mark_layout())
        self.filter_entry = ttk.Entry(bar, textvariable=self.filter_var, width=18)
        self.filter_entry.grid(row=0, column=4, sticky="e")
        self.filter_entry.bind("<Escape>", lambda e: self.filter_var.set(""))
        return bar

    def _build_list(self, parent):
        px = self.theme.px
        card = ttk.Frame(parent, style="Card.TFrame", padding=(px(6), px(4), px(4), px(6)))
        card.columnconfigure(0, weight=1)
        card.rowconfigure(0, weight=1)

        self.tree = ttk.Treeview(card, columns=COLUMNS[1:], show=("tree", "headings"), selectmode="extended",
                                 height=6)
        for col in COLUMNS:
            self.tree.heading(col, text=HEADINGS[col], anchor="w", command=lambda c=col: self._sort_by(c))
            # largeurs calculées d'après le contenu : voir _fit_columns
            self.tree.column(col, width=px(100), minwidth=px(60), stretch=False, anchor="w")
        self.tree.grid(row=0, column=0, sticky="nsew")
        self.tree.bind("<Configure>", lambda e: self._fit_columns())
        self.tree.bind("<<TreeviewSelect>>", self._show_selected)
        self.columns_dirty = True
        self._text_widths = {}
        scroll = ttk.Scrollbar(card, orient="vertical", command=self.tree.yview)
        scroll.grid(row=0, column=1, sticky="ns", pady=(px(36), px(2)))

        def autohide(first, last):  # barre visible seulement si la liste déborde
            if float(first) <= 0 and float(last) >= 1:
                scroll.grid_remove()
            else:
                scroll.grid()
            scroll.set(first, last)
        self.tree.configure(yscrollcommand=autohide)
        CellTooltip(self.tree, self.theme)

        self.menu = self.theme.menu(self.root)
        self.tree.bind("<Button-3>", self._context_menu)
        self.tree.bind("<Double-1>", lambda e: self._reveal(self._job_at(e.y)))
        self.tree.bind("<Delete>", lambda e: self._remove(self._selected_jobs()))
        self.tree.bind("<space>", lambda e: self._toggle_pause(self._selected_jobs()))
        self.tree.bind("<Control-a>", lambda e: self.tree.selection_set(self.tree.get_children()) or "break")
        self.tree.bind("<Alt-Up>", lambda e: self._prioritize(self._selected_jobs(), True) or "break")
        self.tree.bind("<Alt-Down>", lambda e: self._prioritize(self._selected_jobs(), False) or "break")
        self.tree.bind("<<TreeviewSelect>>", lambda e: self._refresh_pause_button(), add="+")

        self.empty = ttk.Frame(card, style="Surface.TFrame")
        ttk.Label(self.empty, text="Aucun téléchargement", style="EmptyTitle.TLabel").pack()
        ttk.Label(self.empty, text=HINT + "\nLes pages s'ouvrent dans ton navigateur, Haul télécharge le reste.\n"
                                          "Tu peux aussi déposer ici une page enregistrée ou une liste de liens.",
                  style="SurfaceMuted.TLabel", justify="center").pack(pady=(px(6), 0))
        self.empty.place(relx=0.5, rely=0.5, anchor="center")
        return card

    def _text_width(self, text):
        if text not in self._text_widths:
            if len(self._text_widths) > 4000:  # textes de progression : tous différents
                self._text_widths.clear()
            self._text_widths[text] = self.theme.font.measure(text)
        return self._text_widths[text]

    def _fit_columns(self):
        """Largeurs des colonnes d'après leur contenu, pour que rien ne soit coupé quand la place suffit.

        Progression, vitesse et verdict prennent la largeur de leur contenu (avec un minimum réservé
        pour la progression et la vitesse, pour que les colonnes bougent peu pendant les téléchargements).
        Le nom prend ensuite la place dont il a besoin et le statut le reste ; si les deux ne tiennent
        pas, chacun reçoit une part proportionnelle à sa largeur utile. Le texte complet reste visible
        en infobulle et dans la barre d'état.
        """
        px = self.theme.px
        self.columns_dirty = False
        width = self.tree.winfo_width()
        if width <= 1:
            return
        text, pad = self._text_width, px(24)
        heading = lambda col: self.theme.font_caption.measure(self.tree.heading(col, "text")) + pad
        jobs = self.jobs.values()
        groups = [self.tree.item(iid, "text") for iid in self.groups.values() if self.tree.exists(iid)]
        widths = {
            "progress": max([heading("progress"), text("100 %  ·  999.9 / 999.9 Mo") + pad,
                             text("99 %  ·  1023.9 Mo / 99.9 Go") + pad]
                            + [text(self._row(j)[1]) + pad for j in jobs]),
            "speed": max(heading("speed"), text("1023.9 Mo/s  ·  59 min") + pad),
            "vt": max([heading("vt")] + [text(j.vt) + pad for j in jobs if j.vt]),
        }
        free = max(width - sum(widths.values()) - px(2), 2 * px(120))
        indent = px(20) if groups else 0  # volumes d'un jeu, en retrait sous leur groupe
        want_name = max([px(180)] + [text(j.name or j.url) + px(52) + indent for j in jobs]
                        + [text(g) + px(52) for g in groups])  # icône comprise
        want_status = max([px(180)] + [text(j.status) + pad for j in jobs])
        if want_name + want_status <= free:
            name = want_name
        else:
            name = free * want_name // (want_name + want_status)
        widths["#0"] = name = max(px(120), min(name, free - px(120)))
        widths["status"] = free - name
        for col, w in widths.items():
            if int(self.tree.column(col, "width")) != w:
                self.tree.column(col, width=w)

    def _show_selected(self, _event=None):
        """Texte complet de la ligne sélectionnée dans la barre d'état (qui passe à la ligne)."""
        jobs = self._selected_jobs()
        if len(jobs) == 1 and not self.busy:
            job = jobs[0]
            kind = {"error": "error", "done": "ok"}.get(status_kind(job.state), "info")
            vt = f" · VirusTotal : {job.vt}" if job.vt else ""
            self._status(f"{job.name or job.url} — {job.status}{vt}", kind)

    def _build_actions(self, parent):
        px = self.theme.px
        actions = Flow(parent, gap=px(8), row_gap=px(8))
        # libellés mis à jour par _refresh selon la sélection et l'état de la liste
        self.pause_btn = ttk.Button(actions, text="Mettre en pause",
                                    command=lambda: self._toggle_pause(self._selected_jobs()))
        self.suspend_btn = ttk.Button(actions, text="Tout suspendre", command=self._toggle_suspend)
        self.retry_btn = ttk.Button(actions, text="Réessayer les échecs", command=self._retry_failed)
        self.clear_btn = ttk.Button(actions, text="Retirer les terminés", command=self._clear_done)
        self.clear_all_btn = ttk.Button(actions, text="Tout supprimer", command=lambda: dialogs.clear_all_dialog(self))
        self.process_btn = ttk.Button(actions, text="Analyser / extraire maintenant",
                                      command=lambda: self._postprocess(manual=True))
        self.report_btn = ttk.Button(actions, text="Rapport VirusTotal", command=self._show_report)
        actions.add(self.pause_btn, self.suspend_btn, self.retry_btn, self.clear_btn, self.clear_all_btn,
                    self.process_btn, self.report_btn)
        return actions

    def _build_statusbar(self):
        px = self.theme.px
        bar = ttk.Frame(self.root, style="Surface.TFrame")
        bar.columnconfigure(1, weight=1)
        ttk.Frame(bar, style="Line.TFrame", height=1).grid(row=0, column=0, columnspan=2, sticky="ew")
        self.status_icon = ttk.Label(bar, style="Surface.TLabel")
        # icône centrée sur la première ligne du message
        top = px(8) + max(0, self.theme.font.metrics("linespace") - px(16)) // 2
        self.status_icon.grid(row=1, column=0, sticky="n", padx=(px(24), px(2)), pady=(top, px(8)))
        self.status_var = tk.StringVar()
        message = ttk.Label(bar, textvariable=self.status_var, style="Surface.TLabel", justify="left")
        message.grid(row=1, column=1, sticky="w", padx=(0, px(24)), pady=px(8))
        # le message passe à la ligne au lieu d'être coupé
        bar.bind("<Configure>", lambda e: message.configure(wraplength=max(px(200), e.width - px(80))))
        self.status_kind = "info"
        self._status(HINT)
        return bar

    def _status(self, message, kind="info"):
        """Message de la barre d'état ; kind : info, ok, warn, error ou busy."""
        self.status_var.set(message)
        self.status_kind = kind
        self._refresh_status_icon()

    def _refresh_status_icon(self):
        if self.status_kind == "busy":
            image = self.theme.status_icon("download", frame=self.tick)
        else:
            image = self.theme.dot(STATUS_DOTS[self.status_kind])
        self.status_icon.configure(image=image)

    def _on_tk_error(self, exc, value, tb):
        """Exception dans un rappel de l'interface : journalisée (pas de console sous Haul.exe) et signalée."""
        log.error("Erreur de l'interface", exc_info=(exc, value, tb))
        try:
            self._status(f"Erreur inattendue : {value or exc.__name__} (détails dans haul.log)", "error")
        except Exception:
            pass

    def _choose_folder(self):
        folder = filedialog.askdirectory(initialdir=self.folder_var.get() or os.path.expanduser("~"))
        if folder:
            self.folder_var.set(os.path.normpath(folder))
            self._save_config()

    def _open_folder(self, folder=None):
        folder = folder or self.folder_var.get()
        os.makedirs(folder, exist_ok=True)
        os.startfile(folder)

    # --- userscript et serveur local ---

    def _port_busy(self):
        owner = desktop.port_owner(PORT)
        if owner and not owner.lower().startswith(("haul", "python")):
            self._status(f"Port {PORT} occupé par {owner} : le navigateur ne peut pas envoyer les liens à Haul. "
                         "Ferme ce programme puis relance Haul.", "error")
        else:
            self._status(f"Port {PORT} occupé{f' par {owner}' if owner else ''} : Haul est peut-être déjà lancé.",
                         "warn")

    def _refresh_script_label(self):
        bundled = bundled_script_version()
        seen = self.script_seen if self.script_seen is not None else self.cfg["script_version"]
        prefix = f"Téléchargements FuckingFast · version {__version__} · "
        if not seen:
            text = "script navigateur non détecté"
        elif seen == "?" or (bundled and self._older(seen, bundled)):
            text = f"script navigateur {'' if seen == '?' else seen + ' '}actif, mise à jour {bundled} en attente"
        else:
            text = f"script navigateur {seen} {'actif ✔' if self.script_seen else 'installé'}"
        self.script_var.set(prefix + text)

    @staticmethod
    def _older(version, other):
        def parts(v):
            return tuple(int(p) for p in v.split(".") if p.isdigit())
        return parts(version) < parts(other)

    def _script_active(self, version):
        version = version or "?"  # avant la 3.3, le script n'envoyait pas sa version
        if version != self.script_seen:
            self.script_seen = version
            if self.cfg["script_version"] != version:
                self.cfg["script_version"] = version
                config.save(self.cfg)
            self._refresh_script_label()

    def _script_outdated(self, kind):
        """Requête refusée : kind « missing » (script sans jeton) ou « wrong » (jeton écrit dans un script 3.1)."""
        if kind == "missing":
            self._status("Une ancienne copie du script Haul (sans jeton) tourne encore dans un navigateur : "
                         "supprime-la dans Violentmonkey / Tampermonkey, ou mets-la à jour avec « Installer le "
                         "script navigateur ».", "warn")
        else:
            self._status("Le script navigateur est en version 3.1 : mets-le à jour une dernière fois (« Installer le "
                         "script navigateur »). À partir de la 3.2, il se synchronise tout seul avec Haul.", "warn")

    # --- mises à jour ---

    def _check_update(self):
        """Cherche une nouvelle release (dans un thread) ; recommence toutes les UPDATE_INTERVAL ms."""
        self.timers["update"] = None
        if not self.update_var.get():
            return
        self.timers["update"] = self.root.after(UPDATE_INTERVAL, self._check_update)
        if self.update_busy:
            return
        self.update_busy = True

        def run():
            try:
                release = updater.latest_release(__version__)
            except Exception:
                log.warning("Recherche de mise à jour impossible", exc_info=True)
                release = None
            self.calls.put(lambda: self._update_found(release))
        threading.Thread(target=run, daemon=True).start()

    def _update_found(self, release):
        exe = updater.current_exe()
        if not release or (self.update and self.update["version"] == release["version"]):
            self.update_busy = False
            return
        if not exe:  # lancé depuis les sources : rien à remplacer
            self.update_busy = False
            self._status(f"Haul {release['version']} est disponible : {release['page']}")
            return
        log.info("Mise à jour %s : téléchargement", release["version"])

        def run():
            try:
                path = updater.download(release, __version__, exe)
            except Exception as e:
                log.warning("Téléchargement de la mise à jour impossible", exc_info=True)
                self.calls.put(lambda error=e: self._update_failed(release, error))  # e effacé après except
                return
            self.calls.put(lambda: self._update_ready(release, path))
        threading.Thread(target=run, daemon=True).start()

    def _update_failed(self, release, error):
        self.update_busy = False
        self._status(f"Mise à jour {release['version']} non téléchargée ({error}) : nouvel essai plus tard, ou "
                     f"télécharge-la sur {release['page']}", "warn")

    def _update_ready(self, release, path):
        self.update_busy = False
        self.update = {"version": release["version"], "path": path}
        self.update_btn.configure(text=f"Redémarrer pour mettre à jour ({release['version']})")
        self.update_btn.pack(side="left", padx=(0, self.theme.px(8)), before=self.script_btn)
        self._status(f"Haul {release['version']} est prêt : il s'installera quand tu quitteras Haul, ou tout de "
                     "suite avec « Redémarrer pour mettre à jour ».", "ok")
        self._alert("Mise à jour prête", f"Haul {release['version']} s'installera à la fermeture.")

    def _install_update(self, restart):
        """En quittant : remplace Haul.exe par la version téléchargée, et la lance si demandé."""
        exe = updater.current_exe()
        if not self.update or not exe:
            return
        try:
            updater.install(self.update["path"], exe)
            log.info("Mise à jour %s installée", self.update["version"])
            if restart:
                updater.relaunch(exe)
        except OSError:
            log.exception("Installation de la mise à jour impossible")

    # --- fenêtre, zone de notification, notifications ---

    def _start_tray(self):
        self.tray = desktop.Tray(ICON_PATH if ICON_PATH.exists() else None, "Haul",
                                 lambda key: self.calls.put(lambda: self._tray_command(key)))
        if not self.tray.hwnd:
            self.tray = None

    def _tray_command(self, key):
        if key == "open":
            self._show_window()
        elif key == "suspend":
            self._toggle_suspend()
        elif key == "folder":
            self._open_folder()
        elif key == "quit":
            self._show_window()
            self._on_close()

    def _tray_items(self):
        return [("open", "Afficher Haul", True), None,
                ("suspend", self._suspend_label(), self.suspend_btn.instate(["!disabled"])),
                ("folder", "Ouvrir le dossier de destination", True), None, ("quit", "Quitter Haul", True)]

    def _show_window(self):
        self.root.deiconify()
        self.root.lift()
        self.root.focus_force()
        desktop.bring_to_front(self.hwnd)

    def _on_unmap(self, event):
        # réduire la fenêtre la range dans la zone de notification
        if event.widget is self.root and self.tray and self.root.state() == "iconic":
            self.root.withdraw()

    def _alert(self, title, text, warning=False):
        """Prévient hors de la fenêtre (notification + bouton qui clignote) si elle n'est pas au premier plan."""
        if not self.notify_var.get() or notify.is_foreground(self.hwnd):
            return
        notify.flash(self.hwnd)
        if self.tray and self.tray.balloon(title, text, warning):
            return
        self.notifier.show(title, text, warning)
        if self.notification_timer:
            self.root.after_cancel(self.notification_timer)
        self.notification_timer = self.root.after(NOTIFICATION_LIFETIME, self.notifier.remove)

    def _watch_attention(self, kinds):
        """Captcha qui attend, fin de la liste : notification et progression dans la barre des tâches."""
        now = time.monotonic()
        waiting = [self.jobs[i] for i, since in self.browser_since.items()
                   if now - since > CAPTCHA_ALERT_AFTER and i in self.jobs]
        for job in waiting:
            if job.id not in self.captcha_alerted and job.detail != NO_SCRIPT:
                self.captcha_alerted.add(job.id)
                self._alert("Captcha à valider", f"{job.name or job.url} attend dans ton navigateur.", warning=True)

        active = any(j.state in ACTIVE for j in self.jobs.values())
        if self.was_active and not active:
            done, errors = kinds.get("done", 0), kinds.get("error", 0)
            self._alert("Téléchargements terminés",
                        plural(done, "fichier terminé", "fichiers terminés")
                        + (f", {plural(errors, 'erreur')}" if errors else ""), warning=bool(errors))
        self.was_active = active

        tb = notify.TaskbarProgress
        if active:
            sized = [j for j in self.jobs.values() if j.total and (j.state in ACTIVE or j.state in ON_DISK)]
            total = sum(j.total for j in sized)
            fraction = sum(min(j.done, j.total) for j in sized) / total if total else None
            state = tb.PAUSED if waiting else tb.NORMAL if fraction is not None else tb.INDETERMINATE
            self.taskbar.set(state, fraction)
        elif self.busy:
            self.taskbar.set(tb.INDETERMINATE)
        elif kinds.get("error"):
            self.taskbar.set(tb.ERROR, 1.0)
        else:
            self.taskbar.set(tb.NONE)

    def _warn_no_script(self, job):
        if self.no_script_warned:
            return
        self.no_script_warned = True
        self._status("Le script Haul ne répond pas dans le navigateur qui a ouvert la page : installe-le "
                     "(« Installer le script navigateur ») dans ton navigateur par défaut, avec Violentmonkey ou "
                     "Tampermonkey. La page attend encore quelques minutes.", "warn")
        self._alert("Script navigateur absent ?", f"{job.name or job.url} : aucune nouvelle du script Haul.",
                    warning=True)

    # --- liste : groupes, tri, filtre ---

    def _job_at(self, y):
        iid = self.tree.identify_row(y)
        return self.jobs.get(int(iid)) if iid and iid.isdigit() else None

    def _group_jobs(self, iid):
        key = next((k for k, g in self.groups.items() if g == iid), None)
        return [j for j in self.jobs.values() if postprocess.set_key(j) == key] if key else []

    def _selected_jobs(self):
        jobs = {}
        for iid in self.tree.selection():
            for job in self._group_jobs(iid) if not iid.isdigit() else [self.jobs.get(int(iid))]:
                if job:
                    jobs[job.id] = job
        return list(jobs.values())

    def _mark_layout(self):
        self.layout_dirty = True

    def _sort_by(self, column):
        """Clic sur un en-tête : tri croissant, décroissant, puis retour à l'ordre de la file."""
        if not self.sort or self.sort[0] != column:
            self.sort = (column, False)
        elif not self.sort[1]:
            self.sort = (column, True)
        else:
            self.sort = None
        for col in COLUMNS:
            arrow = (" ▼" if self.sort[1] else " ▲") if self.sort and self.sort[0] == col else ""
            self.tree.heading(col, text=HEADINGS[col] + arrow)
        self.layout_dirty = True

    def _layout(self):
        """Ordre, groupes et filtre de la liste.

        Les volumes d'un même jeu sont rangés sous une ligne de groupe repliée qui résume leur
        avancement ; sans tri, l'ordre est celui de la file (priorité).
        """
        self.layout_dirty = False
        tree = self.tree
        members = {}
        for job in self.jobs.values():
            key = postprocess.set_key(job)
            if key and key[2]:
                members.setdefault(key, []).append(job)
        members = {k: v for k, v in members.items() if len(v) > 1}
        for key in [k for k in self.groups if k not in members]:
            iid = self.groups.pop(key)
            for child in tree.get_children(iid):
                tree.move(child, "", "end")
            tree.delete(iid)
        for key, jobs in members.items():
            if key not in self.groups:
                self.groups[key] = iid = f"g{self.next_group}"
                self.next_group += 1
                name = folder_name(jobs[0].name) or archive_base(jobs[0].name)
                tree.insert("", "end", iid=iid, open=False, text=name)
                self.columns_dirty = True
        for job in self.jobs.values():
            if not tree.exists(str(job.id)):
                tree.insert("", "end", iid=str(job.id), **self._item(job))

        query = self.filter_var.get().strip().lower()

        def match(job):
            return not query or query in (job.name or job.url).lower() or query in job.status.lower()

        ordered = list(self.jobs.values())
        if self.sort:
            ordered.sort(key=sort_key(self.sort[0]), reverse=self.sort[1])
        top, placed = [], set()
        for job in ordered:
            key = postprocess.set_key(job)
            if key in self.groups:
                if key not in placed:
                    placed.add(key)
                    visible = [str(j.id) for j in ordered if postprocess.set_key(j) == key and match(j)]
                    if visible:
                        top.append((self.groups[key], visible))
            elif match(job):
                top.append((str(job.id), None))
        keep = {iid for iid, _ in top}
        for iid in tree.get_children(""):
            if iid not in keep:
                tree.detach(iid)
        for index, (iid, children) in enumerate(top):
            tree.move(iid, "", index)
            if children is not None:
                for child in tree.get_children(iid):
                    if child not in children:
                        tree.detach(child)
                for i, child in enumerate(children):
                    tree.move(child, iid, i)
                if query:
                    tree.item(iid, open=True)
        self._refresh_groups()

    def _refresh_groups(self):
        for key, iid in self.groups.items():
            jobs = [j for j in self.jobs.values() if postprocess.set_key(j) == key]
            if not jobs:
                continue
            kind, fraction, status, progress, speed, vt = group_summary(jobs)
            name = folder_name(jobs[0].name) or archive_base(jobs[0].name)
            tree_kind = kind if kind != "download" or fraction is not None else "busy"
            self.tree.item(iid, text=f"{name}  ({plural(len(jobs), 'fichier')})",
                           image=self.theme.status_icon(tree_kind, fraction, self.tick),
                           values=(status, progress, speed, vt))

    # --- menu contextuel ---

    def _context_menu(self, event):
        iid = self.tree.identify_row(event.y)
        if not iid:
            return
        if iid not in self.tree.selection():
            self.tree.selection_set(iid)
        jobs = self._selected_jobs()
        if not jobs:
            return
        job = self.jobs[int(iid)] if iid.isdigit() else jobs[0]
        m = self.menu
        m.delete(0, "end")

        def item(label, command, targets):
            m.add_command(label=label, command=lambda: command(targets), state="normal" if targets else "disabled")

        m.add_command(label="Afficher dans l'Explorateur", command=lambda: self._reveal(job))
        m.add_command(label="Copier le lien de la page", command=lambda: self._copy_links(jobs))
        in_browser = [j for j in jobs if j.state == State.BROWSER and is_page_url(j.url)]
        if in_browser:
            item("Rouvrir la page dans le navigateur", self._reopen_pages, in_browser)
        m.add_separator()
        pausable = [j for j in jobs if j.state in ACTIVE]
        item("Passer ce lien (pause)" if in_browser and len(jobs) == 1 else "Mettre en pause", self._pause, pausable)
        item("Reprendre", self._resume, [j for j in jobs if j.state == State.PAUSED])
        item("Réessayer", self._retry, [j for j in jobs if j.state in (State.ERROR, State.RETRY)])
        waiting = [j for j in jobs if j.state in (State.WAITING, State.QUEUED, State.PAUSED, State.RETRY)]
        item("Placer en tête de file (Alt+↑)", lambda t: self._prioritize(t, True), waiting)
        item("Placer en fin de file (Alt+↓)", lambda t: self._prioritize(t, False), waiting)
        m.add_separator()
        item("Retirer de la liste", self._remove, [j for j in jobs if status_kind(j.state) != "busy"
                                                   or j.state == State.CONNECTING])
        m.tk_popup(event.x_root, event.y_root)

    def _reveal(self, job):
        if not job:
            return
        if job.path and os.path.exists(job.path):
            subprocess.Popen(f'explorer /select,"{job.path}"')
        else:
            self._open_folder(job.dest)

    def _reopen_pages(self, jobs):
        for job in jobs:
            if is_page_url(job.url):
                os.startfile(job.url)

    def _copy_links(self, jobs):
        self.root.clipboard_clear()
        self.root.clipboard_append("\n".join(j.url for j in jobs))
        self.root.update_idletasks()
        self.last_seq = clipboard.sequence()  # ne pas relire ce qu'on vient de copier
        self._status(f"{plural(len(jobs), 'lien copié', 'liens copiés')}.", "ok")

    def _prioritize(self, jobs, first=True):
        """Place les fichiers en tête (ou en fin) de la file : pages à ouvrir et téléchargements en attente."""
        if not jobs:
            return
        self.engine.prioritize(jobs, first)
        ids = {j.id for j in jobs}
        moved = [j for j in self.jobs.values() if j.id in ids]
        rest = [j for j in self.jobs.values() if j.id not in ids]
        self.jobs = {j.id: j for j in (moved + rest if first else rest + moved)}
        self.layout_dirty = self.queue_dirty = True
        if self.sort:
            self._status("Ordre de la file modifié ; clique sur l'en-tête trié pour revenir à l'ordre de la file.")

    def _remove(self, jobs):
        """Retire de la liste ; un fichier en cours est d'abord mis en pause (le fichier partiel reste)."""
        for job in jobs:
            if job.state in (State.CHECKING, State.EXTRACTING) or job.id not in self.jobs:
                continue  # analyse / extraction en cours
            if job.state in ACTIVE:
                self.engine.pause(job)
            self.tree.delete(str(job.id))
            del self.jobs[job.id]
            self.seen.discard(page_key(job.url))  # pourra être ajouté de nouveau
            self.browser_since.pop(job.id, None)
            self.columns_dirty = self.queue_dirty = self.layout_dirty = True

    def _pause(self, jobs):
        for job in jobs:
            if job.state in ACTIVE:
                self.engine.pause(job)

    def _resume(self, jobs):
        for job in jobs:
            if job.state == State.PAUSED:
                self.engine.submit(job)

    def _toggle_pause(self, jobs):
        if any(j.state in ACTIVE for j in jobs):
            self._pause(jobs)
        else:
            self._resume(jobs)

    def _suspend_all(self):
        """Met tout en pause ; les liens ajoutés ensuite arrivent en pause jusqu'à « Tout reprendre »."""
        self.suspended = True
        self._pause(list(self.jobs.values()))
        self._status("Téléchargements suspendus : les fichiers partiels sont gardés, « Tout reprendre » "
                     "repart de là. Les liens ajoutés entre-temps attendent en pause.", "warn")

    def _resume_all(self):
        self.suspended = False
        self._resume(list(self.jobs.values()))

    def _toggle_suspend(self):
        if self._suspend_label() == "Tout suspendre":
            self._suspend_all()
        else:
            self._resume_all()

    def _suspend_label(self):
        active = any(j.state in ACTIVE for j in self.jobs.values())
        paused = any(j.state == State.PAUSED for j in self.jobs.values())
        return "Tout reprendre" if self.suspended or (paused and not active) else "Tout suspendre"

    # --- presse-papier, fichiers déposés ---

    def _read_clipboard(self):
        try:
            text = self.root.clipboard_get()
        except tk.TclError:
            text = ""
        return text, clipboard.read_html()

    def _poll_clipboard(self):
        seq = clipboard.sequence()
        if seq != self.last_seq:
            self.last_seq = seq
            if self.watch_var.get():
                self._add_from_clipboard(quiet=True)
        self.timers["clipboard"] = self.root.after(700, self._poll_clipboard)

    def _paste_shortcut(self, event):
        if not isinstance(event.widget, (tk.Entry, ttk.Entry, tk.Text)):
            self._add_from_clipboard()

    def _add_from_clipboard(self, quiet=False):
        text, html_text = self._read_clipboard()
        if self._add_links(text + "\n" + html_text):
            return
        if FILE_HINT_RE.search(text):
            self._status("Noms de fichiers sans liens : copie-les depuis la page web, pas depuis un fichier texte.",
                         "warn")
        elif not quiet:
            self._status("Aucun lien fuckingfast.co dans le presse-papier.", "warn")

    def _add_from_files(self, paths):
        """Fichiers déposés sur la fenêtre : page enregistrée, liste de liens, raccourci .url."""
        text = "\n".join(dialogs.read_link_file(p) for p in paths if os.path.isfile(p))
        if not self._add_links(text):
            self._status("Aucun lien fuckingfast.co dans " + ("ce fichier." if len(paths) == 1 else "ces fichiers."),
                         "warn")

    def _add_links(self, text):
        """Ajoute les liens trouvés ; retourne True s'il y en avait, même déjà connus."""
        urls = [m.group(0) for m in LINK_RE.finditer(text or "")]
        # Les fichiers hors archive copiés avec un jeu (bonus, langues…) vont dans le dossier de ce jeu.
        folders = [f for f in (folder_name(name_from_url(u)) for u in urls) if f]
        game = max(set(folders), key=folders.count) if folders else None
        added = sum(self._add_job(url, game=game) for url in urls)
        if added:
            self._status(f"{plural(added, 'lien ajouté', 'liens ajoutés')}.", "ok")
        elif urls:
            self._status("Ces liens sont déjà dans la liste.")
        return bool(urls)

    def _insert(self, job):
        self.seen.add(page_key(job.url))
        self.jobs[job.id] = job
        self.tree.insert("", "end", iid=str(job.id), **self._item(job))
        self.columns_dirty = self.queue_dirty = self.layout_dirty = True

    def _destination(self, name, game=None):
        """Dossier du fichier : un sous-dossier par jeu si le réglage est actif (nom de l'archive, sinon
        `game`, le jeu copié en même temps)."""
        folder = self.folder_var.get()
        sub = (folder_name(name) or game) if self.subfolders_var.get() else None
        return os.path.join(folder, sub) if sub else folder

    def _add_job(self, url, dl_url=None, user_agent=None, game=None):
        if page_key(url) in self.seen:
            return False
        name = name_from_url(url)
        job = Job(id=self.next_id, url=url, dest=self._destination(name, game), name=name,
                  dl_url=dl_url, user_agent=user_agent, state=State.PAUSED if self.suspended else State.WAITING)
        self.next_id += 1
        self._insert(job)
        if not self.suspended:
            self.engine.submit(job)
        return True

    # --- liste sauvegardée ---

    def _restore_queue(self):
        try:
            items = json.loads(QUEUE_PATH.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return
        jobs = load_jobs(items, self.next_id)
        for job in jobs:
            self._insert(job)
        self.next_id += len(jobs)
        self.queue_dirty = False
        paused = sum(j.state == State.PAUSED for j in jobs)
        if paused:
            self._status(f"{plural(paused, 'téléchargement interrompu', 'téléchargements interrompus')} "
                         "lors de la dernière session : « Tout reprendre » pour continuer.", "warn")

    def _save_queue(self):
        self.queue_dirty, self.last_queue_save = False, time.monotonic()
        try:
            QUEUE_PATH.parent.mkdir(parents=True, exist_ok=True)
            tmp = QUEUE_PATH.with_suffix(".tmp")
            tmp.write_text(json.dumps(dump_jobs(self.jobs.values()), ensure_ascii=False, indent=1), encoding="utf-8")
            tmp.replace(QUEUE_PATH)
        except OSError:
            log.exception("Sauvegarde de la liste impossible")

    # --- suivi des téléchargements ---

    @staticmethod
    def _row(job):
        progress = progress_label(job.done, job.total)
        speed = ""
        if job.speed > 0 and job.state == State.DOWNLOADING:
            left = eta(job.done, job.total, job.speed)
            speed = f"{human_size(job.speed)}/s" + (f"  ·  {duration(left)}" if left else "")
        return (job.status, progress, speed, job.vt)

    def _item(self, job):
        kind = status_kind(job.state)
        fraction = job.done / job.total if kind in ("download", "paused") and job.total else None
        image = self.theme.status_icon(kind, fraction, self.tick)
        return {"text": job.name or job.url, "image": image, "values": self._row(job)}

    def _drain_events(self):
        try:
            self._apply_events()
        except Exception:
            log.exception("Mise à jour de l'interface")
        finally:
            self.timers["events"] = self.root.after(200, self._drain_events)

    def _apply_events(self):
        while not self.calls.empty():
            self.calls.get()()
        while not self.incoming.empty():
            page_url, dl_url, user_agent = self.incoming.get()
            if self._add_job(page_url or dl_url, dl_url, user_agent):
                self._status("Lien reçu du navigateur.", "ok")
        changed = False
        try:
            while True:
                job_id, fields = self.events.get_nowait()
                if job_id is None:  # message de l'analyse / extraction
                    self.busy = not fields.get("done")
                    kind = fields.get("kind") or ("busy" if self.busy else "ok")
                    self._status(fields["message"], kind)
                    if fields.get("done"):
                        changed = True
                        self._alert("Analyse / extraction terminée", fields["message"], warning=kind == "error")
                    continue
                job = self.jobs.get(job_id)
                if not job:
                    continue
                for k, v in fields.items():
                    setattr(job, k, v)
                if fields.keys() & {"state", "name", "vt", "detail"}:
                    self.columns_dirty = self.queue_dirty = changed = True
                    if self.sort or self.filter_var.get():
                        self.layout_dirty = True
                if "state" in fields:
                    if job.state == State.BROWSER:
                        self.browser_since.setdefault(job.id, time.monotonic())
                        if job.detail == NO_SCRIPT:
                            self._warn_no_script(job)
                    else:
                        self.browser_since.pop(job.id, None)
                if self.tree.exists(str(job_id)):
                    self.tree.item(str(job_id), **self._item(job))
        except queue.Empty:
            pass
        if self.layout_dirty:
            self._layout()
        kinds = self._refresh()
        self._watch_attention(kinds)
        if self.queue_dirty and time.monotonic() - self.last_queue_save > 2:
            self._save_queue()
        if changed and (self.scan_var.get() or self.extract_var.get()):
            self._postprocess()

    def _refresh(self):
        """Animations, compteurs, débit total et boutons disponibles. Retourne le nombre de fichiers par famille."""
        self.tick += 1
        kinds = {}
        for job in self.jobs.values():
            kind = status_kind(job.state)
            kinds[kind] = kinds.get(kind, 0) + 1
            if kind == "busy" or (kind == "download" and not job.total):
                self.tree.item(str(job.id), image=self.theme.status_icon(kind, frame=self.tick))
        self._refresh_groups()
        if self.status_kind == "busy":
            self._refresh_status_icon()
        if self.columns_dirty:
            self._fit_columns()

        if self.jobs:
            self.empty.place_forget()
            parts = (["suspendu"] if self.suspended else []) + [plural(len(self.jobs), "fichier")]
            active = kinds.get("download", 0) + kinds.get("busy", 0) + kinds.get("browser", 0)
            for n, text in ((active, "en cours"), (kinds.get("wait", 0), "en attente"),
                            (kinds.get("paused", 0), "en pause"),
                            (kinds.get("done", 0), plural(kinds.get("done", 0), "terminé")[2:]),
                            (kinds.get("error", 0), plural(kinds.get("error", 0), "erreur")[2:])):
                if n:
                    parts.append(f"{n} {text}")
            self.summary_var.set("  ·  ".join(parts))
        else:
            # message de liste vide seulement s'il tient sous les en-têtes de colonnes
            room = self.tree.winfo_height() - self.theme.px(48)
            if room >= self.empty.winfo_reqheight():
                self.empty.place(relx=0.5, rely=0.5, anchor="center")
            else:
                self.empty.place_forget()
            self.summary_var.set("")

        downloading = [j for j in self.jobs.values() if j.state == State.DOWNLOADING]
        total = sum(j.speed for j in downloading)
        left = eta(sum(j.done for j in downloading if j.total), sum(j.total for j in downloading if j.total), total)
        self.total_var.set(f"↓ {human_size(total)}/s  ·  {total * 8 / 1e6:.0f} Mbit/s"
                           + (f"  ·  fin dans {duration(left)}" if left else "") if total else "")

        def enable(button, on):
            button.state(["!disabled"] if on else ["disabled"])
        self._refresh_pause_button()
        label = self._suspend_label()
        if self.suspend_btn.cget("text") != label:
            self.suspend_btn.configure(text=label)
        enable(self.suspend_btn, self.suspended or kinds.get("paused", 0) or any(
            j.state in ACTIVE for j in self.jobs.values()))
        enable(self.retry_btn, any(j.state in (State.ERROR, State.RETRY) for j in self.jobs.values()))
        enable(self.clear_btn, kinds.get("done", 0))
        enable(self.clear_all_btn, self.jobs)
        enable(self.process_btn, not self.busy and any(j.state in ON_DISK for j in self.jobs.values()))
        enable(self.report_btn, self.last_report is not None)
        if self.tray:
            self.tray.items = self._tray_items()
        return kinds

    def _refresh_pause_button(self):
        """« Mettre en pause » ou « Reprendre » selon la sélection."""
        selected = self._selected_jobs()
        active = any(j.state in ACTIVE for j in selected)
        paused = any(j.state == State.PAUSED for j in selected)
        label = "Reprendre" if paused and not active else "Mettre en pause"
        if self.pause_btn.cget("text") != label:
            self.pause_btn.configure(text=label)
        self.pause_btn.state(["!disabled"] if active or paused else ["disabled"])

    def _retry(self, jobs):
        for job in jobs:
            if job.state in (State.ERROR, State.RETRY):
                self.engine.submit(job)

    def _retry_failed(self):
        self._retry(list(self.jobs.values()))

    def _clear_done(self):
        self._remove([j for j in self.jobs.values() if status_kind(j.state) == "done"])

    def _clear_all(self, delete_partials=False):
        jobs = [j for j in self.jobs.values() if j.state not in (State.CHECKING, State.EXTRACTING)]
        if delete_partials:
            for job in jobs:
                if job.state in ACTIVE:
                    self.engine.pause(job, discard=True)  # supprimé par le moteur une fois arrêté
                elif job.path and job.state not in ON_DISK:
                    remove_partial(job.path)
        self._remove(jobs)
        self._save_queue()
        self._status(f"Liste vidée ({plural(len(jobs), 'fichier retiré', 'fichiers retirés')}"
                     + (", téléchargements inachevés supprimés du disque)." if delete_partials else ")."), "ok")

    # --- analyse VirusTotal puis extraction ---

    def _postprocess(self, manual=False):
        """Analyse puis extrait les fichiers téléchargés.

        En automatique : chaque jeu dès que tous ses volumes de la liste sont téléchargés, une seule
        fois par fichier (voir postprocess.ready_for_postprocess).
        """
        if self.busy or not self.jobs:
            return
        if manual:
            batch = [j for j in self.jobs.values() if j.state in ON_DISK and j.path and j.state != State.EXTRACTED]
        else:
            batch = postprocess.ready_for_postprocess(self.jobs.values())
        if not batch:
            if manual:
                self._status("Rien à traiter : aucun fichier téléchargé en attente.")
            return
        scan, extract = self.scan_var.get(), self.extract_var.get() or manual
        winrar = postprocess.find_winrar() if extract else None
        if extract and not winrar:
            self._status("WinRAR introuvable : extraction impossible.", "error")
            self.extract_var.set(False)
            self._refresh_pipeline()
        if not scan and not winrar:
            return
        for job in batch:
            job.processed = True
        self.queue_dirty = True
        self.busy = True
        threading.Thread(target=self._postprocess_worker, args=(batch, scan, winrar), daemon=True).start()

    def _postprocess_worker(self, batch, scan, winrar):
        def status(message, done=False, kind=None):
            self.events.put((None, {"message": message, "done": done, "kind": kind}))

        try:
            postprocess.process(
                batch, scan, winrar, lambda job, **fields: self.events.put((job.id, fields)), status,
                delete_archives=self.cfg["delete_archives"],
                on_report=lambda report: self.calls.put(lambda: setattr(self, "last_report", report)),
                on_missing_key=lambda: self.calls.put(self._api_key_dialog))
        except Exception as e:
            log.exception("Analyse / extraction")
            status(f"Analyse / extraction interrompue : {e}", done=True, kind="error")

    def _show_report(self):
        if not self.last_report:
            self._status("Aucune analyse VirusTotal pour l'instant.")
            return
        dialogs.report_window(self)

    def _api_key_dialog(self):
        dialogs.api_key_dialog(self)

    def _on_close(self, restart=False):
        """Quitte Haul (en installant une mise à jour téléchargée ; restart : puis relance Haul)."""
        active = [j for j in self.jobs.values() if j.state in ACTIVE]
        if active or self.busy:
            lines = []
            if active:
                lines.append(f"{plural(len(active), 'téléchargement')} en cours ou en attente : "
                             "ils seront mis en pause et pourront reprendre au prochain lancement.")
            if self.busy:
                lines.append("L'analyse ou l'extraction en cours sera interrompue.")
            question = "Redémarrer Haul pour le mettre à jour ?" if restart else "Quitter Haul ?"
            if not messagebox.askyesno("Mettre à jour Haul ?" if restart else "Quitter Haul ?",
                                       "\n\n".join(lines) + "\n\n" + question,
                                       icon="warning", default="no", parent=self.root):
                return
        self._save_config()
        self.engine.shutdown()
        self._save_queue()
        if self.server:
            self.server.shutdown()
        self.notifier.remove()
        if self.tray:
            self.tray.stop()
        self.taskbar.set(notify.TaskbarProgress.NONE)
        for timer in (*self.timers.values(), self.notification_timer):
            if timer:
                self.root.after_cancel(timer)
        self._install_update(restart)
        self.root.destroy()
