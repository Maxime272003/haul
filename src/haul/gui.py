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

from . import __version__, clipboard, config, notify, postprocess
from .engine import ACTIVE, ON_DISK, Engine, Job, State
from .links import FILE_HINT_RE, LINK_RE, human_size, is_page_url, name_from_url, page_key, safe_name
from .paths import ICON_PATH, QUEUE_PATH
from .server import PORT, USERSCRIPT_URL, LinkServer
from .theme import Theme
from .widgets import CellTooltip, ChoiceStepper, Flow, Stepper

log = logging.getLogger(__name__)

HINT = "Sélectionne les liens fuckingfast.co sur la page web et fais Ctrl+C."
STATUS_DOTS = {"info": "faint", "ok": "green", "warn": "amber", "error": "red"}
SPEED_CHOICES = (0, 1, 2, 5, 10, 20, 50, 100)  # débit total maximal, Mo/s (0 = illimité)
CAPTCHA_ALERT_AFTER = 10  # secondes dans le navigateur sans lien reçu : on prévient
NOTIFICATION_LIFETIME = 30_000  # ms avant de retirer l'icône de notification
VT_KEY_URL = "https://www.virustotal.com/gui/my-apikey"
EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"  # connu de VirusTotal

KINDS = {
    State.WAITING: "wait", State.QUEUED: "wait", State.BROWSER: "browser", State.PAUSED: "paused",
    State.CONNECTING: "busy", State.CHECKING: "busy", State.EXTRACTING: "busy", State.DOWNLOADING: "download",
    State.DONE: "done", State.PRESENT: "done", State.EXTRACTED: "done",
    State.ERROR: "error", State.EXTRACT_FAILED: "error", State.BLOCKED: "error",
}
# Repris tels quels au lancement suivant ; les autres (en cours à la fermeture) passent en pause.
RESTORED = frozenset({State.DONE, State.PRESENT, State.EXTRACTED, State.EXTRACT_FAILED, State.BLOCKED,
                      State.ERROR, State.PAUSED})


def status_kind(state):
    """Famille d'un état : wait, browser, paused, busy, download, done ou error."""
    return KINDS[state]


def plural(n, word, plural_word=None):
    return f"{n} {word if n < 2 else plural_word or word + 's'}"


def speed_label(mb):
    return f"{mb} Mo/s" if mb else "illimité"


# --- sauvegarde de la liste entre deux lancements ---

def dump_jobs(jobs):
    return [{"url": j.url, "dest": j.dest, "name": j.name, "state": j.state.value, "detail": j.detail,
             "done": j.done, "total": j.total, "vt": j.vt, "processed": j.processed} for j in jobs]


def load_jobs(items, first_id=1):
    """Jobs sauvegardés par dump_jobs ; ce qui était en cours revient en pause."""
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
        jobs.append(Job(id=first_id + len(jobs), url=url, dest=dest,
                        name=safe_name(name) if isinstance(name, str) else None, state=state, detail=detail,
                        done=done if isinstance(done, int) else 0, total=total if isinstance(total, int) else None,
                        vt=item.get("vt") if isinstance(item.get("vt"), str) else "", processed=processed))
    return jobs


class App:
    def __init__(self, root):
        self.root = root
        self.cfg = config.load()
        self.events = queue.Queue()    # (job.id, {champ: valeur}) ou (None, {"message": …, "done": bool, "kind": …})
        self.incoming = queue.Queue()  # liens reçus pour des pages ouvertes à la main dans le navigateur
        self.calls = queue.Queue()     # fonctions à exécuter dans le thread de l'interface
        self.engine = Engine(self.events, lambda *link: self.incoming.put(link))
        self.engine.set_parallel(self.cfg["parallel"])
        self.engine.set_connections(self.cfg["connections"])
        self.engine.set_max_speed(self.cfg["max_speed"] << 20)
        self.jobs = {}
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
        self.was_active = False
        self.notification_timer = None

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
        self._restore_queue()
        self.last_seq = clipboard.sequence()
        self.timers = {"clipboard": root.after(700, self._poll_clipboard),
                       "events": root.after(200, self._drain_events)}
        root.protocol("WM_DELETE_WINDOW", self._on_close)
        try:
            self.server = LinkServer(self.engine, self.cfg["token"],
                                     on_bad_token=lambda: self.calls.put(self._script_outdated))
            threading.Thread(target=self.server.serve_forever, daemon=True).start()
        except OSError:
            self.server = None
            self._status(f"Port {PORT} occupé : Haul est peut-être déjà lancé.", "warn")

    # --- configuration ---

    def _save_config(self):
        speed = SPEED_CHOICES[self.speed_stepper.index()]
        self.cfg.update(folder=self.folder_var.get(), parallel=self._spin_value(self.parallel_var, 1, 6),
                        connections=self._spin_value(self.conn_var, 1, 16), max_speed=speed,
                        watch=self.watch_var.get(), scan=self.scan_var.get(), extract=self.extract_var.get(),
                        notify=self.notify_var.get())
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

    def _switch_changed(self):
        self._save_config()
        self._postprocess()  # analyse / extraction activée alors que la liste est déjà finie

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

    def _build_header(self, parent):
        px = self.theme.px
        header = ttk.Frame(parent)
        header.columnconfigure(1, weight=1)
        if ICON_PATH.with_suffix(".png").exists():
            icon = tk.PhotoImage(master=self.root, file=str(ICON_PATH.with_suffix(".png")))
            self.logo = icon.subsample(max(1, round(icon.width() / px(40))))
            ttk.Label(header, image=self.logo).grid(row=0, column=0, rowspan=2, padx=(0, px(12)))
        ttk.Label(header, text="Haul", style="Title.TLabel").grid(row=0, column=1, sticky="sw")
        ttk.Label(header, text=f"Téléchargements FuckingFast · version {__version__}",
                  style="Muted.TLabel").grid(row=1, column=1, sticky="nw")
        buttons = ttk.Frame(header)
        buttons.grid(row=0, column=2, rowspan=2, sticky="e")
        ttk.Button(buttons, text="Installer le script navigateur",
                   command=lambda: os.startfile(USERSCRIPT_URL)).pack(side="left")
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
        opts.grid(row=3, column=0, columnspan=3, sticky="ew")
        self.watch_var = tk.BooleanVar(value=self.cfg["watch"])
        self.parallel_var = tk.StringVar(value=str(self.cfg["parallel"]))
        self.conn_var = tk.StringVar(value=str(self.cfg["connections"]))
        speed = min(SPEED_CHOICES, key=lambda v: abs(v - self.cfg["max_speed"]))
        self.speed_var = tk.StringVar(value=speed_label(speed))
        self.scan_var = tk.BooleanVar(value=self.cfg["scan"])
        self.extract_var = tk.BooleanVar(value=self.cfg["extract"])
        self.notify_var = tk.BooleanVar(value=self.cfg["notify"])

        def switch(text, var):
            return ttk.Checkbutton(opts, text=text, variable=var, style="Switch.TCheckbutton",
                                   command=self._switch_changed)

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
        opts.add(switch("Surveiller le presse-papier", self.watch_var), parallel, conns, speed_box,
                 switch("Analyser avec VirusTotal", self.scan_var),
                 ttk.Button(opts, text="Clé VirusTotal…", command=self._api_key_dialog),
                 switch("Puis extraire avec WinRAR", self.extract_var),
                 switch("Notifications", self.notify_var))
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
        return bar

    def _build_list(self, parent):
        px = self.theme.px
        card = ttk.Frame(parent, style="Card.TFrame", padding=(px(6), px(4), px(4), px(6)))
        card.columnconfigure(0, weight=1)
        card.rowconfigure(0, weight=1)

        cols = ("status", "progress", "speed", "vt")
        self.tree = ttk.Treeview(card, columns=cols, show=("tree", "headings"), selectmode="extended", height=6)
        for col, text in (("#0", "FICHIER"), ("status", "STATUT"), ("progress", "PROGRESSION"),
                          ("speed", "VITESSE"), ("vt", "VIRUSTOTAL")):
            self.tree.heading(col, text=text, anchor="w")
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
        self.tree.bind("<<TreeviewSelect>>", lambda e: self._refresh_pause_button(), add="+")

        self.empty = ttk.Frame(card, style="Surface.TFrame")
        ttk.Label(self.empty, text="Aucun téléchargement", style="EmptyTitle.TLabel").pack()
        ttk.Label(self.empty, text=HINT + "\nLes pages s'ouvrent dans ton navigateur, Haul télécharge le reste.",
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
        widths = {
            "progress": max([heading("progress"), text("100 %  ·  999.9 / 999.9 Mo") + pad,
                             text("99 %  ·  1023.9 Mo / 99.9 Go") + pad]
                            + [text(self._row(j)[1]) + pad for j in jobs]),
            "speed": max(heading("speed"), text("1023.9 Mo/s") + pad),
            "vt": max([heading("vt")] + [text(j.vt) + pad for j in jobs if j.vt]),
        }
        free = max(width - sum(widths.values()) - px(2), 2 * px(120))
        want_name = max([px(180)] + [text(j.name or j.url) + px(52) for j in jobs])  # icône comprise
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
        self.process_btn = ttk.Button(actions, text="Analyser / extraire maintenant",
                                      command=lambda: self._postprocess(manual=True))
        self.report_btn = ttk.Button(actions, text="Rapport VirusTotal", command=self._show_report)
        actions.add(self.pause_btn, self.suspend_btn, self.retry_btn, self.clear_btn, self.process_btn,
                    self.report_btn)
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

    def _choose_folder(self):
        folder = filedialog.askdirectory(initialdir=self.folder_var.get() or os.path.expanduser("~"))
        if folder:
            self.folder_var.set(os.path.normpath(folder))
            self._save_config()

    def _open_folder(self, folder=None):
        folder = folder or self.folder_var.get()
        os.makedirs(folder, exist_ok=True)
        os.startfile(folder)

    def _script_outdated(self):
        self._status("Le script navigateur est à mettre à jour : clique « Installer le script navigateur » "
                     "puis confirme dans Violentmonkey / Tampermonkey.", "warn")

    # --- notifications ---

    def _alert(self, title, text, warning=False):
        """Prévient hors de la fenêtre (notification + bouton qui clignote) si elle n'est pas au premier plan."""
        if not self.notify_var.get() or notify.is_foreground(self.hwnd):
            return
        notify.flash(self.hwnd)
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
            if job.id not in self.captcha_alerted:
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

    # --- menu contextuel ---

    def _job_at(self, y):
        iid = self.tree.identify_row(y)
        return self.jobs.get(int(iid)) if iid else None

    def _selected_jobs(self):
        return [self.jobs[int(iid)] for iid in self.tree.selection() if int(iid) in self.jobs]

    def _context_menu(self, event):
        iid = self.tree.identify_row(event.y)
        if not iid:
            return
        if iid not in self.tree.selection():
            self.tree.selection_set(iid)
        jobs = self._selected_jobs()
        job = self.jobs[int(iid)]
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
        item("Réessayer", self._retry, [j for j in jobs if j.state == State.ERROR])
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
            self.columns_dirty = self.queue_dirty = True

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

    # --- presse-papier ---

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

    def _add_links(self, text):
        """Ajoute les liens trouvés ; retourne True s'il y en avait, même déjà connus."""
        urls = [m.group(0) for m in LINK_RE.finditer(text or "")]
        added = sum(self._add_job(url) for url in urls)
        if added:
            self._status(f"{plural(added, 'lien ajouté', 'liens ajoutés')}.", "ok")
        elif urls:
            self._status("Ces liens sont déjà dans la liste.")
        return bool(urls)

    def _insert(self, job):
        self.seen.add(page_key(job.url))
        self.jobs[job.id] = job
        self.tree.insert("", "end", iid=str(job.id), **self._item(job))
        self.columns_dirty = self.queue_dirty = True

    def _add_job(self, url, dl_url=None, user_agent=None):
        if page_key(url) in self.seen:
            return False
        job = Job(id=self.next_id, url=url, dest=self.folder_var.get(), name=name_from_url(url),
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
        if job.total and job.done >= job.total:
            progress = human_size(job.total)
        elif job.total:
            done, total = human_size(job.done), human_size(job.total)
            if done.split()[-1] == total.split()[-1]:
                done = done.split()[0]  # « 312.0 / 500.0 Mo »
            progress = f"{job.done * 100 // job.total} %  ·  {done} / {total}"
        elif job.done:
            progress = human_size(job.done)
        else:
            progress = ""
        speed = f"{human_size(job.speed)}/s" if job.speed > 0 and job.state == State.DOWNLOADING else ""
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
                if "state" in fields:
                    if job.state == State.BROWSER:
                        self.browser_since.setdefault(job.id, time.monotonic())
                    else:
                        self.browser_since.pop(job.id, None)
                if self.tree.exists(str(job_id)):
                    self.tree.item(str(job_id), **self._item(job))
        except queue.Empty:
            pass
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
            self.empty.place(relx=0.5, rely=0.5, anchor="center")
            self.summary_var.set("")

        total = sum(j.speed for j in self.jobs.values() if j.state == State.DOWNLOADING)
        self.total_var.set(f"↓ {human_size(total)}/s  ·  {total * 8 / 1e6:.0f} Mbit/s" if total else "")

        def enable(button, on):
            button.state(["!disabled"] if on else ["disabled"])
        self._refresh_pause_button()
        label = self._suspend_label()
        if self.suspend_btn.cget("text") != label:
            self.suspend_btn.configure(text=label)
        enable(self.suspend_btn, self.suspended or kinds.get("paused", 0) or any(
            j.state in ACTIVE for j in self.jobs.values()))
        enable(self.retry_btn, any(j.state == State.ERROR for j in self.jobs.values()))
        enable(self.clear_btn, kinds.get("done", 0))
        enable(self.process_btn, not self.busy and any(j.state in ON_DISK for j in self.jobs.values()))
        enable(self.report_btn, self.last_report is not None)
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
            if job.state == State.ERROR:
                self.engine.submit(job)

    def _retry_failed(self):
        self._retry(list(self.jobs.values()))

    def _clear_done(self):
        self._remove([j for j in self.jobs.values() if status_kind(j.state) == "done"])

    # --- analyse VirusTotal puis extraction ---

    def _postprocess(self, manual=False):
        """Analyse puis extrait les fichiers téléchargés.

        En automatique : seulement quand toute la liste est finie, et une seule fois par fichier.
        """
        if self.busy or not self.jobs:
            return
        if not manual and not all(j.state in ON_DISK for j in self.jobs.values()):
            return  # téléchargements en cours, en attente, en pause ou en échec
        batch = [j for j in self.jobs.values() if j.state in ON_DISK and j.path
                 and (j.state != State.EXTRACTED if manual else not j.processed)]
        if not batch:
            if manual:
                self._status("Rien à traiter : aucun fichier téléchargé en attente.")
            return
        scan, extract = self.scan_var.get(), self.extract_var.get() or manual
        winrar = postprocess.find_winrar() if extract else None
        if extract and not winrar:
            self._status("WinRAR introuvable : extraction impossible.", "error")
            self.extract_var.set(False)
        if not scan and not winrar:
            return
        for job in batch:
            job.processed = True
        self.queue_dirty = True
        self.busy = True
        threading.Thread(target=self._postprocess_worker, args=(batch, scan, winrar), daemon=True).start()

    def _postprocess_worker(self, batch, scan, winrar):
        def put(job, **fields):
            self.events.put((job.id, fields))

        def set_state(job, state, detail=""):
            put(job, state=state, detail=detail)

        def status(message, done=False, kind=None):
            self.events.put((None, {"message": message, "done": done, "kind": kind}))

        if scan:
            for job in batch:
                put(job, vt="Analyse…")
            status("Analyse VirusTotal en cours (quota gratuit : 4 requêtes/min, compte quelques minutes)…")
            try:
                report = postprocess.scan([j.path for j in batch], notify=status)
            except Exception as e:
                log.exception("Analyse VirusTotal impossible")
                for job in batch:
                    put(job, vt="non analysé", processed=False)  # à refaire une fois le problème réglé
                if isinstance(e, postprocess.MissingApiKey):
                    self.calls.put(self._api_key_dialog)
                return status(f"Analyse VirusTotal impossible : {e}. Extraction non lancée.", done=True,
                              kind="error")
            self.last_report = report
            report.save()
            verdicts = report.verdicts()
            blocking = []
            for job in batch:
                level, label = verdicts.get(os.path.normcase(job.path), ("error", "non analysé"))
                put(job, vt=label)
                if level in postprocess.BLOCKING_LEVELS:
                    blocking.append(f"{job.name} : {label}")
            if blocking:
                log.warning("Extraction bloquée par l'analyse : %s", blocking)
                if winrar:
                    for job in batch:
                        if job.name.lower().endswith(".rar"):
                            set_state(job, State.BLOCKED, "Extraction bloquée : analyse VirusTotal")
                more = f" (+{len(blocking) - 1})" if len(blocking) > 1 else ""
                return status(f"Extraction bloquée — {blocking[0]}{more}. Clique « Rapport VirusTotal ».",
                              done=True, kind="error")
            if not winrar:
                return status("Analyse VirusTotal terminée : rien de bloquant.", done=True)

        todo = postprocess.archive_sets(batch)
        if not todo:
            return status("Rien de bloquant, aucune archive .rar à extraire.", done=True)
        ok, failures = 0, []
        for first, group in todo.items():
            name = os.path.basename(first)
            for job in group:
                set_state(job, State.CHECKING)
            status(f"Vérification de {name} avant extraction…")
            try:
                dest = postprocess.prepare_extraction(winrar, first)
            except (postprocess.ExtractionBlocked, OSError, subprocess.SubprocessError) as e:
                log.warning("Extraction de %s bloquée : %s", first, e)
                for job in group:
                    set_state(job, State.BLOCKED, f"Extraction bloquée : {e}")
                failures.append(f"{name} : {e}")
                continue
            for job in group:
                set_state(job, State.EXTRACTING)
            status(f"Extraction de {name}…")
            try:
                code = postprocess.extract(winrar, first, dest)
            except OSError as e:
                log.exception("Extraction impossible")
                code = str(e)
            if code == 0:
                ok += 1
                where = os.path.relpath(dest, os.path.dirname(first))
                detail = "" if where == "." else f"Extrait ✔ dans {where}{os.sep}"
                for job in group:
                    set_state(job, State.EXTRACTED, detail)
            else:
                failures.append(f"{name} : code {code}")
                for job in group:
                    set_state(job, State.EXTRACT_FAILED, f"Échec extraction (code {code})")
        message = ("Analyse OK, " if scan else "") + f"extraction : {ok}/{len(todo)} archive(s) extraite(s)."
        if failures:
            message += f" Problème — {failures[0]}" + (f" (+{len(failures) - 1})" if len(failures) > 1 else "")
        status(message, done=True, kind="ok" if ok == len(todo) else "warn" if ok else "error")

    def _show_report(self):
        if not self.last_report:
            self._status("Aucune analyse VirusTotal pour l'instant.")
            return
        c, px = self.theme.c, self.theme.px
        win = tk.Toplevel(self.root)
        win.title("Rapport VirusTotal")
        win.geometry(f"{px(1000)}x{px(640)}")
        self.theme.decorate(win)
        card = ttk.Frame(win, style="Card.TFrame", padding=px(6))
        card.pack(fill="both", expand=True, padx=px(16), pady=px(16))
        card.columnconfigure(0, weight=1)
        card.rowconfigure(0, weight=1)
        text = tk.Text(card, font=self.theme.font_mono, wrap="none", background=c["card"], foreground=c["text"],
                       selectbackground=c["accent_soft"], selectforeground=c["text"], insertbackground=c["text"],
                       relief="flat", borderwidth=0, highlightthickness=0, padx=px(10), pady=px(8))
        ys = ttk.Scrollbar(card, orient="vertical", command=text.yview)
        xs = ttk.Scrollbar(card, orient="horizontal", command=text.xview)
        text.configure(yscrollcommand=ys.set, xscrollcommand=xs.set)
        text.grid(row=0, column=0, sticky="nsew")
        ys.grid(row=0, column=1, sticky="ns")
        xs.grid(row=1, column=0, sticky="ew")
        text.insert("1.0", self.last_report.render_text())
        text.configure(state="disabled")

    def _api_key_dialog(self):
        """Saisie, test et enregistrement (chiffré) de la clé API VirusTotal."""
        from vtzip.config import resolve_api_key, store_api_key

        if getattr(self, "key_window", None) and self.key_window.winfo_exists():
            self.key_window.lift()
            return
        px = self.theme.px
        self.key_window = win = tk.Toplevel(self.root)
        win.title("Clé API VirusTotal")
        win.transient(self.root)
        win.resizable(False, False)
        self.theme.decorate(win)
        card = ttk.Frame(win, style="Card.TFrame", padding=(px(20), px(16), px(20), px(18)))
        card.pack(fill="both", expand=True, padx=px(16), pady=px(16))
        card.columnconfigure(0, weight=1)
        ttk.Label(card, text="CLÉ API VIRUSTOTAL", style="Caption.TLabel").grid(row=0, column=0, sticky="w")
        key_var = tk.StringVar(value=resolve_api_key() or "")
        entry = ttk.Entry(card, textvariable=key_var, show="•", width=72)
        entry.grid(row=1, column=0, sticky="ew", pady=(px(6), px(10)))
        show_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(card, text="Afficher la clé", variable=show_var, style="Switch.TCheckbutton",
                        command=lambda: entry.configure(show="" if show_var.get() else "•")).grid(
            row=2, column=0, sticky="w")
        info = tk.StringVar(value="Clé gratuite : virustotal.com, menu de ton profil > API key. "
                                  "Elle est enregistrée chiffrée, lisible seulement par ton compte Windows.")
        ttk.Label(card, textvariable=info, style="SurfaceMuted.TLabel", wraplength=px(560), justify="left").grid(
            row=3, column=0, sticky="w", pady=(px(12), px(16)))
        buttons = ttk.Frame(card, style="Surface.TFrame")
        buttons.grid(row=4, column=0, sticky="e")

        def valid():
            key = key_var.get().strip()
            if len(key) != 64 or not key.isalnum():
                info.set("Une clé VirusTotal fait 64 caractères (chiffres et lettres).")
                return None
            return key

        def test():
            key = valid()
            if not key:
                return
            info.set("Test en cours…")
            test_btn.state(["disabled"])

            def run():
                from vtzip.vt import VirusTotalClient, VTError
                try:
                    VirusTotalClient(key, rpm=0, timeout=20).lookup_hash(EICAR_SHA256)
                    message = "Clé valide ✔"
                except VTError as e:
                    message = f"Échec : {e}"

                def show():
                    if win.winfo_exists():
                        info.set(message)
                        test_btn.state(["!disabled"])
                self.calls.put(show)
            threading.Thread(target=run, daemon=True).start()

        def save(_event=None):
            key = valid()
            if not key:
                return
            store_api_key(key)
            win.destroy()
            self._status("Clé VirusTotal enregistrée.", "ok")

        ttk.Button(buttons, text="Obtenir une clé", command=lambda: os.startfile(VT_KEY_URL)).pack(side="left")
        test_btn = ttk.Button(buttons, text="Tester", command=test)
        test_btn.pack(side="left", padx=(px(8), 0))
        ttk.Button(buttons, text="Enregistrer", style="Accent.TButton", command=save).pack(side="left", padx=(px(8), 0))
        entry.bind("<Return>", save)
        win.bind("<Escape>", lambda e: win.destroy())
        entry.focus_set()

    def _on_close(self):
        active = [j for j in self.jobs.values() if j.state in ACTIVE]
        if active or self.busy:
            lines = []
            if active:
                lines.append(f"{plural(len(active), 'téléchargement')} en cours ou en attente : "
                             "ils seront mis en pause et pourront reprendre au prochain lancement.")
            if self.busy:
                lines.append("L'analyse ou l'extraction en cours sera interrompue.")
            if not messagebox.askyesno("Quitter Haul ?", "\n\n".join(lines) + "\n\nQuitter Haul ?",
                                       icon="warning", default="no", parent=self.root):
                return
        self._save_config()
        self.engine.shutdown()
        self._save_queue()
        if self.server:
            self.server.shutdown()
        self.notifier.remove()
        self.taskbar.set(notify.TaskbarProgress.NONE)
        for timer in (*self.timers.values(), self.notification_timer):
            if timer:
                self.root.after_cancel(timer)
        self.root.destroy()
