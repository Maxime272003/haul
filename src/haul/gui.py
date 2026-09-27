"""Fenêtre principale (Tkinter)."""

import logging
import os
import queue
import subprocess
import threading
import tkinter as tk
from tkinter import filedialog, ttk

from . import __version__, clipboard, config, postprocess
from .engine import DOWNLOADED, Engine, Job
from .links import FILE_HINT_RE, LINK_RE, human_size, name_from_url, page_key
from .paths import ICON_PATH
from .server import PORT, USERSCRIPT_URL, LinkServer
from .theme import Theme
from .widgets import CellTooltip, Flow, Stepper

log = logging.getLogger(__name__)

HINT = "Sélectionne les liens fuckingfast.co sur la page web et fais Ctrl+C."
STATUS_DOTS = {"info": "faint", "ok": "green", "warn": "amber", "error": "red"}


def status_kind(status):
    """Famille d'un statut de fichier : wait, browser, busy, download, done ou error."""
    if status.startswith(("Erreur", "Échec", "Extraction bloquée")):
        return "error"
    if status in DOWNLOADED or status.startswith("Extrait"):
        return "done"
    if status.startswith("Téléchargement"):
        return "download"
    if status.startswith("Dans le navigateur"):
        return "browser"
    if status.startswith(("Extraction", "Connexion")):
        return "busy"
    return "wait"


def plural(n, word, plural_word=None):
    return f"{n} {word if n < 2 else plural_word or word + 's'}"


class App:
    def __init__(self, root):
        self.root = root
        self.cfg = config.load()
        self.events = queue.Queue()    # (job.id, {champ: valeur}) ou (None, {"message": …, "done": bool, "kind": …})
        self.incoming = queue.Queue()  # liens reçus pour des pages ouvertes à la main dans le navigateur
        self.engine = Engine(self.events, lambda *link: self.incoming.put(link))
        self.engine.set_parallel(self.cfg["parallel"])
        self.engine.set_connections(self.cfg["connections"])
        self.jobs = {}
        self.seen = set()
        self.next_id = 1
        self.busy = False       # analyse / extraction en cours
        self.processed = set()  # fichiers déjà passés par l'analyse + extraction automatiques
        self.last_report = None
        self.tick = 0           # animation des icônes « en cours »

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
        self.last_seq = clipboard.sequence()
        root.after(700, self._poll_clipboard)
        root.after(200, self._drain_events)
        root.protocol("WM_DELETE_WINDOW", self._on_close)
        try:
            self.server = LinkServer(self.engine)
            threading.Thread(target=self.server.serve_forever, daemon=True).start()
        except OSError:
            self.server = None
            self._status(f"Port {PORT} occupé : Haul est peut-être déjà lancé.", "warn")

    # --- configuration ---

    def _save_config(self):
        self.cfg.update(folder=self.folder_var.get(), parallel=self._spin_value(self.parallel_var, 1, 6),
                        connections=self._spin_value(self.conn_var, 1, 16), watch=self.watch_var.get(),
                        scan=self.scan_var.get(), extract=self.extract_var.get())
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
        self.scan_var = tk.BooleanVar(value=self.cfg["scan"])
        self.extract_var = tk.BooleanVar(value=self.cfg["extract"])

        def switch(text, var):
            return ttk.Checkbutton(opts, text=text, variable=var, style="Switch.TCheckbutton",
                                   command=self._save_config)

        def stepper(text, var, hi):
            box = ttk.Frame(opts, style="Surface.TFrame")
            ttk.Label(box, text=text, style="Surface.TLabel").pack(side="left", padx=(0, px(10)))
            Stepper(box, var, 1, hi, command=self._settings_changed, style="Surface.TFrame").pack(side="left")
            return box

        opts.add(switch("Surveiller le presse-papier", self.watch_var),
                 stepper("Fichiers simultanés", self.parallel_var, 6),
                 stepper("Connexions par fichier", self.conn_var, 16),
                 switch("Analyser avec VirusTotal", self.scan_var),
                 switch("Puis extraire avec WinRAR", self.extract_var))
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

        self.empty = ttk.Frame(card, style="Surface.TFrame")
        ttk.Label(self.empty, text="Aucun téléchargement", style="EmptyTitle.TLabel").pack()
        ttk.Label(self.empty, text=HINT + "\nLes pages s'ouvrent dans ton navigateur, Haul télécharge le reste.",
                  style="SurfaceMuted.TLabel", justify="center").pack(pady=(px(6), 0))
        self.empty.place(relx=0.5, rely=0.5, anchor="center")
        return card

    def _text_width(self, text):
        if text not in self._text_widths:
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
            kind = {"error": "error", "done": "ok"}.get(status_kind(job.status), "info")
            vt = f" · VirusTotal : {job.vt}" if job.vt else ""
            self._status(f"{job.name or job.url} — {job.status}{vt}", kind)

    def _build_actions(self, parent):
        px = self.theme.px
        actions = Flow(parent, gap=px(8), row_gap=px(8))
        self.retry_btn = ttk.Button(actions, text="Réessayer les échecs", command=self._retry_failed)
        self.clear_btn = ttk.Button(actions, text="Retirer les terminés", command=self._clear_done)
        self.process_btn = ttk.Button(actions, text="Analyser / extraire maintenant",
                                      command=lambda: self._postprocess(manual=True))
        self.report_btn = ttk.Button(actions, text="Rapport VirusTotal", command=self._show_report)
        actions.add(self.retry_btn, self.clear_btn, self.process_btn, self.report_btn)
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
        m.add_command(label="Afficher dans l'Explorateur", command=lambda: self._reveal(job))
        m.add_command(label="Copier le lien de la page", command=lambda: self._copy_links(jobs))
        m.add_separator()
        failed = [j for j in jobs if j.status.startswith("Erreur")]
        m.add_command(label="Réessayer", command=lambda: self._retry(failed),
                      state="normal" if failed else "disabled")
        removable = [j for j in jobs if status_kind(j.status) in ("done", "error")]
        m.add_command(label="Retirer de la liste", command=lambda: self._remove(removable),
                      state="normal" if removable else "disabled")
        m.tk_popup(event.x_root, event.y_root)

    def _reveal(self, job):
        if not job:
            return
        if job.path and os.path.exists(job.path):
            subprocess.Popen(f'explorer /select,"{job.path}"')
        else:
            self._open_folder(job.dest)

    def _copy_links(self, jobs):
        self.root.clipboard_clear()
        self.root.clipboard_append("\n".join(j.url for j in jobs))
        self.root.update_idletasks()
        self.last_seq = clipboard.sequence()  # ne pas relire ce qu'on vient de copier
        self._status(f"{plural(len(jobs), 'lien copié', 'liens copiés')}.", "ok")

    def _remove(self, jobs):
        for job in jobs:
            if status_kind(job.status) not in ("done", "error"):
                continue  # encore géré par le moteur
            self.tree.delete(str(job.id))
            del self.jobs[job.id]
            self.seen.discard(page_key(job.url))  # pourra être ajouté de nouveau
            self.processed.discard(job.path)

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
        self.root.after(700, self._poll_clipboard)

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

    def _add_job(self, url, dl_url=None, user_agent=None):
        key = page_key(url)
        if key in self.seen:
            return False
        self.seen.add(key)
        job = Job(id=self.next_id, url=url, dest=self.folder_var.get(), name=name_from_url(url),
                  dl_url=dl_url, user_agent=user_agent)
        self.next_id += 1
        self.jobs[job.id] = job
        self.tree.insert("", "end", iid=str(job.id), **self._item(job))
        self.columns_dirty = True
        self.engine.submit(job)
        return True

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
        speed = f"{human_size(job.speed)}/s" if job.speed > 0 and job.status.startswith("Téléchargement") else ""
        return (job.status, progress, speed, job.vt)

    def _item(self, job):
        kind = status_kind(job.status)
        fraction = job.done / job.total if kind == "download" and job.total else None
        image = self.theme.status_icon(kind, fraction, self.tick)
        return {"text": job.name or job.url, "image": image, "values": self._row(job)}

    def _drain_events(self):
        while not self.incoming.empty():
            page_url, dl_url, user_agent = self.incoming.get()
            if self._add_job(page_url or dl_url, dl_url, user_agent):
                self._status("Lien reçu du navigateur.", "ok")
        try:
            while True:
                job_id, fields = self.events.get_nowait()
                if job_id is None:  # message de l'analyse / extraction
                    self.busy = not fields.get("done")
                    self._status(fields["message"], fields.get("kind") or ("busy" if self.busy else "ok"))
                    continue
                job = self.jobs.get(job_id)
                if not job:
                    continue
                for k, v in fields.items():
                    setattr(job, k, v)
                if "name" in fields or "status" in fields:
                    self.columns_dirty = True
                if self.tree.exists(str(job_id)):
                    self.tree.item(str(job_id), **self._item(job))
        except queue.Empty:
            pass
        self._refresh()
        if self.scan_var.get() or self.extract_var.get():
            self._postprocess()
        self.root.after(200, self._drain_events)

    def _refresh(self):
        """Animations, compteurs, débit total et boutons disponibles."""
        self.tick += 1
        kinds = {}
        for job in self.jobs.values():
            kind = status_kind(job.status)
            kinds[kind] = kinds.get(kind, 0) + 1
            if kind == "busy" or (kind == "download" and not job.total):
                self.tree.item(str(job.id), image=self.theme.status_icon(kind, frame=self.tick))
        if self.status_kind == "busy":
            self._refresh_status_icon()
        if self.columns_dirty:
            self._fit_columns()

        if self.jobs:
            self.empty.place_forget()
            parts = [plural(len(self.jobs), "fichier")]
            active = kinds.get("download", 0) + kinds.get("busy", 0) + kinds.get("browser", 0)
            for n, text in ((active, "en cours"), (kinds.get("wait", 0), "en attente"),
                            (kinds.get("done", 0), plural(kinds.get("done", 0), "terminé")[2:]),
                            (kinds.get("error", 0), plural(kinds.get("error", 0), "erreur")[2:])):
                if n:
                    parts.append(f"{n} {text}")
            self.summary_var.set("  ·  ".join(parts))
        else:
            self.empty.place(relx=0.5, rely=0.5, anchor="center")
            self.summary_var.set("")

        total = sum(j.speed for j in self.jobs.values() if j.status.startswith("Téléchargement"))
        self.total_var.set(f"↓ {human_size(total)}/s  ·  {total * 8 / 1e6:.0f} Mbit/s" if total else "")

        def enable(button, on):
            button.state(["!disabled"] if on else ["disabled"])
        enable(self.retry_btn, kinds.get("error", 0) and any(j.status.startswith("Erreur")
                                                               for j in self.jobs.values()))
        enable(self.clear_btn, kinds.get("done", 0))
        enable(self.process_btn, not self.busy and any(self._downloaded(j) for j in self.jobs.values()))
        enable(self.report_btn, self.last_report is not None)

    def _retry(self, jobs):
        for job in jobs:
            if job.status.startswith("Erreur"):
                job.status, job.speed = "En attente", 0
                self.tree.item(str(job.id), **self._item(job))
                self.engine.submit(job)

    def _retry_failed(self):
        self._retry(list(self.jobs.values()))

    def _clear_done(self):
        for job in list(self.jobs.values()):
            if job.status in DOWNLOADED or job.status.startswith("Extrait"):
                self.tree.delete(str(job.id))
                del self.jobs[job.id]

    # --- analyse VirusTotal puis extraction ---

    @staticmethod
    def _downloaded(job):
        return job.status in DOWNLOADED or job.status.startswith(("Extr", "Échec extraction"))

    def _postprocess(self, manual=False):
        """Analyse puis extrait les fichiers téléchargés.

        En automatique : seulement quand toute la liste est finie, et une seule fois par fichier.
        """
        if self.busy or not self.jobs:
            return
        if not manual and not all(self._downloaded(j) for j in self.jobs.values()):
            return  # téléchargements en cours, en attente ou en échec
        batch = [j for j in self.jobs.values() if self._downloaded(j) and j.path
                 and (not j.status.startswith("Extrait") if manual else j.path not in self.processed)]
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
        self.processed.update(j.path for j in batch)
        self.busy = True
        threading.Thread(target=self._postprocess_worker, args=(batch, scan, winrar), daemon=True).start()

    def _postprocess_worker(self, batch, scan, winrar):
        def put(job, **fields):
            self.events.put((job.id, fields))

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
                    put(job, vt="non analysé")
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
                            put(job, status="Extraction bloquée")
                more = f" (+{len(blocking) - 1})" if len(blocking) > 1 else ""
                return status(f"Extraction bloquée — {blocking[0]}{more}. Clique « Rapport VirusTotal ».",
                              done=True, kind="error")
            if not winrar:
                return status("Analyse VirusTotal terminée : rien de bloquant.", done=True)

        todo = postprocess.archive_sets(batch)
        if not todo:
            return status("Rien de bloquant, aucune archive .rar à extraire.", done=True)
        ok = 0
        for first, group in todo.items():
            for job in group:
                put(job, status="Extraction…")
            try:
                code = postprocess.extract(winrar, first)
            except OSError as e:
                log.exception("Extraction impossible")
                code = str(e)
            ok += code == 0
            for job in group:
                put(job, status="Extrait ✔" if code == 0 else f"Échec extraction (code {code})")
        status(("Analyse OK, " if scan else "") + f"extraction terminée : {ok}/{len(todo)} archive(s) extraite(s).",
               done=True, kind="ok" if ok == len(todo) else "warn")

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

    def _on_close(self):
        self._save_config()
        self.engine.shutdown()
        if self.server:
            self.server.shutdown()
        self.root.destroy()
