"""Fenêtre principale (Tkinter)."""

import logging
import os
import queue
import threading
import tkinter as tk
from tkinter import filedialog, ttk
from tkinter.scrolledtext import ScrolledText

from . import __version__, clipboard, config, postprocess
from .engine import DOWNLOADED, Engine, Job
from .links import FILE_HINT_RE, LINK_RE, human_size, name_from_url, page_key
from .paths import ICON_PATH
from .server import PORT, USERSCRIPT_URL, LinkServer

log = logging.getLogger(__name__)


class App:
    def __init__(self, root):
        self.root = root
        self.cfg = config.load()
        self.events = queue.Queue()    # (job.id, {champ: valeur}) ou (None, {"message": …, "done": bool})
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

        root.title(f"Haul {__version__}")
        if ICON_PATH.exists():
            root.iconbitmap(default=str(ICON_PATH))
        root.geometry("1050x480")
        root.minsize(640, 320)
        self._build()
        self.last_seq = clipboard.sequence()
        root.after(700, self._poll_clipboard)
        root.after(200, self._drain_events)
        root.protocol("WM_DELETE_WINDOW", self._on_close)
        try:
            self.server = LinkServer(self.engine)
            threading.Thread(target=self.server.serve_forever, daemon=True).start()
        except OSError:
            self.server = None
            self.status_var.set(f"Port {PORT} occupé : Haul est peut-être déjà lancé.")

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
        pad = {"padx": 6, "pady": 4}
        top = ttk.Frame(self.root)
        top.pack(fill="x", **pad)
        ttk.Label(top, text="Dossier :").pack(side="left")
        self.folder_var = tk.StringVar(value=self.cfg["folder"])
        ttk.Entry(top, textvariable=self.folder_var).pack(side="left", fill="x", expand=True, padx=4)
        ttk.Button(top, text="Parcourir…", command=self._choose_folder).pack(side="left")
        ttk.Button(top, text="Ouvrir", command=self._open_folder).pack(side="left", padx=(4, 0))

        opts = ttk.Frame(self.root)
        opts.pack(fill="x", **pad)
        self.watch_var = tk.BooleanVar(value=self.cfg["watch"])
        ttk.Checkbutton(opts, text="Surveiller le presse-papier", variable=self.watch_var,
                        command=self._save_config).pack(side="left")
        ttk.Label(opts, text="   Fichiers simultanés :").pack(side="left")
        self.parallel_var = tk.StringVar(value=str(self.cfg["parallel"]))
        ttk.Spinbox(opts, from_=1, to=6, width=3, textvariable=self.parallel_var,
                    command=self._settings_changed).pack(side="left", padx=4)
        ttk.Label(opts, text="   Connexions par fichier :").pack(side="left")
        self.conn_var = tk.StringVar(value=str(self.cfg["connections"]))
        ttk.Spinbox(opts, from_=1, to=16, width=3, textvariable=self.conn_var,
                    command=self._settings_changed).pack(side="left", padx=4)
        self.scan_var = tk.BooleanVar(value=self.cfg["scan"])
        ttk.Checkbutton(opts, text="Analyser (VirusTotal)", variable=self.scan_var,
                        command=self._save_config).pack(side="left", padx=(12, 0))
        self.extract_var = tk.BooleanVar(value=self.cfg["extract"])
        ttk.Checkbutton(opts, text="puis extraire (WinRAR)", variable=self.extract_var,
                        command=self._save_config).pack(side="left", padx=(6, 0))
        ttk.Button(opts, text="Ajouter depuis le presse-papier",
                   command=self._add_from_clipboard).pack(side="right")

        cols = ("name", "status", "progress", "speed", "vt")
        self.tree = ttk.Treeview(self.root, columns=cols, show="headings")
        for col, text, width, stretch in (("name", "Fichier", 340, True), ("status", "Statut", 220, True),
                                          ("progress", "Progression", 170, False), ("speed", "Vitesse", 80, False),
                                          ("vt", "VirusTotal", 150, False)):
            self.tree.heading(col, text=text)
            self.tree.column(col, width=width, stretch=stretch)
        self.tree.pack(fill="both", expand=True, **pad)

        bottom = ttk.Frame(self.root)
        bottom.pack(fill="x", **pad)
        ttk.Button(bottom, text="Réessayer les échecs", command=self._retry_failed).pack(side="left")
        ttk.Button(bottom, text="Retirer les terminés", command=self._clear_done).pack(side="left", padx=4)
        ttk.Button(bottom, text="Analyser / extraire maintenant",
                   command=lambda: self._postprocess(manual=True)).pack(side="left")
        ttk.Button(bottom, text="Rapport VirusTotal", command=self._show_report).pack(side="left", padx=4)
        ttk.Button(bottom, text="Installer le script navigateur",
                   command=lambda: os.startfile(USERSCRIPT_URL)).pack(side="left")
        self.total_var = tk.StringVar()
        ttk.Label(bottom, textvariable=self.total_var, font=("Segoe UI", 9, "bold")).pack(side="right", padx=(8, 0))
        self.status_var = tk.StringVar(value="Sélectionne les liens fuckingfast.co sur la page web et fais Ctrl+C.")
        ttk.Label(bottom, textvariable=self.status_var, foreground="#555").pack(side="right")

    def _choose_folder(self):
        folder = filedialog.askdirectory(initialdir=self.folder_var.get() or os.path.expanduser("~"))
        if folder:
            self.folder_var.set(os.path.normpath(folder))
            self._save_config()

    def _open_folder(self):
        folder = self.folder_var.get()
        os.makedirs(folder, exist_ok=True)
        os.startfile(folder)

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

    def _add_from_clipboard(self, quiet=False):
        text, html_text = self._read_clipboard()
        if self._add_links(text + "\n" + html_text):
            return
        if FILE_HINT_RE.search(text):
            self.status_var.set("Noms de fichiers sans liens : copie-les depuis la page web, "
                                "pas depuis un fichier texte.")
        elif not quiet:
            self.status_var.set("Aucun lien fuckingfast.co dans le presse-papier.")

    def _add_links(self, text):
        added = sum(self._add_job(m.group(0)) for m in LINK_RE.finditer(text or ""))
        if added:
            self.status_var.set(f"{added} lien(s) ajouté(s).")
        return added

    def _add_job(self, url, dl_url=None, user_agent=None):
        key = page_key(url)
        if key in self.seen:
            return False
        self.seen.add(key)
        job = Job(id=self.next_id, url=url, dest=self.folder_var.get(), name=name_from_url(url),
                  dl_url=dl_url, user_agent=user_agent)
        self.next_id += 1
        self.jobs[job.id] = job
        self.tree.insert("", "end", iid=str(job.id), values=self._row(job))
        self.engine.submit(job)
        return True

    # --- suivi des téléchargements ---

    @staticmethod
    def _row(job):
        if job.total:
            progress = f"{human_size(job.done)} / {human_size(job.total)} ({job.done * 100 // job.total}%)"
        elif job.done:
            progress = human_size(job.done)
        else:
            progress = ""
        speed = f"{human_size(job.speed)}/s" if job.speed > 0 else ""
        return (job.name or job.url, job.status, progress, speed, job.vt)

    def _drain_events(self):
        while not self.incoming.empty():
            page_url, dl_url, user_agent = self.incoming.get()
            if self._add_job(page_url or dl_url, dl_url, user_agent):
                self.status_var.set("Lien reçu du navigateur.")
        try:
            while True:
                job_id, fields = self.events.get_nowait()
                if job_id is None:  # message de l'analyse / extraction
                    self.busy = not fields.get("done")
                    self.status_var.set(fields["message"])
                    continue
                job = self.jobs.get(job_id)
                if not job:
                    continue
                for k, v in fields.items():
                    setattr(job, k, v)
                if self.tree.exists(str(job_id)):
                    self.tree.item(str(job_id), values=self._row(job))
        except queue.Empty:
            pass
        total = sum(j.speed for j in self.jobs.values() if j.status.startswith("Téléchargement"))
        self.total_var.set(f"Total : {human_size(total)}/s ({total * 8 / 1e6:.0f} Mbit/s)" if total else "")
        if self.scan_var.get() or self.extract_var.get():
            self._postprocess()
        self.root.after(200, self._drain_events)

    def _retry_failed(self):
        for job in self.jobs.values():
            if job.status.startswith("Erreur"):
                job.status, job.speed = "En attente", 0
                self.tree.item(str(job.id), values=self._row(job))
                self.engine.submit(job)

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
                self.status_var.set("Rien à traiter : aucun fichier téléchargé en attente.")
            return
        scan, extract = self.scan_var.get(), self.extract_var.get() or manual
        winrar = postprocess.find_winrar() if extract else None
        if extract and not winrar:
            self.status_var.set("WinRAR introuvable : extraction impossible.")
            self.extract_var.set(False)
        if not scan and not winrar:
            return
        self.processed.update(j.path for j in batch)
        self.busy = True
        threading.Thread(target=self._postprocess_worker, args=(batch, scan, winrar), daemon=True).start()

    def _postprocess_worker(self, batch, scan, winrar):
        def put(job, **fields):
            self.events.put((job.id, fields))

        def status(message, done=False):
            self.events.put((None, {"message": message, "done": done}))

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
                return status(f"Analyse VirusTotal impossible : {e}. Extraction non lancée.", done=True)
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
                return status(f"⚠ Extraction bloquée — {blocking[0]}{more}. Clique « Rapport VirusTotal ».",
                              done=True)
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
               done=True)

    def _show_report(self):
        if not self.last_report:
            self.status_var.set("Aucune analyse VirusTotal pour l'instant.")
            return
        win = tk.Toplevel(self.root)
        win.title("Rapport VirusTotal")
        win.geometry("980x600")
        text = ScrolledText(win, font=("Consolas", 10), wrap="none")
        text.pack(fill="both", expand=True)
        text.insert("1.0", self.last_report.render_text())
        text.configure(state="disabled")

    def _on_close(self):
        self._save_config()
        self.engine.shutdown()
        if self.server:
            self.server.shutdown()
        self.root.destroy()
