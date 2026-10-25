"""Fenêtres secondaires de l'application : ajout de liens, « Tout supprimer », clé VirusTotal, rapport."""

import os
import threading
import tkinter as tk
from tkinter import filedialog, ttk

from .engine import ACTIVE, ON_DISK, State

VT_KEY_URL = "https://www.virustotal.com/gui/my-apikey"
EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"  # connu de VirusTotal
LINK_FILE_TYPES = (("Pages et listes de liens", "*.html *.htm *.txt *.url"), ("Tous les fichiers", "*.*"))
MAX_LINK_FILE = 4 << 20  # un fichier de liens plus gros n'en est pas un


def plural(n, word, plural_word=None):
    return f"{n} {word if n < 2 else plural_word or word + 's'}"


def read_link_file(path):
    """Texte d'un fichier de liens (.txt, page .html enregistrée, raccourci .url), ou "" s'il n'en est pas un."""
    try:
        if os.path.getsize(path) > MAX_LINK_FILE:
            return ""
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.read()
    except OSError:
        return ""


def _window(app, attr, title):
    """Fenêtre unique (ramenée au premier plan si déjà ouverte) ; None si elle l'était."""
    existing = getattr(app, attr, None)
    if existing is not None and existing.winfo_exists():
        existing.lift()
        return None
    win = tk.Toplevel(app.root)
    setattr(app, attr, win)
    win.title(title)
    win.transient(app.root)
    win.resizable(False, False)
    app.theme.decorate(win)
    return win


def _card(app, win):
    px = app.theme.px
    card = ttk.Frame(win, style="Card.TFrame", padding=(px(20), px(16), px(20), px(18)))
    card.pack(fill="both", expand=True, padx=px(16), pady=px(16))
    return card


def _text(app, parent, **kw):
    c, px = app.theme.c, app.theme.px
    return tk.Text(parent, background=c["card"], foreground=c["text"], selectbackground=c["accent_soft"],
                   selectforeground=c["text"], insertbackground=c["text"], relief="flat", borderwidth=0,
                   highlightthickness=1, highlightbackground=c["border"], highlightcolor=c["accent"], padx=px(10),
                   pady=px(8), **kw)


def links_dialog(app):
    """Colle ou importe des liens à la main (surveillance du presse-papier désactivée, fichier .txt / .html)."""
    win = _window(app, "links_window", "Ajouter des liens")
    if not win:
        return
    px = app.theme.px
    win.resizable(True, True)
    card = _card(app, win)
    card.columnconfigure(0, weight=1)
    card.rowconfigure(2, weight=1)
    ttk.Label(card, text="LIENS FUCKINGFAST", style="Caption.TLabel").grid(row=0, column=0, sticky="w")
    ttk.Label(card, text="Colle des liens ou du texte qui en contient (un par ligne ou en vrac), ou importe une "
                         "page enregistrée. Tu peux aussi déposer des fichiers sur la fenêtre de Haul.",
              style="SurfaceMuted.TLabel", wraplength=px(560), justify="left").grid(
        row=1, column=0, sticky="w", pady=(px(4), px(10)))
    text = _text(app, card, font=app.theme.font, width=72, height=12, wrap="none", undo=True)
    text.grid(row=2, column=0, sticky="nsew")
    buttons = ttk.Frame(card, style="Surface.TFrame")
    buttons.grid(row=3, column=0, sticky="ew", pady=(px(14), 0))

    def import_file():
        paths = filedialog.askopenfilenames(parent=win, title="Importer des liens", filetypes=LINK_FILE_TYPES)
        for path in paths:
            text.insert("end", read_link_file(path) + "\n")

    def add(_event=None):
        content = text.get("1.0", "end")
        win.destroy()
        if not app._add_links(content):
            app._status("Aucun lien fuckingfast.co dans le texte.", "warn")
        return "break"

    ttk.Button(buttons, text="Importer un fichier…", command=import_file).pack(side="left")
    ttk.Button(buttons, text="Ajouter", style="Accent.TButton", command=add).pack(side="right")
    ttk.Button(buttons, text="Annuler", command=win.destroy).pack(side="right", padx=(0, px(8)))
    win.bind("<Escape>", lambda e: win.destroy())
    win.bind("<Control-Return>", add)
    text.focus_set()


def clear_all_dialog(app):
    """Confirmation de « Tout supprimer » : vide la liste, et au choix les téléchargements inachevés."""
    jobs = list(app.jobs.values())
    if not jobs:
        return
    win = _window(app, "clear_window", "Tout supprimer")
    if not win:
        return
    px = app.theme.px
    active = sum(j.state in ACTIVE for j in jobs)
    unfinished = sum(j.state not in ON_DISK for j in jobs)
    busy = sum(j.state in (State.CHECKING, State.EXTRACTING) for j in jobs)
    card = _card(app, win)
    ttk.Label(card, text=f"Vider la liste ({plural(len(jobs), 'fichier')}) ?", style="EmptyTitle.TLabel").pack(
        anchor="w")
    lines = []
    if active:
        lines.append("1 téléchargement en cours ou en attente sera arrêté." if active == 1
                     else f"{active} téléchargements en cours ou en attente seront arrêtés.")
    lines.append("Les fichiers terminés et extraits restent sur le disque.")
    if busy:
        lines.append(f"{plural(busy, 'fichier')} en cours d'analyse ou d'extraction reste dans la liste.")
    ttk.Label(card, text="\n".join(lines), style="SurfaceMuted.TLabel", justify="left",
              wraplength=px(480)).pack(anchor="w", pady=(px(8), px(12)))
    partial_var = tk.BooleanVar(value=False)
    if unfinished:
        ttk.Checkbutton(card, text="Supprimer aussi les téléchargements inachevés du disque (.part)",
                        variable=partial_var, style="Switch.TCheckbutton").pack(anchor="w", pady=(0, px(16)))
    buttons = ttk.Frame(card, style="Surface.TFrame")
    buttons.pack(anchor="e")

    def confirm(_event=None):
        win.destroy()
        app._clear_all(delete_partials=partial_var.get())

    ttk.Button(buttons, text="Annuler", command=win.destroy).pack(side="left")
    ttk.Button(buttons, text="Tout supprimer", style="Accent.TButton", command=confirm).pack(
        side="left", padx=(px(8), 0))
    win.bind("<Escape>", lambda e: win.destroy())
    win.bind("<Return>", confirm)
    win.focus_set()


def report_window(app):
    """Rapport détaillé de la dernière analyse VirusTotal."""
    c, px = app.theme.c, app.theme.px
    win = tk.Toplevel(app.root)
    win.title("Rapport VirusTotal")
    win.geometry(f"{px(1000)}x{px(640)}")
    app.theme.decorate(win)
    card = ttk.Frame(win, style="Card.TFrame", padding=px(6))
    card.pack(fill="both", expand=True, padx=px(16), pady=px(16))
    card.columnconfigure(0, weight=1)
    card.rowconfigure(0, weight=1)
    text = tk.Text(card, font=app.theme.font_mono, wrap="none", background=c["card"], foreground=c["text"],
                   selectbackground=c["accent_soft"], selectforeground=c["text"], insertbackground=c["text"],
                   relief="flat", borderwidth=0, highlightthickness=0, padx=px(10), pady=px(8))
    ys = ttk.Scrollbar(card, orient="vertical", command=text.yview)
    xs = ttk.Scrollbar(card, orient="horizontal", command=text.xview)
    text.configure(yscrollcommand=ys.set, xscrollcommand=xs.set)
    text.grid(row=0, column=0, sticky="nsew")
    ys.grid(row=0, column=1, sticky="ns")
    xs.grid(row=1, column=0, sticky="ew")
    text.insert("1.0", app.last_report.render_text())
    text.configure(state="disabled")


def api_key_dialog(app):
    """Saisie, test et enregistrement (chiffré) de la clé API VirusTotal."""
    from vtzip.config import resolve_api_key, store_api_key

    win = _window(app, "key_window", "Clé API VirusTotal")
    if not win:
        return
    px = app.theme.px
    card = _card(app, win)
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
            app.calls.put(show)
        threading.Thread(target=run, daemon=True).start()

    def save(_event=None):
        key = valid()
        if not key:
            return
        store_api_key(key)
        win.destroy()
        app._status("Clé VirusTotal enregistrée.", "ok")

    ttk.Button(buttons, text="Obtenir une clé", command=lambda: os.startfile(VT_KEY_URL)).pack(side="left")
    test_btn = ttk.Button(buttons, text="Tester", command=test)
    test_btn.pack(side="left", padx=(px(8), 0))
    ttk.Button(buttons, text="Enregistrer", style="Accent.TButton", command=save).pack(side="left", padx=(px(8), 0))
    entry.bind("<Return>", save)
    win.bind("<Escape>", lambda e: win.destroy())
    entry.focus_set()
