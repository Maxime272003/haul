"""Point d'entrée : `python -m haul`, commande `haul` ou Haul.exe.

Options : --minimized démarre réduit dans la zone de notification (lancement avec Windows) ;
--wait-pid N attend la fin de l'ancienne instance (relance après une mise à jour).
"""

import logging
import sys
import threading
import tkinter as tk
from logging.handlers import RotatingFileHandler

from haul.paths import DATA_DIR, LOG_PATH

log = logging.getLogger("haul")

LOG_SIZE = 5 << 20  # haul.log tourne sur 3 fichiers de 5 Mo


def setup_logging():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    handler = RotatingFileHandler(LOG_PATH, maxBytes=LOG_SIZE, backupCount=3, encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s"))
    root = logging.getLogger()
    root.addHandler(handler)
    root.setLevel(logging.INFO)
    # Sans console (Haul.exe, pythonw), une exception non rattrapée n'irait nulle part.
    sys.excepthook = lambda *exc: log.critical("Exception non rattrapée", exc_info=exc)
    threading.excepthook = lambda args: log.critical(
        "Exception non rattrapée dans le thread %s", args.thread.name if args.thread else "?",
        exc_info=(args.exc_type, args.exc_value, args.exc_traceback))


def main():
    setup_logging()
    from haul import config, desktop, updater
    from haul.server import show_running_instance

    args = sys.argv[1:]
    if updater.WAIT_PID_ARG in args:
        try:
            desktop.wait_process(int(args[args.index(updater.WAIT_PID_ARG) + 1]))
        except (IndexError, ValueError):
            pass
    exe = updater.current_exe()
    if exe:
        updater.cleanup(exe)
    instance = desktop.single_instance()
    if not instance:
        # Haul tourne déjà : on l'affiche au lieu d'en lancer un 2e (presse-papier surveillé deux fois,
        # pages ouvertes sans serveur pour recevoir les liens).
        desktop.allow_foreground()
        if show_running_instance(config.load()["token"]):
            return
        from tkinter import messagebox
        root = tk.Tk()
        root.withdraw()
        messagebox.showinfo("Haul", "Haul est déjà lancé (voir la zone de notification).", parent=root)
        root.destroy()
        return
    try:
        from ctypes import windll
        windll.shcore.SetProcessDpiAwareness(1)
    except (ImportError, AttributeError, OSError):
        pass
    from haul.gui import App
    root = tk.Tk()
    App(root, minimized=desktop.MINIMIZED_ARG in args)
    root.mainloop()


if __name__ == "__main__":
    main()
