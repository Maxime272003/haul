"""Réglages persistants de l'application (JSON dans %APPDATA%\\Haul)."""

import json
import os
import secrets

from .paths import CONFIG_PATH

DEFAULTS = {
    "folder": os.path.join(os.path.expanduser("~"), "Downloads", "Haul"),
    "parallel": 2,       # fichiers téléchargés en même temps
    "connections": 8,    # connexions par fichier
    "watch": True,       # surveiller le presse-papier
    "scan": True,        # analyse VirusTotal quand toute la liste est téléchargée
    "extract": True,     # puis extraction WinRAR
    "max_speed": 0,      # débit total maximal en Mo/s (0 = illimité)
    "notify": True,      # notifications Windows (captcha à valider, liste terminée…)
    "theme": "system",   # apparence : system (celle de Windows), light ou dark
    "token": "",         # secret partagé avec le userscript, généré au premier lancement
    "subfolders": True,  # un sous-dossier par jeu (nom de l'archive) dans le dossier de destination
    "delete_archives": False,  # archives envoyées à la corbeille après une extraction réussie
    "tray": True,        # icône dans la zone de notification ; réduire y range la fenêtre
    "script_version": "",  # dernière version du userscript qui s'est manifestée ("?" : avant la 3.3)
}


def load():
    cfg = dict(DEFAULTS)
    try:
        with open(CONFIG_PATH, encoding="utf-8") as f:
            data = json.load(f)
        cfg.update({k: v for k, v in data.items() if k in DEFAULTS and type(v) is type(DEFAULTS[k])})
    except (OSError, ValueError, AttributeError):
        pass
    if len(cfg["token"]) < 32:
        cfg["token"] = secrets.token_urlsafe(32)
        save(cfg)
    return cfg


def save(cfg):
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp = CONFIG_PATH.with_suffix(".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2, ensure_ascii=False)
    tmp.replace(CONFIG_PATH)
