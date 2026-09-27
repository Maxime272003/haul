"""Réglages persistants de l'application (JSON dans %APPDATA%\\Haul)."""

import json
import os

from .paths import CONFIG_PATH

DEFAULTS = {
    "folder": os.path.join(os.path.expanduser("~"), "Downloads", "Haul"),
    "parallel": 2,       # fichiers téléchargés en même temps
    "connections": 8,    # connexions par fichier
    "watch": True,       # surveiller le presse-papier
    "scan": True,        # analyse VirusTotal quand toute la liste est téléchargée
    "extract": True,     # puis extraction WinRAR
}


def load():
    cfg = dict(DEFAULTS)
    try:
        with open(CONFIG_PATH, encoding="utf-8") as f:
            data = json.load(f)
        cfg.update({k: v for k, v in data.items() if k in DEFAULTS})
    except (OSError, ValueError):
        pass
    return cfg


def save(cfg):
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp = CONFIG_PATH.with_suffix(".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2, ensure_ascii=False)
    tmp.replace(CONFIG_PATH)
