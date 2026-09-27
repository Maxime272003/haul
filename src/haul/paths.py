"""Emplacements des fichiers de l'application.

Les données (config, journal, rapports) vivent dans %APPDATA%\\Haul, jamais dans le dépôt ni
à côté du .exe. Les ressources embarquées (userscript, icône) sont dans le paquet, ou dans
sys._MEIPASS pour la version PyInstaller.
"""

import os
import sys
from pathlib import Path

FROZEN = getattr(sys, "frozen", False)

DATA_DIR = Path(os.environ.get("APPDATA") or Path.home() / ".config") / "Haul"
CONFIG_PATH = DATA_DIR / "config.json"
LOG_PATH = DATA_DIR / "haul.log"
REPORTS_DIR = DATA_DIR / "reports"

ASSETS_DIR = (Path(sys._MEIPASS) / "haul" / "assets") if FROZEN else Path(__file__).parent / "assets"
USERSCRIPT_PATH = ASSETS_DIR / "haul.user.js"
ICON_PATH = ASSETS_DIR / "haul.ico"
