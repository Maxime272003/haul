"""Reconnaissance des liens FuckingFast et petits utilitaires de noms de fichiers."""

import re
import urllib.parse

# Page d'un fichier : https://fuckingfast.co/<id>#<nom du fichier> (ou /f/<id>)
LINK_RE = re.compile(r"https?://(?:www\.)?fuckingfast\.co/(?!dl/)(?:f/)?[A-Za-z0-9_-]+(?:#[^\s\"'<>]*)?", re.I)
# Lien direct : dl.fuckingfast.co/... (site actuel) ou fuckingfast.co/dl/... (ancienne version)
DL_RE = re.compile(r"https?://(?:dl\.fuckingfast\.co/|(?:www\.)?fuckingfast\.co/dl/)[^\s\"'<>)\\]+", re.I)
# Texte qui ressemble à des noms de fichiers d'archive copiés sans leurs liens
FILE_HINT_RE = re.compile(r"\.(?:rar|zip|7z|bin)\b|fitgirl", re.I)


def human_size(n):
    if n is None:
        return "?"
    for unit in ("o", "Ko", "Mo", "Go"):
        if n < 1024 or unit == "Go":
            return f"{n:.0f} {unit}" if unit == "o" else f"{n:.1f} {unit}"
        n /= 1024


def safe_name(name):
    """Nom de fichier Windows valide, ou None."""
    name = re.sub(r'[<>:"/\\|?*\x00-\x1f]', "_", name).strip(" .")
    return name[:200] or None


def name_from_url(url):
    """Le nom du fichier est dans le fragment : fuckingfast.co/abc#Jeu.part01.rar."""
    if "#" in url:
        return safe_name(urllib.parse.unquote(url.split("#", 1)[1]))
    return None


def is_page_url(url):
    """Vraie page FuckingFast, seule chose que l'application accepte d'ouvrir dans le navigateur.

    Tout le reste (chemin local, partage réseau, autre protocole…) serait lancé par Windows.
    """
    return isinstance(url, str) and LINK_RE.fullmatch(url) is not None


def page_key(url):
    """Identifiant d'une page FuckingFast, sans le #nom, le www ni le préfixe /f/."""
    parts = urllib.parse.urlsplit(url)
    path = parts.path.rstrip("/")
    return parts.netloc.lower().removeprefix("www.") + (path[2:] if path.startswith("/f/") else path)
