"""Reconnaissance des liens FuckingFast et petits utilitaires de noms de fichiers."""

import re
import urllib.parse

# Page d'un fichier : https://fuckingfast.co/<id>#<nom du fichier> (ou /f/<id>)
LINK_RE = re.compile(r"https?://(?:www\.)?fuckingfast\.co/(?!dl/)(?:f/)?[A-Za-z0-9_-]+(?:#[^\s\"'<>]*)?", re.I)
# Lien direct : dl.fuckingfast.co/... (site actuel) ou fuckingfast.co/dl/... (ancienne version)
DL_RE = re.compile(r"https?://(?:dl\.fuckingfast\.co/|(?:www\.)?fuckingfast\.co/dl/)[^\s\"'<>)\\]+", re.I)
# Texte qui ressemble à des noms de fichiers d'archive copiés sans leurs liens
FILE_HINT_RE = re.compile(r"\.(?:rar|zip|7z|bin)\b|fitgirl", re.I)
# Volume d'une archive en plusieurs parties : Jeu.part01.rar
VOLUME_RE = re.compile(r"\.part(\d+)\.rar$", re.I)
# Signature d'un site en fin de nom : « Jeu_--_fitgirl-repacks.site_--_ »
SITE_TAG_RE = re.compile(r"[\s_.-]*--[\s_.-]*[\w.-]+\.(?:site|com|org|net|info)[\s_.-]*(?:--[\s_.-]*)?$", re.I)
# Noms de périphériques : Windows refuse ces noms de fichier, même suivis d'une extension (CON.rar)
RESERVED_NAMES = frozenset({"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(10)),
                            *(f"LPT{i}" for i in range(10))})


def human_size(n):
    if n is None:
        return "?"
    for unit in ("o", "Ko", "Mo", "Go"):
        if n < 1024 or unit == "Go":
            return f"{n:.0f} {unit}" if unit == "o" else f"{n:.1f} {unit}"
        n /= 1024


def duration(seconds):
    """Durée courte et lisible : « 45 s », « 12 min », « 2 h 05 »."""
    seconds = max(0, round(seconds))
    if seconds < 60:
        return f"{seconds} s"
    minutes = round(seconds / 60)
    if minutes < 60:
        return f"{minutes} min"
    hours, minutes = divmod(minutes, 60)
    return f"{hours} h {minutes:02d}"


def safe_name(name):
    """Nom de fichier Windows valide, ou None."""
    name = re.sub(r'[<>:"/\\|?*\x00-\x1f]', "_", name).strip(" .")
    if name.split(".", 1)[0].strip().upper() in RESERVED_NAMES:
        name = "_" + name
    return name[:200] or None


def archive_base(name):
    """Nom commun aux volumes d'une archive .rar (« Jeu » pour Jeu.part01.rar et Jeu.rar), sinon None."""
    if not name or not name.lower().endswith(".rar"):
        return None
    m = VOLUME_RE.search(name)
    return name[:m.start()] if m else name[:-4]


def folder_name(name):
    """Dossier propre à un jeu, d'après le nom de son archive (« Elden Ring » pour
    Elden_Ring_--_fitgirl-repacks.site_--_.part01.rar), ou None si ce n'est pas une archive."""
    base = archive_base(name)
    if not base:
        return None
    pretty = SITE_TAG_RE.sub("", base).replace("_", " ")
    return safe_name(re.sub(r"\s+", " ", pretty).strip(" .-")) or safe_name(base)


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
