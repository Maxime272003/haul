"""Mises à jour : dernière release GitHub, téléchargement vérifié, remplacement de Haul.exe.

La CI publie une release à chaque fusion sur main (Haul.exe + Haul.exe.sha256). L'application
compare sa version à la dernière, télécharge le nouvel exécutable à côté de l'actuel
(Haul.exe.new, empreinte SHA-256 vérifiée), puis l'installe en quittant : Windows refuse d'écraser
un exécutable en cours d'exécution mais accepte de le renommer (Haul.exe.old, supprimé au
lancement suivant).
"""

import hashlib
import logging
import os
import re
import subprocess
import sys

log = logging.getLogger(__name__)

REPO = "Maxime272003/haul"
LATEST_URL = f"https://api.github.com/repos/{REPO}/releases/latest"
RELEASES_PAGE = f"https://github.com/{REPO}/releases/latest"
DOWNLOAD_PREFIX = f"https://github.com/{REPO}/releases/download/"
ASSET = "Haul.exe"
CHECKSUM = ASSET + ".sha256"
TIMEOUT = (15, 60)
MAX_SIZE = 512 << 20  # un exécutable plus gros n'est pas le nôtre
WAIT_PID_ARG = "--wait-pid"  # relancé après une mise à jour : attendre la fin de l'ancien processus

VERSION_RE = re.compile(r"v?(\d+)\.(\d+)\.(\d+)")
SHA256_RE = re.compile(r"[0-9a-fA-F]{64}")


class UpdateError(Exception):
    pass


def parse_version(text):
    """(majeure, mineure, correctif) de « v1.2.3 » / « 1.2.3 », ou None."""
    m = VERSION_RE.fullmatch((text or "").strip())
    return tuple(int(p) for p in m.groups()) if m else None


def version_text(version):
    return ".".join(str(p) for p in version)


def next_version(base, tags):
    """Version de la prochaine release : la version du code si elle est plus récente que toutes les
    releases (montée de version à la main), sinon la dernière release + 1 sur le correctif."""
    base_v = parse_version(base)
    if base_v is None:
        raise ValueError(f"version invalide : {base!r}")
    released = [v for v in (parse_version(t) for t in tags) if v]
    latest = max(released, default=None)
    if latest is None or base_v > latest:
        return version_text(base_v)
    return version_text((latest[0], latest[1], latest[2] + 1))


def is_newer(version, current):
    v, c = parse_version(version), parse_version(current)
    return v is not None and c is not None and v > c


def _session(current):
    import requests
    s = requests.Session()
    s.headers["User-Agent"] = f"Haul/{current}"
    return s


def latest_release(current):
    """{"version", "url", "sha256_url", "page", "notes"} de la dernière release si elle est plus récente
    que `current` et contient Haul.exe, sinon None."""
    with _session(current) as s:
        r = s.get(LATEST_URL, headers={"Accept": "application/vnd.github+json"}, timeout=TIMEOUT)
        if r.status_code == 404:
            return None  # aucune release publiée
        r.raise_for_status()
        data = r.json()
    version = data.get("tag_name", "")
    if not is_newer(version, current):
        return None
    assets = {a.get("name"): a for a in data.get("assets", []) if isinstance(a, dict)}
    exe, checksum = assets.get(ASSET), assets.get(CHECKSUM)
    if not exe or not checksum:
        log.warning("Release %s sans %s ou %s", version, ASSET, CHECKSUM)
        return None
    urls = exe.get("browser_download_url", ""), checksum.get("browser_download_url", "")
    if not all(u.startswith(DOWNLOAD_PREFIX) for u in urls):  # jamais un autre site
        raise UpdateError("adresse de téléchargement inattendue")
    return {"version": version_text(parse_version(version)), "url": urls[0], "sha256_url": urls[1],
            "size": exe.get("size"), "page": data.get("html_url") or RELEASES_PAGE, "notes": data.get("body") or ""}


def parse_checksum(text):
    m = SHA256_RE.search(text or "")
    if not m:
        raise UpdateError("empreinte SHA-256 illisible")
    return m.group(0).lower()


def download(release, current, exe_path, on_progress=lambda done, total: None):
    """Télécharge le nouvel exécutable à côté de `exe_path` et vérifie son empreinte ; retourne son chemin."""
    target = exe_path + ".new"
    partial = exe_path + ".download"
    with _session(current) as s:
        r = s.get(release["sha256_url"], timeout=TIMEOUT)
        r.raise_for_status()
        expected = parse_checksum(r.text)
        digest, done = hashlib.sha256(), 0
        with s.get(release["url"], stream=True, timeout=TIMEOUT) as r:
            r.raise_for_status()
            total = int(r.headers.get("Content-Length") or release.get("size") or 0) or None
            if total and total > MAX_SIZE:
                raise UpdateError("fichier trop gros")
            with open(partial, "wb") as f:
                for chunk in r.iter_content(1 << 16):
                    done += len(chunk)
                    if done > MAX_SIZE:
                        raise UpdateError("fichier trop gros")
                    digest.update(chunk)
                    f.write(chunk)
                    on_progress(done, total)
    if digest.hexdigest() != expected:
        os.remove(partial)
        raise UpdateError("empreinte SHA-256 différente : téléchargement corrompu")
    os.replace(partial, target)
    return target


def install(new_path, exe_path):
    """Remplace l'exécutable en cours par `new_path` (l'ancien devient .old, supprimé au prochain lancement)."""
    old = exe_path + ".old"
    try:
        os.remove(old)
    except FileNotFoundError:
        pass
    os.replace(exe_path, old)
    try:
        os.replace(new_path, exe_path)
    except OSError:
        os.replace(old, exe_path)  # rien ne doit rester sans exécutable
        raise


def cleanup(exe_path):
    """Restes d'une mise à jour : ancien exécutable, téléchargement interrompu."""
    for suffix in (".old", ".download"):
        try:
            os.remove(exe_path + suffix)
        except FileNotFoundError:
            pass
        except OSError:
            log.debug("Impossible de supprimer %s", exe_path + suffix, exc_info=True)


def relaunch(exe_path):
    """Relance Haul, qui attendra la fin de ce processus avant de démarrer (instance unique)."""
    flags = getattr(subprocess, "DETACHED_PROCESS", 0) | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
    subprocess.Popen([exe_path, WAIT_PID_ARG, str(os.getpid())], close_fds=True, creationflags=flags)


def current_exe():
    """Chemin de Haul.exe s'il tourne en version autonome (PyInstaller), sinon None."""
    return sys.executable if getattr(sys, "frozen", False) else None
