"""File de téléchargements.

Les pages FuckingFast s'ouvrent une par une dans le navigateur habituel : le captcha validé une
fois vaut pour les liens suivants. Le userscript renvoie le lien direct (voir server.py), puis le
fichier est téléchargé hors navigateur, plusieurs fichiers en parallèle.
"""

import logging
import os
import queue
import threading
import time
import urllib.parse
from dataclasses import dataclass

from .downloader import Downloader, Refused
from .links import page_key, safe_name

log = logging.getLogger(__name__)

LINK_TIMEOUT = 600  # temps laissé pour valider le captcha dans le navigateur

# Statuts d'un fichier présent sur le disque
DOWNLOADED = ("Terminé", "Déjà présent")


@dataclass
class Job:
    id: int
    url: str
    dest: str
    name: str = None
    status: str = "En attente"
    done: int = 0
    total: int = None
    speed: float = 0.0
    dl_url: str = None
    user_agent: str = None
    vt: str = ""  # verdict VirusTotal affiché

    @property
    def path(self):
        return os.path.join(self.dest, self.name) if self.name else None


class Progress:
    """Limite la fréquence des mises à jour envoyées à l'interface et calcule la vitesse."""

    def __init__(self, emit, job, start=0):
        self.emit, self.job = emit, job
        self.t_last, self.b_last = time.monotonic(), start

    def update(self, done, total=None, force=False):
        now = time.monotonic()
        if not force and now - self.t_last < 0.5:
            return
        speed = (done - self.b_last) / max(now - self.t_last, 1e-6)
        self.t_last, self.b_last = now, done
        self.emit(self.job, done=done, total=total, speed=speed)


class Engine:
    """Ouvre les pages dans le navigateur, reçoit les liens du userscript, gère les téléchargements.

    Les changements d'état sont publiés dans `events` sous la forme (job.id, {champ: valeur}).
    """

    def __init__(self, events, on_unknown_link, open_page=os.startfile):
        self.events = events
        self.on_unknown_link = on_unknown_link  # lien reçu pour une page que l'app n'a pas ouverte
        self.open_page = open_page
        self.max_parallel = 2
        self.connections = 8
        self.downloaders = set()
        self._lock = threading.Lock()
        self._to_resolve = queue.Queue()
        self._waiting = {}  # page_key -> (job, threading.Event)
        self._dl_pending = []
        self._dl_active = 0
        threading.Thread(target=self._resolver, daemon=True).start()

    # --- API (thread de l'interface / serveur local) ---

    def submit(self, job):
        if job.dl_url:
            self._queue_download(job)
        else:
            self._to_resolve.put(job)

    def set_parallel(self, n):
        self.max_parallel = n
        self._pump()

    def set_connections(self, n):
        self.connections = n

    def is_waiting(self, page_url):
        with self._lock:
            return page_key(page_url) in self._waiting

    def link_found(self, page_url, dl_url, user_agent):
        """Retourne True si l'onglet peut être fermé (page ouverte par l'app)."""
        with self._lock:
            entry = self._waiting.get(page_key(page_url))
        if entry:
            job, event = entry
            job.dl_url, job.user_agent = dl_url, user_agent
            event.set()
            return True
        self.on_unknown_link(page_url, dl_url, user_agent)
        return False

    def shutdown(self):
        for d in list(self.downloaders):
            d.cancel()

    # --- interne ---

    def emit(self, job, **fields):
        self.events.put((job.id, fields))

    def _resolver(self):
        # Une page à la fois : le captcha validé une fois vaut pour les liens suivants.
        while True:
            job = self._to_resolve.get()
            try:
                if job.path and os.path.exists(job.path):
                    self.emit(job, status="Déjà présent")
                    continue
                key, event = page_key(job.url), threading.Event()
                with self._lock:
                    self._waiting[key] = (job, event)
                self.emit(job, status="Dans le navigateur : valide le captcha si demandé")
                self.open_page(job.url)
                received = event.wait(LINK_TIMEOUT)
                with self._lock:
                    self._waiting.pop(key, None)
                if not received:
                    self.emit(job, status="Erreur : aucun lien reçu du navigateur (userscript installé ?)")
                    continue
                log.info("Lien reçu pour %s : %s", job.url, job.dl_url)
                self._queue_download(job)
            except Exception as e:
                log.exception("Échec %s", job.url)
                self.emit(job, status=f"Erreur : {str(e).splitlines()[0][:120]}", speed=0)

    def _queue_download(self, job):
        self.emit(job, status="En attente de téléchargement")
        with self._lock:
            self._dl_pending.append(job)
        self._pump()

    def _pump(self):
        with self._lock:
            while self._dl_active < self.max_parallel and self._dl_pending:
                job = self._dl_pending.pop(0)
                self._dl_active += 1
                threading.Thread(target=self._run_download, args=(job,), daemon=True).start()

    def _run_download(self, job):
        try:
            self._download(job)
        except Exception as e:
            log.exception("Échec %s", job.url)
            self.emit(job, status=f"Erreur : {str(e).splitlines()[0][:120]}", speed=0)
        finally:
            with self._lock:
                self._dl_active -= 1
            self._pump()

    def _download(self, job):
        url = job.dl_url
        # Empreinte Chrome de curl_cffi seule, puis avec le User-Agent du navigateur.
        attempts = [({}, {})] + ([({"User-Agent": job.user_agent}, {})] if job.user_agent else [])
        d = Downloader(url, job.url, attempts, self.connections)
        self.emit(job, status="Connexion au serveur…")
        try:
            d.probe()
        except Refused as e:
            job.dl_url = None  # lien sans doute expiré : « Réessayer » rouvrira la page
            raise RuntimeError(f"le serveur refuse le téléchargement ({e})") from e
        name = job.name or safe_name(d.filename or "") or safe_name(
            urllib.parse.unquote(os.path.basename(urllib.parse.urlparse(url).path))) or "download.bin"
        final = os.path.join(job.dest, name)
        if os.path.exists(final):
            self.emit(job, name=name, status="Déjà présent")
            return
        os.makedirs(job.dest, exist_ok=True)
        conns = min(d.connections, max(1, (d.total or 0) // (4 << 20))) if d.ranges else 1
        self.emit(job, name=name, total=d.total,
                  status=f"Téléchargement ({conns} connexion{'s' if conns > 1 else ''})")
        prog = Progress(self.emit, job)
        self.downloaders.add(d)
        try:
            d.download(final, prog.update)
        finally:
            self.downloaders.discard(d)
        self.emit(job, status="Terminé", done=d.done, total=d.total or d.done, speed=0)
