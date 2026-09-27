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
from enum import Enum

from .downloader import Cancelled, Downloader, Refused
from .links import is_page_url, page_key, safe_name

log = logging.getLogger(__name__)

LINK_TIMEOUT = 600  # temps laissé pour valider le captcha dans le navigateur
MIN_CONNECTION_SPEED = 16 << 10  # plancher par connexion quand le débit total est limité


class State(str, Enum):
    """État d'un fichier. Le libellé affiché est dans LABELS (ou Job.detail, plus précis)."""

    WAITING = "waiting"          # en file, page pas encore ouverte
    BROWSER = "browser"          # page ouverte, en attente du lien direct (captcha)
    QUEUED = "queued"            # lien direct reçu, en attente d'une place de téléchargement
    CONNECTING = "connecting"
    DOWNLOADING = "downloading"
    PAUSED = "paused"
    DONE = "done"
    PRESENT = "present"          # déjà sur le disque
    CHECKING = "checking"        # test d'intégrité de l'archive avant extraction
    EXTRACTING = "extracting"
    EXTRACTED = "extracted"
    EXTRACT_FAILED = "extract_failed"
    BLOCKED = "blocked"          # extraction bloquée (analyse, archive dangereuse…)
    ERROR = "error"


LABELS = {
    State.WAITING: "En attente",
    State.BROWSER: "Dans le navigateur : valide le captcha si demandé",
    State.QUEUED: "En attente de téléchargement",
    State.CONNECTING: "Connexion au serveur…",
    State.DOWNLOADING: "Téléchargement",
    State.PAUSED: "En pause",
    State.DONE: "Terminé",
    State.PRESENT: "Déjà présent",
    State.CHECKING: "Vérification de l'archive…",
    State.EXTRACTING: "Extraction…",
    State.EXTRACTED: "Extrait ✔",
    State.EXTRACT_FAILED: "Échec extraction",
    State.BLOCKED: "Extraction bloquée",
    State.ERROR: "Erreur",
}

# Fichier complet sur le disque (téléchargé, éventuellement en cours de traitement)
ON_DISK = frozenset({State.DONE, State.PRESENT, State.CHECKING, State.EXTRACTING, State.EXTRACTED,
                     State.EXTRACT_FAILED, State.BLOCKED})
# Encore entre les mains du moteur
ACTIVE = frozenset({State.WAITING, State.BROWSER, State.QUEUED, State.CONNECTING, State.DOWNLOADING})


@dataclass(eq=False)  # comparé par identité (listes d'attente du moteur)
class Job:
    id: int
    url: str
    dest: str
    name: str = None
    state: State = State.WAITING
    detail: str = ""  # précision affichée à la place du libellé de l'état
    done: int = 0
    total: int = None
    speed: float = 0.0
    dl_url: str = None
    user_agent: str = None
    vt: str = ""  # verdict VirusTotal affiché
    processed: bool = False  # déjà passé par l'analyse + extraction automatiques

    @property
    def path(self):
        return os.path.join(self.dest, self.name) if self.name else None

    @property
    def status(self):
        return self.detail or LABELS[self.state]


def error_detail(e):
    return f"Erreur : {str(e).splitlines()[0][:120] if str(e) else type(e).__name__}"


def complete_on_disk(path, total):
    """Le fichier existe et a la taille attendue (si on la connaît)."""
    try:
        return os.path.isfile(path) and (total is None or os.path.getsize(path) == total)
    except OSError:
        return False


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

    Les changements d'état sont publiés dans `events` sous la forme (job.id, {champ: valeur}) ;
    l'interface les applique au Job dans son propre thread.
    """

    def __init__(self, events, on_unknown_link, open_page=os.startfile):
        self.events = events
        self.on_unknown_link = on_unknown_link  # lien reçu pour une page que l'app n'a pas ouverte
        self.open_page = open_page
        self.max_parallel = 2
        self.connections = 8
        self.max_speed = 0  # octets/s, tous téléchargements confondus (0 = illimité)
        self._lock = threading.Lock()
        self._to_resolve = queue.Queue()
        self._resolve_ids = set()  # jobs dans _to_resolve (pas de doublon après pause / reprise)
        self._waiting = {}  # page_key -> (job, threading.Event)
        self._dl_pending = []
        self._dl_active = 0
        self._downloaders = {}  # job.id -> Downloader en cours
        self._paths = set()  # fichiers en cours d'écriture
        self._paused = set()  # job.id mis en pause
        threading.Thread(target=self._resolver, daemon=True).start()

    # --- API (thread de l'interface / serveur local) ---

    def submit(self, job):
        """Ajoute le fichier à la file, ou le reprend après une pause ou une erreur."""
        if job.dl_url:
            with self._lock:
                self._paused.discard(job.id)
            self._queue_download(job)
            return
        with self._lock:
            self._paused.discard(job.id)
            queued = job.id in self._resolve_ids  # encore dans la file : il suffit de lever la pause
            self._resolve_ids.add(job.id)
            # publié sous le verrou : _resolve ne peut pas publier BROWSER avant
            self.set_state(job, State.WAITING)
        if not queued:
            self._to_resolve.put(job)

    def pause(self, job):
        """Met le fichier en pause ; l'état PAUSED est publié une fois tout arrêté.

        Un fichier dans le navigateur est libéré : la page suivante s'ouvre (« passer ce lien »).
        Le fichier partiel reste sur le disque, la reprise repart de là.
        """
        with self._lock:
            self._paused.add(job.id)
            downloader = self._downloaders.get(job.id)
            entry = self._waiting.get(page_key(job.url))
            browser = entry is not None and entry[0] is job
            pending = job in self._dl_pending
            if pending:
                self._dl_pending.remove(job)
        if downloader:
            downloader.cancel()  # _run_download publie PAUSED
        elif browser:
            entry[1].set()  # _resolver publie PAUSED
        elif pending or job.id in self._resolve_ids:
            self.set_state(job, State.PAUSED, speed=0)

    def set_parallel(self, n):
        self.max_parallel = n
        self._pump()

    def set_connections(self, n):
        self.connections = n

    def set_max_speed(self, bytes_per_second):
        self.max_speed = max(0, int(bytes_per_second))

    def is_waiting(self, page_url):
        with self._lock:
            return page_key(page_url) in self._waiting

    def link_found(self, page_url, dl_url, user_agent):
        """Retourne True si l'onglet peut être fermé (page ouverte par l'app)."""
        with self._lock:
            entry = self._waiting.get(page_key(page_url)) if page_url else None
        if entry:
            job, event = entry
            job.dl_url, job.user_agent = dl_url, user_agent
            event.set()
            return True
        self.on_unknown_link(page_url, dl_url, user_agent)
        return False

    def shutdown(self):
        with self._lock:
            downloaders = list(self._downloaders.values())
        for d in downloaders:
            d.cancel()

    # --- interne ---

    def emit(self, job, **fields):
        self.events.put((job.id, fields))

    def set_state(self, job, state, detail="", **fields):
        self.emit(job, state=state, detail=detail, **fields)

    def _connection_speed(self):
        """Débit maximal d'une connexion : le plafond total partagé entre les connexions ouvertes."""
        if not self.max_speed:
            return 0
        with self._lock:
            conns = sum(max(1, d.active_connections) for d in self._downloaders.values())
        return max(MIN_CONNECTION_SPEED, self.max_speed // max(1, conns))

    def _resolver(self):
        # Une page à la fois : le captcha validé une fois vaut pour les liens suivants.
        while True:
            job = self._to_resolve.get()
            try:
                self._resolve(job)
            except Exception as e:
                log.exception("Échec %s", job.url)
                self.set_state(job, State.ERROR, error_detail(e), speed=0)

    def _resolve(self, job):
        key, event = page_key(job.url), threading.Event()
        with self._lock:
            self._resolve_ids.discard(job.id)
            if job.id in self._paused:
                return  # PAUSED déjà publié par pause()
            self._waiting[key] = (job, event)
        try:
            if job.path and complete_on_disk(job.path, job.total):
                self.set_state(job, State.PRESENT)
                return
            if not is_page_url(job.url):
                # Ne jamais passer autre chose à os.startfile : Windows lancerait n'importe quoi.
                self.set_state(job, State.ERROR, "Erreur : lien direct expiré, recopie le lien de la page")
                return
            self.set_state(job, State.BROWSER)
            self.open_page(job.url)
            received = event.wait(LINK_TIMEOUT)
        finally:
            with self._lock:
                self._waiting.pop(key, None)
                paused = job.id in self._paused
        if paused:
            self.set_state(job, State.PAUSED)
        elif not received:
            self.set_state(job, State.ERROR, "Erreur : aucun lien reçu du navigateur (userscript installé ?)")
        else:
            log.info("Lien reçu pour %s : %s", job.url, job.dl_url)
            self._queue_download(job)

    def _queue_download(self, job):
        self.set_state(job, State.QUEUED)
        with self._lock:
            if job not in self._dl_pending:
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
        except Cancelled:
            self.set_state(job, State.PAUSED, speed=0)
        except Exception as e:
            log.exception("Échec %s", job.url)
            self.set_state(job, State.ERROR, error_detail(e), speed=0)
        finally:
            with self._lock:
                self._dl_active -= 1
                self._downloaders.pop(job.id, None)
            self._pump()

    def _download(self, job):
        url = job.dl_url
        # Empreinte Chrome de curl_cffi seule, puis avec le User-Agent du navigateur.
        attempts = [({}, {})] + ([({"User-Agent": job.user_agent}, {})] if job.user_agent else [])
        d = Downloader(url, job.url, attempts, self.connections, speed_limit=self._connection_speed)
        with self._lock:
            if job.id in self._paused:
                raise Cancelled("en pause")
            self._downloaders[job.id] = d
        self.set_state(job, State.CONNECTING)
        try:
            d.probe()
        except Refused as e:
            job.dl_url = None  # lien sans doute expiré : « Réessayer » rouvrira la page
            raise RuntimeError(f"le serveur refuse le téléchargement ({e})") from e
        if d.cancelled:
            raise Cancelled("en pause")
        name = job.name or safe_name(d.filename or "") or safe_name(
            urllib.parse.unquote(os.path.basename(urllib.parse.urlparse(url).path))) or "download.bin"
        final = os.path.join(job.dest, name)
        if complete_on_disk(final, d.total):
            self.set_state(job, State.PRESENT, name=name, total=d.total, done=d.total or 0)
            return
        if os.path.exists(final):
            log.warning("%s existe mais n'a pas la taille attendue (%s) : nouveau téléchargement", final, d.total)
        with self._lock:
            if final in self._paths:
                raise RuntimeError("ce fichier est déjà en cours de téléchargement")
            self._paths.add(final)
        try:
            os.makedirs(job.dest, exist_ok=True)
            conns = min(d.connections, max(1, (d.total or 0) // (4 << 20))) if d.ranges else 1
            self.set_state(job, State.DOWNLOADING, f"Téléchargement ({conns} connexion{'s' if conns > 1 else ''})",
                           name=name, total=d.total)
            d.download(final, Progress(self.emit, job).update)
        finally:
            with self._lock:
                self._paths.discard(final)
        self.set_state(job, State.DONE, done=d.done, total=d.total or d.done, speed=0)
