"""Téléchargement HTTP multi-connexions avec reprise.

Utilise curl_cffi (empreinte réseau de Chrome) car Cloudflare rejette les clients HTTP Python classiques.
Le fichier est découpé en segments téléchargés en parallèle ; l'avancement est sauvegardé dans
<fichier>.part.json pour pouvoir reprendre après une coupure.
"""
import json
import os
import re
import threading
import time
import urllib.parse

from curl_cffi import requests as creq

MIN_SEGMENT = 4 << 20
MAX_SEGMENT = 256 << 20
TIMEOUT = (15, 60)  # connexion, inactivité
MAX_RETRIES = 6
WRITE_BUFFER = 1 << 20

CONTENT_RANGE_RE = re.compile(r"bytes (\d+)-(\d+)/(\d+|\*)")


class Refused(Exception):
    """Le serveur a renvoyé une page (captcha, erreur) au lieu du fichier."""


class Cancelled(Exception):
    pass


class Throttled(IOError):
    """Le serveur refuse une connexion de plus (429/503)."""


def filename_from_headers(headers):
    cd = headers.get("Content-Disposition", "")
    m = re.search(r"filename\*=(?:UTF-8'')?([^;]+)", cd, re.I) or re.search(r'filename="?([^";]+)"?', cd, re.I)
    return urllib.parse.unquote(m.group(1).strip()) if m else None


class Downloader:
    def __init__(self, url, referer, attempts, connections=8, speed_limit=lambda: 0):
        """attempts : liste de (headers, cookies) à essayer dans l'ordre lors du probe.

        speed_limit : fonction qui donne le débit maximal d'une connexion en octets/s (0 = illimité),
        relue à chaque requête pour suivre le réglage et le nombre de connexions ouvertes.
        """
        self.url = url
        self.referer = referer
        self.attempts = attempts
        self.connections = max(1, connections)
        self.speed_limit = speed_limit
        self.headers = self.cookies = None
        self.total = None
        self.ranges = False
        self.filename = None
        self.active_connections = 0
        # Octets déjà sur le disque au démarrage + un compteur par connexion : chaque thread
        # n'écrit que le sien, la somme se lit sans verrou.
        self._base = 0
        self._counts = []
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._error = None

    @property
    def done(self):
        return self._base + sum(self._counts)

    @property
    def cancelled(self):
        return self._stop.is_set()

    def _session(self):
        s = creq.Session(impersonate="chrome")
        s.headers.update({"Referer": self.referer, "Accept-Encoding": "identity", **self.headers})
        s.cookies.update(self.cookies)
        return s

    def _get(self, s, **kwargs):
        return s.get(self.url, stream=True, timeout=TIMEOUT, max_recv_speed=int(self.speed_limit() or 0), **kwargs)

    def cancel(self):
        self._stop.set()

    def probe(self):
        """Vérifie que le serveur sert bien le fichier et récupère taille / support des Range."""
        last = None
        for headers, cookies in self.attempts:
            self.headers, self.cookies = headers, cookies
            s = self._session()
            try:
                r = s.get(self.url, headers={"Range": "bytes=0-0"}, stream=True, timeout=TIMEOUT)
                try:
                    ctype = r.headers.get("Content-Type", "")
                    if r.status_code not in (200, 206) or "text/html" in ctype:
                        last = f"HTTP {r.status_code}"
                        continue
                    self.filename = filename_from_headers(r.headers)
                    m = re.search(r"/(\d+)$", r.headers.get("Content-Range", ""))
                    if r.status_code == 206 and m:
                        self.total, self.ranges = int(m.group(1)), True
                    elif r.headers.get("Content-Length"):
                        self.total = int(r.headers["Content-Length"])
                    return
                finally:
                    r.close()
            except creq.RequestsError as e:
                last = str(e)
            finally:
                s.close()
        raise Refused(last)

    def download(self, final_path, on_progress):
        part = final_path + ".part"
        if self.ranges and self.total:
            self._segmented(part, on_progress)
        else:
            self._single(part, on_progress)
        os.replace(part, final_path)

    # --- téléchargement segmenté ---

    def _segmented(self, part, on_progress):
        state_path = part + ".json"
        segments = self._load_state(state_path, part)
        if segments is None:
            size = max(MIN_SEGMENT, min(MAX_SEGMENT, self.total // (self.connections * 4)))
            segments = [[start, min(start + size, self.total) - 1, start] for start in range(0, self.total, size)]
            with open(part, "wb") as f:
                f.truncate(self.total)
        self._base = sum(pos - start for start, _, pos in segments)
        todo = [seg for seg in segments if seg[2] <= seg[1]]
        n_workers = min(self.connections, len(todo))
        self._counts = [0] * n_workers
        alive = [n_workers]
        self.active_connections = n_workers

        def worker(index):
            s = self._session()
            throttled = 0
            try:
                with open(part, "r+b", buffering=WRITE_BUFFER) as f:
                    while not self._stop.is_set():
                        with self._lock:
                            if not todo:
                                return
                            seg = todo.pop(0)
                        try:
                            self._fetch_segment(s, seg, f, index)
                            throttled = 0
                        except Throttled:
                            # Trop de connexions : on rend le segment et on laisse les autres continuer.
                            with self._lock:
                                todo.insert(0, seg)
                                if alive[0] > 1:
                                    return
                            throttled += 1
                            if throttled > MAX_RETRIES:
                                raise
                            time.sleep(5 * throttled)
            except Exception as e:
                self._error = self._error or e
                self._stop.set()
            finally:
                with self._lock:
                    alive[0] -= 1
                    self.active_connections = alive[0]
                s.close()

        threads = [threading.Thread(target=worker, args=(i,), daemon=True) for i in range(n_workers)]
        for t in threads:
            t.start()
        last_save = time.monotonic()
        while any(t.is_alive() for t in threads):
            time.sleep(0.5)
            on_progress(self.done, self.total)
            if time.monotonic() - last_save > 2:
                self._save_state(state_path, segments)
                last_save = time.monotonic()
        self._save_state(state_path, segments)

        if self._error:
            raise self._error
        if self._stop.is_set() or any(pos <= end for _, end, pos in segments):
            raise Cancelled("interrompu")
        on_progress(self.total, self.total)
        os.remove(state_path)

    def _fetch_segment(self, s, seg, f, index):
        """Télécharge seg = [début, fin, position] dans le fichier ouvert f.

        Les octets sont écrits (tampon vidé) avant d'avancer la position : l'état sauvegardé ne
        prétend jamais avoir plus que ce qui est sur le disque.
        """
        errors = 0
        while seg[2] <= seg[1]:
            if self._stop.is_set():
                return
            pending = 0  # octets écrits dans le tampon, pas encore comptés dans seg[2]
            try:
                r = self._get(s, headers={"Range": f"bytes={seg[2]}-{seg[1]}"})
                try:
                    if r.status_code in (429, 503):
                        raise Throttled(f"HTTP {r.status_code}")
                    if r.status_code != 206:
                        raise OSError(f"HTTP {r.status_code} sur un segment")
                    m = CONTENT_RANGE_RE.fullmatch(r.headers.get("Content-Range", "").strip())
                    if not m or int(m.group(1)) != seg[2] or m.group(3) not in ("*", str(self.total)):
                        # plage inattendue : écrire ces octets corromprait le fichier
                        raise OSError(f"plage inattendue ({r.headers.get('Content-Range')!r}) sur un segment")
                    f.seek(seg[2])
                    for chunk in r.iter_content():
                        if self._stop.is_set():
                            break
                        chunk = chunk[: seg[1] - seg[2] - pending + 1]
                        f.write(chunk)
                        pending += len(chunk)
                        self._counts[index] += len(chunk)
                        errors = 0
                        if pending >= WRITE_BUFFER or seg[2] + pending > seg[1]:
                            f.flush()
                            seg[2] += pending
                            pending = 0
                            if seg[2] > seg[1]:
                                break
                    f.flush()
                    seg[2] += pending
                finally:
                    r.close()
            except Throttled:
                raise
            except (OSError, creq.RequestsError):
                self._counts[index] -= pending  # seront téléchargés de nouveau
                errors += 1
                if errors >= MAX_RETRIES:
                    raise
                time.sleep(min(2 * errors, 10))

    def _load_state(self, state_path, part):
        try:
            with open(state_path, encoding="utf-8") as f:
                state = json.load(f)
            if state["total"] == self.total and os.path.getsize(part) == self.total:
                return state["segments"]
        except (OSError, ValueError, KeyError):
            pass
        return None

    def _save_state(self, state_path, segments):
        tmp = state_path + ".tmp"
        with self._lock:
            data = json.dumps({"total": self.total, "segments": [list(seg) for seg in segments]})
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(data)
        os.replace(tmp, state_path)

    # --- téléchargement simple (serveur sans support des Range) ---

    def _single(self, part, on_progress):
        s = self._session()
        self._base, self._counts = 0, [0]
        self.active_connections = 1
        try:
            r = self._get(s)
            try:
                if r.status_code != 200:
                    raise OSError(f"HTTP {r.status_code}")
                last = 0
                with open(part, "wb", buffering=WRITE_BUFFER) as f:
                    for chunk in r.iter_content():
                        if self._stop.is_set():
                            raise Cancelled("interrompu")
                        f.write(chunk)
                        self._counts[0] += len(chunk)
                        if time.monotonic() - last > 0.5:
                            on_progress(self.done, self.total)
                            last = time.monotonic()
            finally:
                r.close()
        finally:
            self.active_connections = 0
            s.close()
        if self.total and self.done < self.total:
            raise OSError("téléchargement incomplet")
        on_progress(self.done, self.total or self.done)
