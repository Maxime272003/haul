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
    def __init__(self, url, referer, attempts, connections=8):
        """attempts : liste de (headers, cookies) à essayer dans l'ordre lors du probe."""
        self.url = url
        self.referer = referer
        self.attempts = attempts
        self.connections = max(1, connections)
        self.headers = self.cookies = None
        self.total = None
        self.ranges = False
        self.filename = None
        self.done = 0
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._error = None

    def _session(self):
        s = creq.Session(impersonate="chrome")
        s.headers.update({"Referer": self.referer, "Accept-Encoding": "identity", **self.headers})
        s.cookies.update(self.cookies)
        return s

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
        self.done = sum(pos - start for start, _, pos in segments)
        todo = [seg for seg in segments if seg[2] <= seg[1]]
        n_workers = min(self.connections, len(todo))
        alive = [n_workers]

        def worker():
            s = self._session()
            throttled = 0
            try:
                while not self._stop.is_set():
                    with self._lock:
                        if not todo:
                            return
                        seg = todo.pop(0)
                    try:
                        self._fetch_segment(s, seg, part)
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
                s.close()

        threads = [threading.Thread(target=worker, daemon=True) for _ in range(n_workers)]
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

    def _fetch_segment(self, s, seg, part):
        errors = 0
        while seg[2] <= seg[1]:
            if self._stop.is_set():
                return
            try:
                r = s.get(self.url, headers={"Range": f"bytes={seg[2]}-{seg[1]}"}, stream=True, timeout=TIMEOUT)
                try:
                    if r.status_code in (429, 503):
                        raise Throttled(f"HTTP {r.status_code}")
                    if r.status_code != 206:
                        raise OSError(f"HTTP {r.status_code} sur un segment")
                    with open(part, "r+b", buffering=0) as f:
                        f.seek(seg[2])
                        for chunk in r.iter_content():
                            if self._stop.is_set():
                                return
                            chunk = chunk[: seg[1] - seg[2] + 1]
                            f.write(chunk)
                            seg[2] += len(chunk)
                            with self._lock:
                                self.done += len(chunk)
                            errors = 0
                            if seg[2] > seg[1]:
                                break
                finally:
                    r.close()
            except Throttled:
                raise
            except (OSError, creq.RequestsError):
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
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump({"total": self.total, "segments": segments}, f)
        os.replace(tmp, state_path)

    # --- téléchargement simple (serveur sans support des Range) ---

    def _single(self, part, on_progress):
        s = self._session()
        try:
            r = s.get(self.url, stream=True, timeout=TIMEOUT)
            try:
                if r.status_code != 200:
                    raise OSError(f"HTTP {r.status_code}")
                self.done = 0
                last = 0
                with open(part, "wb") as f:
                    for chunk in r.iter_content():
                        if self._stop.is_set():
                            raise Cancelled("interrompu")
                        f.write(chunk)
                        self.done += len(chunk)
                        if time.monotonic() - last > 0.5:
                            on_progress(self.done, self.total)
                            last = time.monotonic()
            finally:
                r.close()
        finally:
            s.close()
        if self.total and self.done < self.total:
            raise OSError("téléchargement incomplet")
        on_progress(self.done, self.total or self.done)
