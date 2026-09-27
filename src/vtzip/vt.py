"""Client minimal pour l'API VirusTotal v3 (lookup par hash + upload optionnel)."""

from __future__ import annotations

import threading
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

import requests

API_ROOT = "https://www.virustotal.com/api/v3"
GUI_FILE_URL = "https://www.virustotal.com/gui/file/{}"
# Au-dela de 32 Mo, VT impose de passer par une URL d'upload dediee.
DIRECT_UPLOAD_LIMIT = 32 * 1024 * 1024
MAX_UPLOAD_LIMIT = 650 * 1024 * 1024

KNOWN = "known"
UNKNOWN = "unknown"
ERROR = "error"
SKIPPED = "skipped"


class VTError(RuntimeError):
    pass


class QuotaExceeded(VTError):
    pass


class RateLimiter:
    """Fenetre glissante : `rpm` requetes par minute max (0 = pas de bridage)."""

    def __init__(self, rpm: int = 4, on_wait: Callable[[float], None] | None = None):
        self.rpm = rpm
        self.on_wait = on_wait
        self._calls: deque[float] = deque()
        self._lock = threading.Lock()

    def acquire(self) -> None:
        if self.rpm <= 0:
            return
        with self._lock:
            now = time.monotonic()
            while self._calls and now - self._calls[0] >= 60:
                self._calls.popleft()
            if len(self._calls) >= self.rpm:
                wait = 60 - (now - self._calls[0]) + 0.1
                if wait > 0:
                    if self.on_wait:
                        self.on_wait(wait)
                    time.sleep(wait)
                    now = time.monotonic()
                    while self._calls and now - self._calls[0] >= 60:
                        self._calls.popleft()
            self._calls.append(time.monotonic())


@dataclass
class FileVerdict:
    status: str = UNKNOWN
    malicious: int = 0
    suspicious: int = 0
    harmless: int = 0
    undetected: int = 0
    engines: int = 0
    reputation: int = 0
    type_description: str | None = None
    meaningful_name: str | None = None
    names: list[str] = field(default_factory=list)
    labels: list[str] = field(default_factory=list)
    engine_hits: list[tuple[str, str]] = field(default_factory=list)
    last_analysis_date: int | None = None
    times_submitted: int = 0
    permalink: str | None = None
    message: str | None = None

    @property
    def flagged(self) -> int:
        return self.malicious + self.suspicious

    def as_dict(self) -> dict:
        return {
            "status": self.status,
            "malicious": self.malicious,
            "suspicious": self.suspicious,
            "harmless": self.harmless,
            "undetected": self.undetected,
            "engines": self.engines,
            "reputation": self.reputation,
            "type_description": self.type_description,
            "meaningful_name": self.meaningful_name,
            "names": self.names[:10],
            "labels": self.labels,
            "engine_hits": [{"engine": e, "result": r} for e, r in self.engine_hits],
            "last_analysis_date": self.last_analysis_date,
            "times_submitted": self.times_submitted,
            "permalink": self.permalink,
            "message": self.message,
        }


def _parse_file_object(data: dict, file_hash: str) -> FileVerdict:
    attrs = data.get("data", {}).get("attributes", {}) or {}
    stats = attrs.get("last_analysis_stats", {}) or {}
    results = attrs.get("last_analysis_results", {}) or {}

    hits = [
        (engine, info.get("result") or info.get("category", "?"))
        for engine, info in results.items()
        if info.get("category") in ("malicious", "suspicious")
    ]
    hits.sort(key=lambda pair: pair[0].lower())

    counted = ("harmless", "malicious", "suspicious", "undetected", "timeout")
    labels = []
    threat = attrs.get("popular_threat_classification") or {}
    if threat.get("suggested_threat_label"):
        labels.append(threat["suggested_threat_label"])
    labels += [c.get("value") for c in threat.get("popular_threat_name", [])[:3] if c.get("value")]

    return FileVerdict(
        status=KNOWN,
        malicious=int(stats.get("malicious", 0)),
        suspicious=int(stats.get("suspicious", 0)),
        harmless=int(stats.get("harmless", 0)),
        undetected=int(stats.get("undetected", 0)),
        engines=sum(int(stats.get(k, 0)) for k in counted),
        reputation=int(attrs.get("reputation", 0) or 0),
        type_description=attrs.get("type_description"),
        meaningful_name=attrs.get("meaningful_name"),
        names=list(attrs.get("names", []) or [])[:10],
        labels=labels,
        engine_hits=hits,
        last_analysis_date=attrs.get("last_analysis_date"),
        times_submitted=int(attrs.get("times_submitted", 0) or 0),
        permalink=GUI_FILE_URL.format(file_hash),
    )


class VirusTotalClient:
    def __init__(
        self,
        api_key: str,
        rpm: int = 4,
        cache=None,
        timeout: int = 60,
        on_wait: Callable[[float], None] | None = None,
    ):
        self.api_key = api_key
        self.cache = cache
        self.timeout = timeout
        self.limiter = RateLimiter(rpm, on_wait=on_wait)
        self.session = requests.Session()
        self.session.headers.update(
            {
                "x-apikey": api_key,
                "accept": "application/json",
                "user-agent": "vtzip/1.0 (+https://github.com/)",
            }
        )
        self.requests_made = 0

    # -- bas niveau ------------------------------------------------------
    def _request(self, method: str, url: str, **kwargs) -> requests.Response:
        self.limiter.acquire()
        self.requests_made += 1
        try:
            return self.session.request(method, url, timeout=self.timeout, **kwargs)
        except requests.RequestException as exc:
            raise VTError(f"Erreur réseau : {exc}") from exc

    @staticmethod
    def _error_message(resp: requests.Response) -> str:
        try:
            payload = resp.json()
            err = payload.get("error", {})
            return err.get("message") or err.get("code") or resp.text[:200]
        except ValueError:
            return resp.text[:200] or f"HTTP {resp.status_code}"

    # -- lookup ----------------------------------------------------------
    def lookup_hash(self, file_hash: str) -> FileVerdict:
        cache_key = f"file:{file_hash.lower()}"
        if self.cache:
            cached = self.cache.get(cache_key)
            if cached is not None:
                verdict = FileVerdict(**{**cached, "engine_hits": []})
                verdict.engine_hits = [
                    (h["engine"], h["result"]) for h in cached.get("engine_hits", [])
                ]
                verdict.names = cached.get("names", [])
                verdict.labels = cached.get("labels", [])
                return verdict

        resp = self._request("GET", f"{API_ROOT}/files/{file_hash}")
        if resp.status_code == 200:
            verdict = _parse_file_object(resp.json(), file_hash)
        elif resp.status_code == 404:
            verdict = FileVerdict(
                status=UNKNOWN,
                permalink=GUI_FILE_URL.format(file_hash),
                message="Jamais soumis à VirusTotal.",
            )
        elif resp.status_code == 401:
            raise VTError("Clé API refusée (401). Vérifie-la avec `vtzip config set-key`.")
        elif resp.status_code == 429:
            raise QuotaExceeded(
                "Quota VirusTotal atteint (429). L'API publique est limitée à "
                "4 requêtes par minute et 500 par jour."
            )
        else:
            raise VTError(f"HTTP {resp.status_code} : {self._error_message(resp)}")

        if self.cache:
            self.cache.set(cache_key, verdict.as_dict())
        return verdict

    # -- upload ----------------------------------------------------------
    def upload(self, path: Path) -> str:
        """Envoie le fichier a VT et retourne l'id d'analyse."""
        size = path.stat().st_size
        if size > MAX_UPLOAD_LIMIT:
            raise VTError(
                f"Fichier trop volumineux pour l'API ({size / 1024 / 1024:.0f} Mo > 650 Mo)."
            )
        url = f"{API_ROOT}/files"
        if size > DIRECT_UPLOAD_LIMIT:
            resp = self._request("GET", f"{API_ROOT}/files/upload_url")
            if resp.status_code != 200:
                raise VTError(f"Impossible d'obtenir l'URL d'upload : {self._error_message(resp)}")
            url = resp.json().get("data")
            if not url:
                raise VTError("Réponse d'URL d'upload invalide.")

        with path.open("rb") as fh:
            resp = self._request(
                "POST", url, files={"file": (path.name, fh, "application/octet-stream")}
            )
        if resp.status_code not in (200, 201):
            if resp.status_code == 429:
                raise QuotaExceeded("Quota VirusTotal atteint pendant l'upload (429).")
            raise VTError(f"Upload refusé (HTTP {resp.status_code}) : {self._error_message(resp)}")
        analysis_id = resp.json().get("data", {}).get("id")
        if not analysis_id:
            raise VTError("Aucun identifiant d'analyse retourné par VirusTotal.")
        return analysis_id

    def analysis_status(self, analysis_id: str) -> str:
        resp = self._request("GET", f"{API_ROOT}/analyses/{analysis_id}")
        if resp.status_code == 429:
            raise QuotaExceeded("Quota VirusTotal atteint pendant l'attente (429).")
        if resp.status_code != 200:
            raise VTError(f"Suivi de l'analyse impossible : {self._error_message(resp)}")
        return resp.json().get("data", {}).get("attributes", {}).get("status", "unknown")

    def wait_for_analysis(
        self,
        analysis_id: str,
        timeout: int = 900,
        on_poll: Callable[[str, int], None] | None = None,
    ) -> str:
        deadline = time.monotonic() + timeout
        attempt = 0
        while time.monotonic() < deadline:
            attempt += 1
            status = self.analysis_status(analysis_id)
            if on_poll:
                on_poll(status, attempt)
            if status == "completed":
                return status
            time.sleep(5 if self.limiter.rpm <= 0 else 1)
        raise VTError("Délai d'attente dépassé pour l'analyse VirusTotal.")
