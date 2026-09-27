"""Persistance de la config et du cache local (clé API, résultats VT)."""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

APP_NAME = "vtzip"
ENV_KEYS = ("VT_API_KEY", "VIRUSTOTAL_API_KEY")


def config_dir() -> Path:
    base = os.environ.get("APPDATA") or os.environ.get("XDG_CONFIG_HOME")
    root = Path(base) if base else Path.home() / ".config"
    return root / APP_NAME


def config_path() -> Path:
    return config_dir() / "config.json"


def cache_path() -> Path:
    return config_dir() / "cache.json"


def _read_json(path: Path) -> dict:
    try:
        with path.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def _write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, sort_keys=True)
    tmp.replace(path)


def load_config() -> dict:
    return _read_json(config_path())


def save_config(data: dict) -> Path:
    _write_json(config_path(), data)
    return config_path()


def resolve_api_key(cli_key: str | None = None) -> str | None:
    """Priorite : --api-key > variable d'environnement > fichier de config."""
    if cli_key:
        return cli_key.strip()
    for name in ENV_KEYS:
        value = os.environ.get(name)
        if value and value.strip():
            return value.strip()
    stored = load_config().get("api_key")
    return stored.strip() if isinstance(stored, str) and stored.strip() else None


class ResultCache:
    """Cache hash -> reponse VT, pour ne pas bruler le quota sur un meme fichier."""

    def __init__(self, ttl_seconds: int = 24 * 3600, enabled: bool = True):
        self.ttl = ttl_seconds
        self.enabled = enabled
        self._data: dict = _read_json(cache_path()) if enabled else {}
        self._dirty = False

    def get(self, key: str):
        if not self.enabled:
            return None
        entry = self._data.get(key)
        if not isinstance(entry, dict):
            return None
        if time.time() - entry.get("ts", 0) > self.ttl:
            return None
        return entry.get("value")

    def set(self, key: str, value) -> None:
        if not self.enabled:
            return
        self._data[key] = {"ts": time.time(), "value": value}
        self._dirty = True

    def flush(self) -> None:
        if self.enabled and self._dirty:
            _write_json(cache_path(), self._data)
            self._dirty = False
