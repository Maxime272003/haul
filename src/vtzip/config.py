"""Persistance de la config et du cache local (clé API, résultats VT).

Sous Windows, la clé API est chiffrée avec DPAPI : seul le compte Windows qui l'a enregistrée
peut la relire.
"""

from __future__ import annotations

import base64
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


def _dpapi(data: bytes, protect: bool) -> bytes | None:
    """Chiffre / dechiffre avec DPAPI (lie au compte Windows). None hors Windows ou en cas d'echec."""
    if os.name != "nt":
        return None
    import ctypes
    from ctypes import wintypes

    class Blob(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

    crypt32, kernel32 = ctypes.WinDLL("crypt32"), ctypes.WinDLL("kernel32")
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    buf = ctypes.create_string_buffer(data, len(data))
    blob_in, blob_out = Blob(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char))), Blob()
    func = crypt32.CryptProtectData if protect else crypt32.CryptUnprotectData
    ui_forbidden = 0x1
    if not func(ctypes.byref(blob_in), None, None, None, None, ui_forbidden, ctypes.byref(blob_out)):
        return None
    try:
        return ctypes.string_at(blob_out.pbData, blob_out.cbData)
    finally:
        kernel32.LocalFree(ctypes.cast(blob_out.pbData, ctypes.c_void_p))


def store_api_key(key: str) -> Path:
    """Enregistre la cle : chiffree avec DPAPI sous Windows, en clair ailleurs."""
    data = load_config()
    protected = _dpapi(key.encode(), protect=True)
    if protected:
        data["api_key_dpapi"] = base64.b64encode(protected).decode()
        data.pop("api_key", None)
    else:
        data["api_key"] = key
        data.pop("api_key_dpapi", None)
    return save_config(data)


def stored_api_key() -> str | None:
    """Cle du fichier de config ; une ancienne cle en clair est chiffree au passage."""
    data = load_config()
    protected = data.get("api_key_dpapi")
    if isinstance(protected, str):
        try:
            clear = _dpapi(base64.b64decode(protected), protect=False)
        except ValueError:
            clear = None
        if clear:
            return clear.decode().strip() or None
    stored = data.get("api_key")
    if isinstance(stored, str) and stored.strip():
        if os.name == "nt":
            store_api_key(stored.strip())
        return stored.strip()
    return None


def resolve_api_key(cli_key: str | None = None) -> str | None:
    """Priorite : --api-key > variable d'environnement > fichier de config."""
    if cli_key:
        return cli_key.strip()
    for name in ENV_KEYS:
        value = os.environ.get(name)
        if value and value.strip():
            return value.strip()
    return stored_api_key()


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
