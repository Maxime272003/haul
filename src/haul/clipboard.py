"""Lecture du presse-papier Windows.

Quand on copie une liste de liens depuis une page web, le texte brut ne contient que les noms
des fichiers : les URL sont dans la version HTML (format « HTML Format »), lue ici via l'API Win32.
"""

import ctypes
import html
import time
from ctypes import wintypes

_user32 = ctypes.WinDLL("user32")
_kernel32 = ctypes.WinDLL("kernel32")
_user32.GetClipboardData.restype = wintypes.HANDLE
_user32.GetClipboardData.argtypes = [wintypes.UINT]
_user32.OpenClipboard.argtypes = [wintypes.HWND]
_user32.GetClipboardSequenceNumber.restype = wintypes.DWORD
_kernel32.GlobalLock.restype = ctypes.c_void_p
_kernel32.GlobalLock.argtypes = [wintypes.HGLOBAL]
_kernel32.GlobalUnlock.argtypes = [wintypes.HGLOBAL]
_kernel32.GlobalSize.restype = ctypes.c_size_t
_kernel32.GlobalSize.argtypes = [wintypes.HGLOBAL]
CF_HTML = _user32.RegisterClipboardFormatW("HTML Format")


def sequence():
    """Compteur incrémenté par Windows à chaque changement du presse-papier."""
    return _user32.GetClipboardSequenceNumber()


def read_html():
    """Version HTML du presse-papier (liens compris), ou chaîne vide."""
    if not _user32.IsClipboardFormatAvailable(CF_HTML):
        return ""
    for _ in range(10):  # une autre application peut avoir le presse-papier ouvert
        if _user32.OpenClipboard(None):
            break
        time.sleep(0.02)
    else:
        return ""
    try:
        handle = _user32.GetClipboardData(CF_HTML)
        ptr = _kernel32.GlobalLock(handle) if handle else None
        if not ptr:
            return ""
        try:
            data = ctypes.string_at(ptr, _kernel32.GlobalSize(handle))
        finally:
            _kernel32.GlobalUnlock(handle)
    finally:
        _user32.CloseClipboard()
    return html.unescape(data.split(b"\0", 1)[0].decode("utf-8", "replace"))
