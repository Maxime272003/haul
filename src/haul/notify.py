"""Signaux Windows hors de la fenêtre : notification, bouton de barre des tâches qui clignote, progression.

Tout passe par l'API Win32 (ctypes), sans dépendance. Chaque fonction échoue en silence : ce ne sont
que des indications en plus de la fenêtre.
"""

import ctypes
import logging
from ctypes import wintypes

log = logging.getLogger(__name__)


class GUID(ctypes.Structure):
    _fields_ = [("Data1", wintypes.DWORD), ("Data2", wintypes.WORD), ("Data3", wintypes.WORD),
                ("Data4", ctypes.c_ubyte * 8)]

    @classmethod
    def parse(cls, text):
        guid = cls()
        ctypes.windll.ole32.CLSIDFromString(ctypes.c_wchar_p(text), ctypes.byref(guid))
        return guid


def window_handle(window):
    """HWND du cadre Windows d'une fenêtre Tk (celui qui a un bouton dans la barre des tâches)."""
    window.update_idletasks()
    return ctypes.windll.user32.GetParent(window.winfo_id())


# --- clignotement du bouton ---

class FLASHWINFO(ctypes.Structure):
    _fields_ = [("cbSize", wintypes.UINT), ("hwnd", wintypes.HWND), ("dwFlags", wintypes.DWORD),
                ("uCount", wintypes.UINT), ("dwTimeout", wintypes.DWORD)]


def flash(hwnd):
    """Fait clignoter le bouton de la barre des tâches jusqu'à ce que la fenêtre soit activée."""
    try:
        info = FLASHWINFO(ctypes.sizeof(FLASHWINFO), hwnd, 0x2 | 0xC, 0, 0)  # FLASHW_TRAY | FLASHW_TIMERNOFG
        ctypes.windll.user32.FlashWindowEx(ctypes.byref(info))
    except (OSError, AttributeError):
        pass


def is_foreground(hwnd):
    try:
        return ctypes.windll.user32.GetForegroundWindow() == hwnd
    except (OSError, AttributeError):
        return False


# --- notification (bulle de la zone de notification, affichée comme une notification Windows) ---

class NOTIFYICONDATAW(ctypes.Structure):
    _fields_ = [("cbSize", wintypes.DWORD), ("hWnd", wintypes.HWND), ("uID", wintypes.UINT),
                ("uFlags", wintypes.UINT), ("uCallbackMessage", wintypes.UINT), ("hIcon", wintypes.HICON),
                ("szTip", wintypes.WCHAR * 128), ("dwState", wintypes.DWORD), ("dwStateMask", wintypes.DWORD),
                ("szInfo", wintypes.WCHAR * 256), ("uTimeout", wintypes.UINT), ("szInfoTitle", wintypes.WCHAR * 64),
                ("dwInfoFlags", wintypes.DWORD), ("guidItem", GUID), ("hBalloonIcon", wintypes.HICON)]


NIM_ADD, NIM_MODIFY, NIM_DELETE = 0, 1, 2
NIF_ICON, NIF_TIP, NIF_INFO = 0x2, 0x4, 0x10
NIIF_INFO, NIIF_WARNING, NIIF_USER, NIIF_LARGE_ICON = 0x1, 0x2, 0x4, 0x20


class Notifier:
    """Notifications Windows attribuées à l'application, via une icône temporaire de la zone de notification."""

    def __init__(self, hwnd, icon_path=None, tip="Haul"):
        self.hwnd, self.tip, self.shown = hwnd, tip, False
        self.icon = None
        try:
            user32 = ctypes.windll.user32
            user32.LoadImageW.restype = wintypes.HANDLE
            if icon_path:
                self.icon = user32.LoadImageW(None, str(icon_path), 1, 0, 0, 0x10 | 0x40)  # IMAGE_ICON, fichier
            if not self.icon:
                self.icon = user32.LoadIconW(None, ctypes.c_void_p(32512))  # IDI_APPLICATION
        except (OSError, AttributeError):
            pass

    def _data(self, flags):
        data = NOTIFYICONDATAW()
        data.cbSize = ctypes.sizeof(NOTIFYICONDATAW)
        data.hWnd, data.uID, data.uFlags, data.hIcon = self.hwnd, 1, flags, self.icon
        data.szTip = self.tip
        return data

    def show(self, title, text, warning=False):
        try:
            shell = ctypes.windll.shell32
            if not self.shown:
                self.shown = bool(shell.Shell_NotifyIconW(NIM_ADD, ctypes.byref(self._data(NIF_ICON | NIF_TIP))))
            data = self._data(NIF_ICON | NIF_TIP | NIF_INFO)
            data.szInfoTitle, data.szInfo = title[:63], text[:255]
            data.dwInfoFlags = NIIF_WARNING if warning else (NIIF_USER | NIIF_LARGE_ICON if self.icon else NIIF_INFO)
            shell.Shell_NotifyIconW(NIM_MODIFY, ctypes.byref(data))
        except (OSError, AttributeError):
            log.debug("Notification impossible", exc_info=True)

    def remove(self):
        if self.shown:
            try:
                ctypes.windll.shell32.Shell_NotifyIconW(NIM_DELETE, ctypes.byref(self._data(0)))
            except (OSError, AttributeError):
                pass
            self.shown = False


# --- progression sur le bouton de la barre des tâches (ITaskbarList3) ---

class TaskbarProgress:
    NONE, INDETERMINATE, NORMAL, ERROR, PAUSED = 0x0, 0x1, 0x2, 0x4, 0x8

    def __init__(self, hwnd):
        self.hwnd, self._ptr, self._last = hwnd, None, None
        try:
            ole32 = ctypes.windll.ole32
            ole32.CoInitialize(None)  # déjà initialisé par Tk : sans effet
            ptr = ctypes.c_void_p()
            clsid = GUID.parse("{56FDF344-FD6D-11D0-958A-006097C9A090}")  # CLSID_TaskbarList
            iid = GUID.parse("{EA1AFB91-9E28-4B86-90E9-9E9F8A5EEE6F}")  # IID_ITaskbarList3
            if ole32.CoCreateInstance(ctypes.byref(clsid), None, 1, ctypes.byref(iid), ctypes.byref(ptr)) == 0:
                self._ptr = ptr
                self._method(3)()  # HrInit
        except (OSError, AttributeError):
            self._ptr = None

    def _method(self, index, *argtypes):
        vtable = ctypes.cast(self._ptr, ctypes.POINTER(ctypes.POINTER(ctypes.c_void_p)))[0]
        proto = ctypes.WINFUNCTYPE(ctypes.c_long, ctypes.c_void_p, *argtypes)
        func = proto(vtable[index])
        return lambda *args: func(self._ptr, *args)

    def set(self, state, fraction=None):
        """state : NONE, INDETERMINATE, NORMAL, ERROR ou PAUSED ; fraction entre 0 et 1."""
        if not self._ptr:
            return
        value = None if fraction is None else round(max(0.0, min(1.0, fraction)) * 1000)
        if (state, value) == self._last:
            return
        self._last = (state, value)
        try:
            self._method(10, wintypes.HWND, ctypes.c_int)(self.hwnd, state)  # SetProgressState
            if value is not None and state != self.INDETERMINATE:
                self._method(9, wintypes.HWND, ctypes.c_ulonglong, ctypes.c_ulonglong)(self.hwnd, value, 1000)
        except OSError:
            self._ptr = None
