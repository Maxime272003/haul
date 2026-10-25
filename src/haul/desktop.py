"""Intégration au bureau Windows : instance unique, port occupé, démarrage avec Windows, icône de la
zone de notification et fichiers déposés sur la fenêtre.

Tout passe par l'API Win32 (ctypes). Chaque fonction échoue en douceur : hors de Windows, ou si un
appel est refusé, Haul fonctionne simplement sans ces commodités.
"""

import ctypes
import logging
import os
import sys
import threading
from ctypes import wintypes
from pathlib import Path

from .notify import NIF_ICON, NIF_INFO, NIF_TIP, NIIF_INFO, NIIF_LARGE_ICON, NIIF_USER, NIIF_WARNING, NOTIFYICONDATAW
from .paths import FROZEN

log = logging.getLogger(__name__)

MUTEX_NAME = "Local\\Haul-instance-unique"
ERROR_ALREADY_EXISTS = 183
RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
RUN_VALUE = "Haul"
MINIMIZED_ARG = "--minimized"

LRESULT = ctypes.c_ssize_t
WNDPROC = getattr(ctypes, "WINFUNCTYPE", ctypes.CFUNCTYPE)(LRESULT, wintypes.HWND, wintypes.UINT, wintypes.WPARAM,
                                                           wintypes.LPARAM)


def _dll(name):
    """Instance privée de la DLL : les argtypes posés ici ne touchent pas ctypes.windll (utilisé par Tk…)."""
    return ctypes.WinDLL(name, use_last_error=True)


# --- instance unique ---

def single_instance():
    """Retourne un objet à garder tant que l'application tourne, ou None si Haul est déjà lancé."""
    try:
        kernel32 = _dll("kernel32")
        kernel32.CreateMutexW.restype = wintypes.HANDLE
        kernel32.CreateMutexW.argtypes = [ctypes.c_void_p, wintypes.BOOL, wintypes.LPCWSTR]
        handle = kernel32.CreateMutexW(None, False, MUTEX_NAME)
        if handle and ctypes.get_last_error() == ERROR_ALREADY_EXISTS:
            kernel32.CloseHandle(handle)
            return None
        return handle or True
    except (OSError, AttributeError):
        return True  # pas de mutex possible : on ne bloque pas le lancement


def allow_foreground():
    """Autorise l'instance déjà lancée à passer au premier plan (sinon Windows fait juste clignoter son bouton)."""
    try:
        _dll("user32").AllowSetForegroundWindow(wintypes.DWORD(0xFFFFFFFF))  # ASFW_ANY
    except (OSError, AttributeError):
        pass


def bring_to_front(hwnd):
    try:
        user32 = _dll("user32")
        user32.SetForegroundWindow.argtypes = [wintypes.HWND]
        user32.SetForegroundWindow(hwnd)
    except (OSError, AttributeError):
        pass


# --- qui occupe le port du serveur local ---

def listening_pid(dwords, port):
    """PID qui écoute sur `port` d'après une table MIB_TCPTABLE_OWNER_PID lue comme une suite de DWORD."""
    count = dwords[0] if dwords else 0
    for i in range(min(count, (len(dwords) - 1) // 6)):
        _state, _addr, local_port, _raddr, _rport, pid = dwords[1 + 6 * i:7 + 6 * i]
        if ((local_port & 0xFF) << 8 | (local_port >> 8) & 0xFF) == port:  # ordre réseau
            return pid
    return None


def process_name(pid):
    try:
        kernel32 = _dll("kernel32")
        kernel32.OpenProcess.restype = wintypes.HANDLE
        kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        kernel32.QueryFullProcessImageNameW.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR,
                                                        ctypes.POINTER(wintypes.DWORD)]
        handle = kernel32.OpenProcess(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
        if not handle:
            return None
        try:
            size = wintypes.DWORD(1024)
            buf = ctypes.create_unicode_buffer(size.value)
            if kernel32.QueryFullProcessImageNameW(handle, 0, buf, ctypes.byref(size)):
                return os.path.basename(buf.value)
        finally:
            kernel32.CloseHandle(handle)
    except (OSError, AttributeError):
        pass
    return None


def port_owner(port):
    """« programme.exe (PID 1234) » qui écoute sur ce port TCP local, ou None."""
    try:
        iphlpapi = _dll("iphlpapi")
        iphlpapi.GetExtendedTcpTable.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.DWORD), wintypes.BOOL,
                                                 wintypes.ULONG, ctypes.c_int, wintypes.ULONG]
        size = wintypes.DWORD(0)
        for _ in range(3):  # la table peut grandir entre les deux appels
            buf = ctypes.create_string_buffer(max(size.value, 4))
            # AF_INET, TCP_TABLE_OWNER_PID_LISTENER
            if iphlpapi.GetExtendedTcpTable(buf, ctypes.byref(size), False, 2, 3, 0) == 0:
                dwords = (wintypes.DWORD * (len(buf) // 4)).from_buffer(buf)
                pid = listening_pid(list(dwords), port)
                if pid is None:
                    return None
                return f"{process_name(pid) or 'programme inconnu'} (PID {pid})"
    except (OSError, AttributeError):
        pass
    return None


# --- démarrage avec Windows ---

def autostart_command():
    """Commande lancée à l'ouverture de session : Haul réduit dans la zone de notification."""
    if FROZEN:
        return f'"{sys.executable}" {MINIMIZED_ARG}'
    pythonw = Path(sys.executable).with_name("pythonw.exe")
    return f'"{pythonw if pythonw.exists() else sys.executable}" -m haul {MINIMIZED_ARG}'


def autostart_enabled():
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY) as key:
            return bool(winreg.QueryValueEx(key, RUN_VALUE)[0])
    except (OSError, ImportError):
        return False


def set_autostart(enabled):
    """Ajoute ou retire Haul des programmes lancés à l'ouverture de session ; True si c'est fait."""
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_SET_VALUE) as key:
            if enabled:
                winreg.SetValueEx(key, RUN_VALUE, 0, winreg.REG_SZ, autostart_command())
            else:
                try:
                    winreg.DeleteValue(key, RUN_VALUE)
                except FileNotFoundError:
                    pass
        return True
    except (OSError, ImportError):
        log.warning("Démarrage avec Windows non modifiable", exc_info=True)
        return False


# --- icône de la zone de notification ---

class WNDCLASSW(ctypes.Structure):
    _fields_ = [("style", wintypes.UINT), ("lpfnWndProc", WNDPROC), ("cbClsExtra", ctypes.c_int),
                ("cbWndExtra", ctypes.c_int), ("hInstance", wintypes.HINSTANCE), ("hIcon", wintypes.HICON),
                ("hCursor", wintypes.HANDLE), ("hbrBackground", wintypes.HBRUSH), ("lpszMenuName", wintypes.LPCWSTR),
                ("lpszClassName", wintypes.LPCWSTR)]


WM_DESTROY, WM_CLOSE, WM_NULL = 0x0002, 0x0010, 0x0000
WM_LBUTTONUP, WM_LBUTTONDBLCLK, WM_RBUTTONUP = 0x0202, 0x0203, 0x0205
WM_TRAY = 0x8001  # WM_APP + 1
NIN_BALLOONUSERCLICK = 0x0405
NIF_MESSAGE = 0x1
NIM_ADD, NIM_MODIFY, NIM_DELETE = 0, 1, 2
MF_STRING, MF_GRAYED, MF_SEPARATOR = 0x0, 0x1, 0x800
TPM_RIGHTBUTTON, TPM_NONOTIFY, TPM_RETURNCMD = 0x2, 0x80, 0x100


class Tray:
    """Icône permanente de la zone de notification, avec son menu, dans un thread qui a sa propre fenêtre.

    on_command(clé) est appelé depuis ce thread (« open » pour un clic sur l'icône ou sur une
    notification, sinon la clé de l'entrée de menu choisie) : il doit seulement transmettre à l'interface.
    `items` est la liste [(clé, libellé, actif) ou None pour un séparateur], remplacée par l'interface.
    """

    CLASS_NAME = "HaulTray"

    def __init__(self, icon_path, tip, on_command):
        self.icon_path, self.tip, self.on_command = icon_path, tip, on_command
        self.items = [("open", "Afficher Haul", True)]
        self.hwnd = None
        self.icon = None
        self.ready = threading.Event()
        self._proc = WNDPROC(self._wndproc)  # gardé : sinon libéré pendant que Windows l'appelle
        threading.Thread(target=self._run, daemon=True).start()
        self.ready.wait(2)

    def _api(self):
        user32, shell32, kernel32 = _dll("user32"), _dll("shell32"), _dll("kernel32")
        user32.DefWindowProcW.restype = LRESULT
        user32.DefWindowProcW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
        user32.CreateWindowExW.restype = wintypes.HWND
        user32.CreateWindowExW.argtypes = [wintypes.DWORD, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD,
                                           ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int, wintypes.HWND,
                                           wintypes.HMENU, wintypes.HINSTANCE, ctypes.c_void_p]
        user32.RegisterClassW.argtypes = [ctypes.POINTER(WNDCLASSW)]
        user32.GetMessageW.argtypes = [ctypes.POINTER(wintypes.MSG), wintypes.HWND, wintypes.UINT, wintypes.UINT]
        user32.TranslateMessage.argtypes = [ctypes.POINTER(wintypes.MSG)]
        user32.DispatchMessageW.argtypes = [ctypes.POINTER(wintypes.MSG)]
        user32.PostMessageW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
        user32.CreatePopupMenu.restype = wintypes.HMENU
        user32.AppendMenuW.argtypes = [wintypes.HMENU, wintypes.UINT, ctypes.c_size_t, wintypes.LPCWSTR]
        user32.TrackPopupMenu.argtypes = [wintypes.HMENU, wintypes.UINT, ctypes.c_int, ctypes.c_int, ctypes.c_int,
                                          wintypes.HWND, ctypes.c_void_p]
        user32.DestroyMenu.argtypes = [wintypes.HMENU]
        user32.SetForegroundWindow.argtypes = [wintypes.HWND]
        user32.GetCursorPos.argtypes = [ctypes.POINTER(wintypes.POINT)]
        user32.DestroyWindow.argtypes = [wintypes.HWND]
        user32.LoadImageW.restype = wintypes.HANDLE
        user32.LoadImageW.argtypes = [wintypes.HINSTANCE, wintypes.LPCWSTR, wintypes.UINT, ctypes.c_int,
                                      ctypes.c_int, wintypes.UINT]
        user32.RegisterWindowMessageW.argtypes = [wintypes.LPCWSTR]
        shell32.Shell_NotifyIconW.argtypes = [wintypes.DWORD, ctypes.POINTER(NOTIFYICONDATAW)]
        kernel32.GetModuleHandleW.restype = wintypes.HMODULE
        kernel32.GetModuleHandleW.argtypes = [wintypes.LPCWSTR]
        return user32, shell32, kernel32

    def _run(self):
        try:
            self.user32, self.shell32, kernel32 = self._api()
            hinstance = kernel32.GetModuleHandleW(None)
            wc = WNDCLASSW()
            wc.lpfnWndProc = self._proc
            wc.hInstance = hinstance
            wc.lpszClassName = self.CLASS_NAME
            self.user32.RegisterClassW(ctypes.byref(wc))  # déjà enregistrée après un arrêt / redémarrage : sans effet
            self.hwnd = self.user32.CreateWindowExW(0, self.CLASS_NAME, "Haul", 0, 0, 0, 0, 0, None, None,
                                                    hinstance, None)
            if not self.hwnd:
                raise OSError("CreateWindowExW")
            # Explorer redémarré : l'icône est à recréer
            self.taskbar_created = self.user32.RegisterWindowMessageW("TaskbarCreated")
            if self.icon_path:
                self.icon = self.user32.LoadImageW(None, str(self.icon_path), 1, 0, 0, 0x10 | 0x40)
            self._add()
        except (OSError, AttributeError):
            log.warning("Icône de la zone de notification impossible", exc_info=True)
            self.hwnd = None
            self.ready.set()
            return
        self.ready.set()
        msg = wintypes.MSG()
        while self.user32.GetMessageW(ctypes.byref(msg), None, 0, 0) > 0:
            self.user32.TranslateMessage(ctypes.byref(msg))
            self.user32.DispatchMessageW(ctypes.byref(msg))

    def _data(self, flags):
        data = NOTIFYICONDATAW()
        data.cbSize = ctypes.sizeof(NOTIFYICONDATAW)
        data.hWnd, data.uID, data.uFlags, data.hIcon = self.hwnd, 1, flags, self.icon
        data.uCallbackMessage = WM_TRAY
        data.szTip = self.tip[:127]
        return data

    def _add(self):
        self.shell32.Shell_NotifyIconW(NIM_ADD, ctypes.byref(self._data(NIF_MESSAGE | NIF_ICON | NIF_TIP)))

    def _wndproc(self, hwnd, msg, wparam, lparam):
        try:
            if msg == WM_TRAY:
                event = lparam & 0xFFFF
                if event in (WM_LBUTTONUP, WM_LBUTTONDBLCLK, NIN_BALLOONUSERCLICK):
                    self.on_command("open")
                elif event == WM_RBUTTONUP:
                    self._menu(hwnd)
                return 0
            if msg == getattr(self, "taskbar_created", None):
                self._add()
                return 0
            if msg == WM_CLOSE:
                self.user32.DestroyWindow(hwnd)
                return 0
            if msg == WM_DESTROY:
                data = self._data(0)
                data.hWnd = hwnd  # stop() a déjà oublié self.hwnd
                self.shell32.Shell_NotifyIconW(NIM_DELETE, ctypes.byref(data))
                self.user32.PostQuitMessage(0)
                return 0
        except Exception:
            log.exception("Zone de notification")
        return self.user32.DefWindowProcW(hwnd, msg, wparam, lparam)

    def _menu(self, hwnd):
        items = list(self.items)
        menu = self.user32.CreatePopupMenu()
        try:
            for i, item in enumerate(items, start=1):
                if item is None:
                    self.user32.AppendMenuW(menu, MF_SEPARATOR, 0, None)
                else:
                    self.user32.AppendMenuW(menu, MF_STRING | (0 if item[2] else MF_GRAYED), i, item[1])
            pt = wintypes.POINT()
            self.user32.GetCursorPos(ctypes.byref(pt))
            self.user32.SetForegroundWindow(hwnd)  # sinon le menu ne se ferme pas en cliquant ailleurs
            choice = self.user32.TrackPopupMenu(menu, TPM_RIGHTBUTTON | TPM_NONOTIFY | TPM_RETURNCMD, pt.x, pt.y, 0,
                                                hwnd, None)
            self.user32.PostMessageW(hwnd, WM_NULL, 0, 0)
        finally:
            self.user32.DestroyMenu(menu)
        if choice and items[choice - 1]:
            self.on_command(items[choice - 1][0])

    def balloon(self, title, text, warning=False):
        """Notification Windows attachée à l'icône."""
        if not self.hwnd:
            return False
        try:
            data = self._data(NIF_ICON | NIF_TIP | NIF_INFO | NIF_MESSAGE)
            data.szInfoTitle, data.szInfo = title[:63], text[:255]
            data.dwInfoFlags = NIIF_WARNING if warning else (NIIF_USER | NIIF_LARGE_ICON if self.icon else NIIF_INFO)
            return bool(self.shell32.Shell_NotifyIconW(NIM_MODIFY, ctypes.byref(data)))
        except (OSError, AttributeError):
            return False

    def stop(self):
        if self.hwnd:
            try:
                self.user32.PostMessageW(self.hwnd, WM_CLOSE, 0, 0)
            except (OSError, AttributeError):
                pass
            self.hwnd = None


# --- fichiers déposés sur la fenêtre ---

WM_DROPFILES = 0x0233
GWLP_WNDPROC = -4


class FileDrop:
    """Accepte les fichiers déposés sur une fenêtre Tk ; on_drop(chemins) est appelé dans le thread de Tk."""

    def __init__(self, widget, on_drop):
        self.on_drop = on_drop
        self._old = None
        try:
            self.user32, self.shell32 = _dll("user32"), _dll("shell32")
            self.user32.SetWindowLongPtrW.restype = ctypes.c_void_p
            self.user32.SetWindowLongPtrW.argtypes = [wintypes.HWND, ctypes.c_int, ctypes.c_void_p]
            self.user32.CallWindowProcW.restype = LRESULT
            self.user32.CallWindowProcW.argtypes = [ctypes.c_void_p, wintypes.HWND, wintypes.UINT, wintypes.WPARAM,
                                                    wintypes.LPARAM]
            self.shell32.DragAcceptFiles.argtypes = [wintypes.HWND, wintypes.BOOL]
            self.shell32.DragQueryFileW.argtypes = [wintypes.HANDLE, wintypes.UINT, wintypes.LPWSTR, wintypes.UINT]
            self.shell32.DragFinish.argtypes = [wintypes.HANDLE]
            self.hwnd = widget.winfo_id()
            self._proc = WNDPROC(self._wndproc)  # gardé : sinon libéré pendant que Windows l'appelle
            self.shell32.DragAcceptFiles(self.hwnd, True)
            self._old = self.user32.SetWindowLongPtrW(self.hwnd, GWLP_WNDPROC,
                                                      ctypes.cast(self._proc, ctypes.c_void_p))
        except (OSError, AttributeError, ctypes.ArgumentError):
            log.info("Glisser-déposer indisponible", exc_info=True)
            self._old = None

    def _wndproc(self, hwnd, msg, wparam, lparam):
        if msg == WM_DROPFILES:
            try:
                count = self.shell32.DragQueryFileW(wparam, 0xFFFFFFFF, None, 0)
                paths = []
                for i in range(count):
                    length = self.shell32.DragQueryFileW(wparam, i, None, 0)
                    buf = ctypes.create_unicode_buffer(length + 1)
                    self.shell32.DragQueryFileW(wparam, i, buf, length + 1)
                    paths.append(buf.value)
                self.shell32.DragFinish(wparam)
                self.on_drop(paths)
            except Exception:
                log.exception("Fichiers déposés")
            return 0
        return self.user32.CallWindowProcW(self._old, hwnd, msg, wparam, lparam)
