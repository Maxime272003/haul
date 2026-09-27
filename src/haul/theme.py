"""Apparence de Haul : palette claire ou sombre (celle de Windows), polices et styles ttk.

Les formes arrondies (cartes, boutons, champs, interrupteurs, icônes d'état) sont dessinées ici
en PNG avec anticrénelage : aucune bibliothèque ni aucun fichier image n'est nécessaire.
"""

import base64
import math
import struct
import tkinter as tk
import zlib
from tkinter import font as tkfont
from tkinter import ttk

LIGHT = {
    "bg": "#F3F5F9", "card": "#FFFFFF", "border": "#E2E6ED", "border_hover": "#C5CCD8",
    "text": "#1B2230", "muted": "#667085", "faint": "#A3ABBA", "disabled": "#A9B1BF",
    "accent": "#2163D6", "accent_hover": "#1B56BD", "accent_pressed": "#174AA3", "accent_soft": "#E6EEFC",
    "on_accent": "#FFFFFF",
    "button": "#FFFFFF", "button_hover": "#F1F4F8", "button_pressed": "#E4E8EF",
    "field": "#FFFFFF", "track": "#C6CDD8", "track_hover": "#B2BAC7", "ring": "#DCE1E8",
    "thumb": "#CBD2DC", "thumb_hover": "#A9B2C1",
    "green": "#1E9E5A", "amber": "#D98E04", "red": "#D93F3F", "violet": "#7C4DDB",
    "tooltip": "#1B2230", "on_tooltip": "#FFFFFF",
}
DARK = {
    "bg": "#14171D", "card": "#1C2028", "border": "#2B313C", "border_hover": "#3D4553",
    "text": "#E7EAF0", "muted": "#8E97A8", "faint": "#5E6778", "disabled": "#5A6272",
    "accent": "#3A7BEF", "accent_hover": "#5089F2", "accent_pressed": "#2E68D0", "accent_soft": "#243453",
    "on_accent": "#FFFFFF",
    "button": "#252A34", "button_hover": "#2D333F", "button_pressed": "#363D4B",
    "field": "#16191F", "track": "#454D5B", "track_hover": "#545D6D", "ring": "#343B47",
    "thumb": "#3A414E", "thumb_hover": "#4E5666",
    "green": "#3CC47A", "amber": "#EFB02E", "red": "#F06262", "violet": "#A286F2",
    "tooltip": "#E7EAF0", "on_tooltip": "#14171D",
}

SPINNER_FRAMES = 12
TILE = 192  # taille du centre uniforme des images à bords (voir png)


def system_prefers_dark():
    """Mode sombre des applications Windows (Paramètres > Personnalisation > Couleurs)."""
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                            r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize") as key:
            return winreg.QueryValueEx(key, "AppsUseLightTheme")[0] == 0
    except (ImportError, OSError):
        return False


# --- dessin : formes décrites par leur distance signée (négative à l'intérieur), en pixels ---

def rounded_rect(x0, y0, x1, y1, r):
    cx, cy, hw, hh = (x0 + x1) / 2, (y0 + y1) / 2, (x1 - x0) / 2, (y1 - y0) / 2
    r = min(r, hw, hh)

    def sdf(x, y):
        qx, qy = abs(x - cx) - hw + r, abs(y - cy) - hh + r
        return math.hypot(max(qx, 0), max(qy, 0)) + min(max(qx, qy), 0) - r
    return sdf


def circle(cx, cy, r):
    return lambda x, y: math.hypot(x - cx, y - cy) - r


def arc(cx, cy, r, width, start=0.0, end=1.0):
    """Anneau de `start` à `end` (fractions de tour, sens horaire depuis midi), bouts arrondis."""
    ends = [(cx + r * math.sin(2 * math.pi * t), cy - r * math.cos(2 * math.pi * t)) for t in (start, end)]

    def sdf(x, y):
        ring = abs(math.hypot(x - cx, y - cy) - r) - width / 2
        if end - start >= 1 or (math.atan2(x - cx, cy - y) / (2 * math.pi) - start) % 1 <= end - start:
            return ring
        return min(math.hypot(x - ex, y - ey) for ex, ey in ends) - width / 2
    return sdf


def segment(ax, ay, bx, by, width):
    def sdf(x, y):
        dx, dy = bx - ax, by - ay
        t = max(0.0, min(1.0, ((x - ax) * dx + (y - ay) * dy) / (dx * dx + dy * dy)))
        return math.hypot(x - ax - t * dx, y - ay - t * dy) - width / 2
    return sdf


def union(*shapes):
    return lambda x, y: min(f(x, y) for f in shapes)


def _rgb(color):
    return tuple(int(color[i:i + 2], 16) for i in (1, 3, 5))


def png(width, height, layers, grow=(0, 0)):
    """PNG RGBA : `layers` = [(forme, couleur)], superposées du fond vers le dessus.

    `grow` (gx, gy) élargit l'image en répétant sa colonne et sa ligne centrales : Ttk répète en
    mosaïque le centre des images à bords (`border`), un centre trop petit rendrait l'affichage lent.
    """
    layers = [(shape, _rgb(color)) for shape, color in layers]
    rows = []
    for j in range(height):
        row = []
        for i in range(width):
            x, y = i + 0.5, j + 0.5
            r = g = b = a = 0.0  # couleur prémultipliée
            for shape, (cr, cg, cb) in layers:
                k = min(1.0, max(0.0, 0.5 - shape(x, y)))  # part du pixel couverte
                if k:
                    r, g, b, a = cr * k + r * (1 - k), cg * k + g * (1 - k), cb * k + b * (1 - k), k + a * (1 - k)
            row.append(bytes((round(r / a), round(g / a), round(b / a), round(a * 255))) if a else b"\0\0\0\0")
        mid = width // 2
        rows.append(b"".join(row[:mid] + row[mid:mid + 1] * grow[0] + row[mid:]))
    mid = height // 2
    rows = rows[:mid] + rows[mid:mid + 1] * grow[1] + rows[mid:]
    width, height = width + grow[0], height + grow[1]
    raw = b"".join(b"\0" + row for row in rows)  # filtre PNG « aucun » pour chaque ligne

    def chunk(tag, data):
        return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", zlib.crc32(tag + data))
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(raw)) + chunk(b"IEND", b""))


class Theme:
    """Styles ttk de l'application. `c` : palette, `px(n)` : n pixels à 96 ppp, mis à l'échelle."""

    def __init__(self, root, mode="system"):
        self.root = root
        self.dark = mode == "dark" or (mode == "system" and system_prefers_dark())
        self.c = DARK if self.dark else LIGHT
        self.scale = root.winfo_fpixels("1i") / 96
        self._images = {}
        self._fonts()
        self._styles()

    def px(self, n):
        return max(1, round(n * self.scale))

    def image(self, key, width, height, layers, grow=(0, 0)):
        if key not in self._images:
            data = base64.b64encode(png(width, height, layers, grow))
            self._images[key] = tk.PhotoImage(master=self.root, data=data)
        return self._images[key]

    # --- fenêtres ---

    def decorate(self, window):
        """Barre de titre Windows assortie : sombre en mode sombre, couleur du fond sur Windows 11."""
        window.configure(background=self.c["bg"])
        try:
            from ctypes import byref, c_int, sizeof, windll
            window.update_idletasks()
            hwnd = windll.user32.GetParent(window.winfo_id())
            for attr, value in ((20, int(self.dark)),  # DWMWA_USE_IMMERSIVE_DARK_MODE
                                (35, self._colorref("bg")),  # DWMWA_CAPTION_COLOR
                                (36, self._colorref("text"))):  # DWMWA_TEXT_COLOR
                v = c_int(value)
                windll.dwmapi.DwmSetWindowAttribute(hwnd, attr, byref(v), sizeof(v))
        except (ImportError, AttributeError, OSError):
            pass

    def _colorref(self, name):
        r, g, b = _rgb(self.c[name])
        return r | g << 8 | b << 16

    def menu(self, master):
        c = self.c
        return tk.Menu(master, tearoff=False, background=c["card"], foreground=c["text"],
                       activebackground=c["accent_soft"], activeforeground=c["text"],
                       disabledforeground=c["disabled"], relief="flat", borderwidth=0)

    # --- icônes ---

    def status_icon(self, kind, fraction=None, frame=0):
        """Icône d'état d'un fichier : anneau de progression, coche, alerte…"""
        c, s, gap = self.c, self.px(16), self.px(8)
        cx = cy = s / 2
        r, w = s / 2 - self.px(2), max(1.6, 2 * self.scale)
        if kind == "download" and fraction is not None:
            step = round(max(0.0, min(1.0, fraction)) * 40)  # 40 images au plus
            key, layers = f"dl{step}", [(arc(cx, cy, r, w), c["ring"])]
            if step:
                layers.append((arc(cx, cy, r, w, 0, step / 40), c["accent"]))
        elif kind in ("download", "busy"):  # durée inconnue : arc qui tourne
            start = (frame % SPINNER_FRAMES) / SPINNER_FRAMES
            color = c["accent"] if kind == "download" else c["violet"]
            key = f"{kind}{frame % SPINNER_FRAMES}"
            layers = [(arc(cx, cy, r, w), c["ring"]), (arc(cx, cy, r, w, start, start + 0.3), color)]
        elif kind == "done":
            k = s / 16
            key, layers = "done", [(circle(cx, cy, r + w / 2), c["green"]),
                                   (union(segment(5 * k, 8.3 * k, 7.1 * k, 10.4 * k, 1.8 * k),
                                          segment(7.1 * k, 10.4 * k, 11 * k, 6 * k, 1.8 * k)), "#FFFFFF")]
        elif kind == "error":
            k = s / 16
            key, layers = "error", [(circle(cx, cy, r + w / 2), c["red"]),
                                    (union(segment(cx, 4.6 * k, cx, 8.6 * k, 1.9 * k),
                                           circle(cx, 11.2 * k, 1.05 * k)), "#FFFFFF")]
        elif kind == "browser":
            key, layers = "browser", [(arc(cx, cy, r, w), c["amber"]), (circle(cx, cy, r / 2.4), c["amber"])]
        else:  # en attente
            key, layers = "wait", [(arc(cx, cy, r, w), c["ring"])]
        # marge à droite : l'icône précède le nom du fichier
        return self.image("st-" + key, s + gap, s, layers)

    def dot(self, color_name):
        """Pastille de couleur, aux dimensions des icônes d'état pour que le texte reste aligné."""
        s = self.px(16)
        layers = [(circle(s / 2, s / 2, self.px(4)), self.c[color_name])]
        return self.image("dot-" + color_name, s + self.px(8), s, layers)

    # --- polices ---

    def _fonts(self):
        families = set(tkfont.families(self.root))
        base = "Segoe UI" if "Segoe UI" in families else tkfont.nametofont("TkDefaultFont").actual("family")
        semi = "Segoe UI Semibold" if "Segoe UI Semibold" in families else base
        weight = "normal" if semi != base else "bold"
        for name in ("TkDefaultFont", "TkTextFont", "TkMenuFont", "TkHeadingFont", "TkTooltipFont"):
            tkfont.nametofont(name).configure(family=base, size=10, weight="normal")
        self.font = tkfont.nametofont("TkDefaultFont")
        self.font_small = tkfont.Font(self.root, family=base, size=9)
        self.font_semibold = tkfont.Font(self.root, family=semi, size=10, weight=weight)
        self.font_caption = tkfont.Font(self.root, family=semi, size=8, weight=weight)
        self.font_heading = tkfont.Font(self.root, family=semi, size=12, weight=weight)
        self.font_title = tkfont.Font(self.root, family=semi, size=18, weight=weight)
        self.font_mono = tkfont.Font(self.root, family="Consolas", size=10)

    # --- styles ttk ---

    def _styles(self):
        c, px = self.c, self.px
        s = self.style = ttk.Style(self.root)
        name = "haul-dark" if self.dark else "haul-light"
        if name not in s.theme_names():
            s.theme_create(name, parent="clam")
        s.theme_use(name)
        self.root.configure(background=c["bg"])

        s.configure(".", background=c["bg"], foreground=c["text"], bordercolor=c["border"],
                    lightcolor=c["bg"], darkcolor=c["bg"], troughcolor=c["bg"], focuscolor=c["bg"],
                    selectbackground=c["accent_soft"], selectforeground=c["text"],
                    insertcolor=c["text"], font=self.font, relief="flat")
        s.map(".", background=[], foreground=[("disabled", c["disabled"])],
              selectbackground=[], selectforeground=[])

        # surfaces et textes
        s.configure("TFrame", background=c["bg"])
        s.configure("Surface.TFrame", background=c["card"])
        s.configure("Line.TFrame", background=c["border"])
        r = px(10)
        n = 2 * r + 2
        card = self.image("card", n, n, [(rounded_rect(0, 0, n, n, r), c["border"]),
                                         (rounded_rect(1, 1, n - 1, n - 1, r - 1), c["card"])], (TILE, TILE))
        s.element_create("Card.bg", "image", card, border=r, sticky="nsew", width=n, height=n)
        s.layout("Card.TFrame", [("Card.bg", {"sticky": "nsew"})])

        for style, bg, fg, font in (
            ("TLabel", "bg", "text", self.font),
            ("Muted.TLabel", "bg", "muted", self.font),
            ("Title.TLabel", "bg", "text", self.font_title),
            ("Heading.TLabel", "bg", "text", self.font_heading),
            ("Speed.TLabel", "bg", "accent", self.font_semibold),
            ("Surface.TLabel", "card", "text", self.font),
            ("SurfaceMuted.TLabel", "card", "muted", self.font),
            ("Caption.TLabel", "card", "muted", self.font_caption),
            ("Value.TLabel", "card", "text", self.font_semibold),
            ("EmptyTitle.TLabel", "card", "text", self.font_heading),
        ):
            s.configure(style, background=c[bg], foreground=c[fg], font=font)

        # boutons
        self._button("Accent", c["accent"], None, c["accent_hover"], c["accent_pressed"], c["border"])
        self._button("Button", c["button"], c["border"], c["button_hover"], c["button_pressed"], c["button"],
                     border_hover=c["border_hover"])
        for style, element, fg, font, pad in (
            ("Accent.TButton", "Accent.bg", c["on_accent"], self.font_semibold, (px(16), px(6))),
            ("TButton", "Button.bg", c["text"], self.font, (px(14), px(6))),
            ("Icon.TButton", "Button.bg", c["text"], self.font_semibold, (px(4), px(1))),
        ):
            s.layout(style, [(element, {"sticky": "nsew", "children": [
                ("Button.padding", {"sticky": "nsew", "children": [("Button.label", {"sticky": "nsew"})]})]})])
            s.configure(style, foreground=fg, font=font, padding=pad, anchor="center")
            s.map(style, foreground=[("disabled", c["disabled"])])

        # champ de saisie
        r = px(6)
        n = 2 * r + 4
        fields = [self.image(f"field-{state}", n, n, [
            (rounded_rect(0, 0, n, n, r), color),
            (rounded_rect(bw, bw, n - bw, n - bw, r - bw), c["field"])], (TILE, TILE))
            for state, color, bw in (("rest", c["border"], 1), ("hover", c["border_hover"], 1),
                                     ("focus", c["accent"], max(1.5, 1.5 * self.scale)))]
        s.element_create("Round.field", "image", fields[0], ("focus", fields[2]), ("hover", fields[1]),
                         border=r + 2, padding=(px(10), px(7)), sticky="nsew", width=n, height=n)
        s.layout("TEntry", [("Round.field", {"sticky": "nsew", "children": [
            ("Entry.padding", {"sticky": "nsew", "children": [("Entry.textarea", {"sticky": "nsew"})]})]})])
        s.configure("TEntry", padding=0, foreground=c["text"], insertcolor=c["text"])

        # interrupteurs (Checkbutton)
        w, h, pad = px(34), px(20), px(3)
        switches = {}
        for on in (False, True):
            for hover in (False, True):
                track = (c["accent_hover"] if hover else c["accent"]) if on else (
                    c["track_hover"] if hover else c["track"])
                kx = w - h / 2 if on else h / 2
                switches[on, hover] = self.image(f"switch-{on}-{hover}", w + px(10), h, [
                    (rounded_rect(0, 0, w, h, h / 2), track), (circle(kx, h / 2, h / 2 - pad), "#FFFFFF")])
        s.element_create("Switch.indicator", "image", switches[False, False],
                         ("selected active", switches[True, True]), ("selected", switches[True, False]),
                         ("active", switches[False, True]), sticky="")
        s.layout("Switch.TCheckbutton", [("Checkbutton.padding", {"sticky": "nsew", "children": [
            ("Switch.indicator", {"side": "left", "sticky": ""}),
            ("Checkbutton.label", {"side": "left", "sticky": "w"})]})])
        s.configure("Switch.TCheckbutton", background=c["card"], foreground=c["text"], padding=(0, px(2)))

        # tableau
        rowheight = max(self.font.metrics("linespace") + px(16), px(34))
        s.configure("Treeview", background=c["card"], fieldbackground=c["card"], foreground=c["text"],
                    bordercolor=c["card"], lightcolor=c["card"], darkcolor=c["card"], borderwidth=0,
                    rowheight=rowheight, font=self.font)
        s.map("Treeview", background=[("selected", c["accent_soft"])], foreground=[("selected", c["text"])])
        s.configure("Treeview.Heading", background=c["card"], foreground=c["muted"], font=self.font_caption,
                    bordercolor=c["card"], lightcolor=c["card"], darkcolor=c["card"], borderwidth=0,
                    padding=(px(6), px(8)))
        s.map("Treeview.Heading", background=[], foreground=[])
        s.configure("Treeview.Item", padding=(px(8), 0))
        s.layout("Treeview.Item", [("Treeitem.padding", {"sticky": "nsew", "children": [
            ("Treeitem.image", {"side": "left", "sticky": ""}),
            ("Treeitem.text", {"side": "left", "sticky": "w"})]})])

        # barres de défilement fines, sans flèches
        for orient, vertical in (("Vertical", True), ("Horizontal", False)):
            thick, rr = px(12), px(3)
            long_ = 2 * px(6) + 2
            thumbs = []
            for state in ("thumb", "thumb_hover"):
                w, h = (thick, long_) if vertical else (long_, thick)
                shape = (rounded_rect(px(3), 0, w - px(3), h, rr) if vertical
                         else rounded_rect(0, px(3), w, h - px(3), rr))
                grow = (0, TILE) if vertical else (TILE, 0)
                thumbs.append(self.image(f"{orient}-{state}", w, h, [(shape, c[state])], grow))
            border = (0, px(6), 0, px(6)) if vertical else (px(6), 0, px(6), 0)
            s.element_create(f"{orient}.Scrollbar.thumb", "image", thumbs[0],
                             ("pressed", thumbs[1]), ("active", thumbs[1]), border=border, sticky="nsew",
                             width=w, height=h)
            s.layout(f"{orient}.TScrollbar", [(f"{orient}.Scrollbar.trough", {
                "sticky": "ns" if vertical else "ew",
                "children": [(f"{orient}.Scrollbar.thumb", {"expand": "1", "sticky": "nsew"})]})])
            s.configure(f"{orient}.TScrollbar", troughcolor=c["card"], background=c["card"],
                        bordercolor=c["card"], lightcolor=c["card"], darkcolor=c["card"], gripcount=0)

    def _button(self, name, fill, border, hover, pressed, disabled, border_hover=None):
        r = self.px(6)
        n = 2 * r + 4

        def img(state, color, edge):
            layers = [(rounded_rect(0, 0, n, n, r), edge)] if edge else []
            inset = 1 if edge else 0
            layers.append((rounded_rect(inset, inset, n - inset, n - inset, r - inset), color))
            return self.image(f"{name}-{state}", n, n, layers, (TILE // 2, TILE // 4))

        self.style.element_create(
            f"{name}.bg", "image", img("rest", fill, border),
            ("disabled", img("disabled", disabled, border)),
            ("pressed", img("pressed", pressed, border_hover or border)),
            ("active", img("hover", hover, border_hover or border)),
            border=r + 1, sticky="nsew", width=n, height=n)
