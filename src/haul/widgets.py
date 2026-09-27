"""Petits composants de l'interface : disposition fluide, sélecteur numérique, infobulles."""

import tkinter as tk
from tkinter import ttk


class Flow(ttk.Frame):
    """Aligne ses enfants à la suite et passe à la ligne quand la largeur manque : rien n'est coupé."""

    def __init__(self, master, gap=8, row_gap=8, **kw):
        super().__init__(master, **kw)
        self.gap, self.row_gap, self.items = gap, row_gap, []
        self._pending = False
        self.bind("<Configure>", self._schedule)

    def add(self, *widgets):
        for widget in widgets:
            self.items.append(widget)
            widget.bind("<Configure>", self._schedule, add="+")  # taille du texte changée, etc.
        self._schedule()

    def _schedule(self, _event=None):
        if not self._pending:
            self._pending = True
            self.after_idle(self._reflow)

    def _reflow(self):
        self._pending = False
        sizes = [(w.winfo_reqwidth(), w.winfo_reqheight()) for w in self.items]
        width = self.winfo_width()
        if width <= 1:  # pas encore affiché : une seule ligne
            width = sum(w for w, _ in sizes) + self.gap * len(sizes)
        lines, line, x = [], [], 0
        for item, (w, h) in zip(self.items, sizes, strict=True):
            if line and x + w > width:
                lines.append(line)
                line, x = [], 0
            line.append((item, h))
            x += w + self.gap
        if line:
            lines.append(line)
        y = 0
        for line in lines:
            line_height = max(h for _, h in line)
            x = 0
            for item, h in line:
                item.place(x=x, y=y + (line_height - h) // 2)
                x += item.winfo_reqwidth() + self.gap
            y += line_height + self.row_gap
        height = max(1, y - self.row_gap)
        min_width = max((w for w, _ in sizes), default=1)
        if (int(self.cget("height")), int(self.cget("width"))) != (height, min_width):
            self.configure(height=height, width=min_width)


class Stepper(ttk.Frame):
    """Nombre entier entre `lo` et `hi`, réglé avec les boutons − et + ou la molette."""

    def __init__(self, master, variable, lo, hi, command=None, **kw):
        super().__init__(master, **kw)
        self.var, self.lo, self.hi, self.command = variable, lo, hi, command
        self.minus = ttk.Button(self, text="−", width=2, style="Icon.TButton", command=lambda: self.step(-1))
        value = ttk.Label(self, textvariable=variable, width=3, anchor="center", style="Value.TLabel")
        self.plus = ttk.Button(self, text="+", width=2, style="Icon.TButton", command=lambda: self.step(1))
        self.minus.grid(row=0, column=0)
        value.grid(row=0, column=1)
        self.plus.grid(row=0, column=2)
        for widget in (self, value, self.minus, self.plus):
            widget.bind("<MouseWheel>", lambda e: self.step(1 if e.delta > 0 else -1))
        self.step(0)

    def get(self):
        try:
            return max(self.lo, min(self.hi, int(self.var.get())))
        except ValueError:
            return self.lo

    def step(self, delta):
        value = max(self.lo, min(self.hi, self.get() + delta))
        if str(value) != self.var.get():
            self.var.set(str(value))
            if self.command:
                self.command()
        self.minus.state(["disabled" if value <= self.lo else "!disabled"])
        self.plus.state(["disabled" if value >= self.hi else "!disabled"])


class Tooltip:
    """Petite bulle de texte sous le pointeur."""

    def __init__(self, master, theme):
        self.master, self.theme, self.window = master, theme, None

    def show(self, text, x, y):
        self.hide()
        c, px = self.theme.c, self.theme.px
        self.window = tw = tk.Toplevel(self.master)
        tw.wm_overrideredirect(True)
        tw.attributes("-topmost", True)
        tk.Label(tw, text=text, background=c["tooltip"], foreground=c["on_tooltip"], font=self.theme.font_small,
                 padx=px(9), pady=px(5), justify="left", wraplength=px(520)).pack()
        tw.update_idletasks()
        # reste dans l'écran
        x = min(x + px(12), tw.winfo_screenwidth() - tw.winfo_reqwidth() - px(4))
        y = y + px(18)
        if y + tw.winfo_reqheight() > tw.winfo_screenheight():
            y -= tw.winfo_reqheight() + px(26)
        tw.geometry(f"+{x}+{y}")

    def hide(self, _event=None):
        if self.window:
            self.window.destroy()
            self.window = None


class CellTooltip(Tooltip):
    """Affiche le texte complet d'une cellule de Treeview quand il ne tient pas dans la colonne."""

    def __init__(self, tree, theme, delay=400):
        super().__init__(tree, theme)
        self.tree, self.delay = tree, delay
        self.cell, self.after_id = None, None
        tree.bind("<Motion>", self._motion, add="+")
        tree.bind("<Leave>", self._leave, add="+")
        tree.bind("<ButtonPress>", self._leave, add="+")
        tree.bind("<MouseWheel>", self._leave, add="+")

    def _motion(self, event):
        cell = (self.tree.identify_row(event.y), self.tree.identify_column(event.x))
        if cell == self.cell:
            return
        self._leave()
        self.cell = cell
        if cell[0] and self.tree.identify_region(event.x, event.y) in ("tree", "cell"):
            self.after_id = self.tree.after(self.delay, self._maybe_show, event.x_root, event.y_root)

    def _leave(self, _event=None):
        if self.after_id:
            self.tree.after_cancel(self.after_id)
            self.after_id = None
        self.cell = None
        self.hide()

    def _maybe_show(self, x, y):
        self.after_id = None
        iid, column = self.cell or (None, None)
        if not iid or not self.tree.exists(iid):
            return
        width = int(self.tree.column(column, "width"))
        if column == "#0":
            text = self.tree.item(iid, "text")
            image = self.tree.item(iid, "image")
            width -= self.theme.px(16) + (int(self.tree.tk.call("image", "width", image[0])) if image else 0)
        else:
            text = self.tree.set(iid, column)
            width -= self.theme.px(10)
        if text and self.theme.font.measure(text) > width:
            self.show(text, x, y)
