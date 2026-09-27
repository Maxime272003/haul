"""Génère l'icône de Haul (haul.ico + haul.png) : flèche blanche sur carré arrondi bleu."""

from pathlib import Path

from PIL import Image, ImageDraw

ASSETS = Path(__file__).resolve().parent.parent / "src" / "haul" / "assets"

S = 256
img = Image.new("RGBA", (S, S), (0, 0, 0, 0))
d = ImageDraw.Draw(img)
d.rounded_rectangle((8, 8, S - 8, S - 8), radius=52, fill=(33, 99, 214))
white = (255, 255, 255)
d.rectangle((108, 48, 148, 140), fill=white)                   # tige
d.polygon([(64, 128), (192, 128), (128, 194)], fill=white)     # pointe
d.rounded_rectangle((60, 204, 196, 222), radius=9, fill=white)  # socle
img.save(ASSETS / "haul.ico", sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)])
img.save(ASSETS / "haul.png")
print(f"Icônes écrites dans {ASSETS}")
