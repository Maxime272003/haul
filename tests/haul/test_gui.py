import struct
import zlib

from haul.engine import Job
from haul.gui import App, plural, status_kind
from haul.theme import arc, circle, png, rounded_rect


def test_status_kind_covers_engine_and_postprocess_statuses():
    assert status_kind("En attente") == "wait"
    assert status_kind("En attente de téléchargement") == "wait"
    assert status_kind("Dans le navigateur : valide le captcha si demandé") == "browser"
    assert status_kind("Connexion au serveur…") == "busy"
    assert status_kind("Téléchargement (8 connexions)") == "download"
    assert status_kind("Terminé") == status_kind("Déjà présent") == status_kind("Extrait ✔") == "done"
    assert status_kind("Extraction…") == "busy"
    for failed in ("Erreur : aucun lien reçu", "Échec extraction (code 3)", "Extraction bloquée"):
        assert status_kind(failed) == "error"


def test_plural():
    assert plural(1, "fichier") == "1 fichier"
    assert plural(3, "fichier") == "3 fichiers"
    assert plural(2, "lien ajouté", "liens ajoutés") == "2 liens ajoutés"


def test_row_progress_and_speed():
    job = Job(id=1, url="u", dest=".", name="a.rar", status="Téléchargement (8 connexions)",
              done=312 << 20, total=500 << 20, speed=5 << 20)
    assert App._row(job) == ("Téléchargement (8 connexions)", "62 %  ·  312.0 / 500.0 Mo", "5.0 Mo/s", "")
    job.total = 3 << 30  # unités différentes : les deux sont affichées
    assert App._row(job)[1] == "10 %  ·  312.0 Mo / 3.0 Go"
    job.status, job.done, job.total = "Terminé", 500 << 20, 500 << 20
    assert App._row(job)[1:3] == ("500.0 Mo", "")  # plus de vitesse une fois terminé


def _decode(data):
    """Pixels RGBA d'un PNG produit par theme.png (filtre « aucun » sur chaque ligne)."""
    assert data.startswith(b"\x89PNG\r\n\x1a\n")
    width, height = struct.unpack(">II", data[16:24])
    idat_len = struct.unpack(">I", data[33:37])[0]
    raw = zlib.decompress(data[41:41 + idat_len])
    stride = 1 + 4 * width
    return width, height, [[tuple(raw[j * stride + 1 + 4 * i:j * stride + 5 + 4 * i]) for i in range(width)]
                           for j in range(height)]


def test_png_antialiased_shapes():
    w, h, px = _decode(png(20, 20, [(circle(10, 10, 8.3), "#FF0000")]))
    assert (w, h) == (20, 20)
    assert px[10][10] == (255, 0, 0, 255)   # centre plein
    assert px[0][0][3] == 0                  # coin transparent
    assert 0 < px[10][1][3] < 255            # bord adouci


def test_png_grow_repeats_center_for_nine_slice():
    _, _, small = _decode(png(10, 10, [(rounded_rect(0, 0, 10, 10, 4), "#00FF00")]))
    w, h, big = _decode(png(10, 10, [(rounded_rect(0, 0, 10, 10, 4), "#00FF00")], grow=(30, 5)))
    assert (w, h) == (40, 15)
    assert big[0][:5] == small[0][:5] and big[0][-5:] == small[0][-5:]  # coins intacts
    assert big[7][20] == (0, 255, 0, 255)


def test_arc_covers_only_requested_fraction():
    quarter = arc(10, 10, 8, 2, 0, 0.25)  # de midi à 3 h
    assert quarter(15.66, 4.34) < 0  # 45° : sur l'arc
    assert quarter(10, 18) > 0  # 6 h : hors de l'arc
