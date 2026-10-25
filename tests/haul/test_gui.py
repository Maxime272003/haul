import json
import struct
import zlib

from haul.engine import Job, State
from haul.gui import App, dump_jobs, eta, group_summary, load_jobs, plural, sort_key, status_kind
from haul.theme import arc, circle, png, rounded_rect


def test_status_kind_covers_every_state():
    assert status_kind(State.WAITING) == status_kind(State.QUEUED) == status_kind(State.RETRY) == "wait"
    assert status_kind(State.BROWSER) == "browser"
    assert status_kind(State.PAUSED) == "paused"
    assert status_kind(State.CONNECTING) == status_kind(State.CHECKING) == status_kind(State.EXTRACTING) == "busy"
    assert status_kind(State.DOWNLOADING) == "download"
    assert status_kind(State.DONE) == status_kind(State.PRESENT) == status_kind(State.EXTRACTED) == "done"
    for failed in (State.ERROR, State.EXTRACT_FAILED, State.BLOCKED):
        assert status_kind(failed) == "error"
    assert all(status_kind(s) for s in State)


def test_plural():
    assert plural(1, "fichier") == "1 fichier"
    assert plural(3, "fichier") == "3 fichiers"
    assert plural(2, "lien ajouté", "liens ajoutés") == "2 liens ajoutés"


def test_row_progress_and_speed():
    job = Job(id=1, url="u", dest=".", name="a.rar", state=State.DOWNLOADING, detail="Téléchargement (8 connexions)",
              done=312 << 20, total=500 << 20, speed=5 << 20)
    # temps restant : 188 Mo à 5 Mo/s
    assert App._row(job) == ("Téléchargement (8 connexions)", "62 %  ·  312.0 / 500.0 Mo", "5.0 Mo/s  ·  38 s", "")
    job.total = 3 << 30  # unités différentes : les deux sont affichées
    assert App._row(job)[1] == "10 %  ·  312.0 Mo / 3.0 Go"
    job.state, job.detail, job.done, job.total = State.DONE, "", 500 << 20, 500 << 20
    assert App._row(job)[:3] == ("Terminé", "500.0 Mo", "")  # plus de vitesse une fois terminé


def test_saved_queue_round_trip_pauses_unfinished_jobs():
    jobs = [
        Job(1, "https://fuckingfast.co/a#A.rar", "D:/dl", name="A.rar", state=State.EXTRACTED, done=5, total=5,
            vt="RAS", processed=True),
        Job(2, "https://fuckingfast.co/b#B.rar", "D:/dl", name="B.rar", state=State.DOWNLOADING,
            detail="Téléchargement (8 connexions)", done=3, total=9),
        Job(3, "https://fuckingfast.co/c", "D:/dl", state=State.BROWSER),
        Job(4, "https://fuckingfast.co/d#D.rar", "D:/dl", name="D.rar", state=State.EXTRACTING, processed=True),
        Job(5, "https://fuckingfast.co/e", "D:/dl", state=State.ERROR, detail="Erreur : HTTP 404"),
    ]
    restored = load_jobs(json.loads(json.dumps(dump_jobs(jobs))), first_id=10)
    assert [j.id for j in restored] == [10, 11, 12, 13, 14]
    assert [(j.state, j.status) for j in restored] == [
        (State.EXTRACTED, "Extrait ✔"), (State.PAUSED, "En pause"), (State.PAUSED, "En pause"),
        (State.DONE, "Terminé"), (State.ERROR, "Erreur : HTTP 404")]
    assert (restored[0].vt, restored[0].processed) == ("RAS", True)
    assert (restored[1].name, restored[1].done, restored[1].total) == ("B.rar", 3, 9)
    assert restored[3].processed is False  # extraction interrompue : à refaire


def test_saved_queue_keeps_recent_direct_links():
    jobs = [Job(1, "https://fuckingfast.co/a", "D:/dl", state=State.DOWNLOADING,
                dl_url="https://dl.fuckingfast.co/dl/tok", user_agent="Mozilla/5.0"),
            Job(2, "https://fuckingfast.co/b", "D:/dl", state=State.PAUSED, dl_url="https://evil.example/x.exe"),
            Job(3, "https://fuckingfast.co/c", "D:/dl", state=State.PAUSED)]
    saved = json.loads(json.dumps(dump_jobs(jobs, now=1000)))
    restored = load_jobs(saved, now=1000 + 3600)
    assert (restored[0].dl_url, restored[0].user_agent) == ("https://dl.fuckingfast.co/dl/tok", "Mozilla/5.0")
    assert restored[1].dl_url is None  # pas un lien FuckingFast : la page sera rouverte
    assert restored[2].dl_url is None
    assert load_jobs(saved, now=1000 + 2 * 24 * 3600)[0].dl_url is None  # trop vieux pour être encore valable


def test_saved_queue_ignores_damaged_entries():
    items = [{"url": "u"}, {"url": 1, "dest": "d", "state": "done"}, "x",
             {"url": "https://fuckingfast.co/a", "dest": "d", "state": "inconnu"},
             {"url": "https://fuckingfast.co/a", "dest": "d", "state": "done", "name": "../../x.exe", "total": "9"}]
    restored = load_jobs(items)
    assert len(restored) == 1
    assert restored[0].name == "_.._x.exe" and restored[0].total is None
    assert load_jobs({"pas": "une liste"}) == []


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



def test_group_summary_aggregates_volumes():
    jobs = [Job(1, "u", ".", name="Jeu.part1.rar", state=State.DONE, done=100, total=100, vt="PROPRE"),
            Job(2, "u", ".", name="Jeu.part2.rar", state=State.DOWNLOADING, done=50, total=100, speed=10, vt="PROPRE"),
            Job(3, "u", ".", name="Jeu.part3.rar", state=State.DOWNLOADING, done=0, total=100, speed=40)]
    kind, fraction, status, progress, speed, vt = group_summary(jobs)
    assert (kind, fraction) == ("download", 0.5)
    assert status == "2 en cours  ·  1 terminé"
    assert progress == "50 %  ·  150 / 300 o"
    assert speed == "50 o/s  ·  3 s"
    assert vt == ""  # verdicts différents
    for job in jobs:
        job.state, job.done = State.EXTRACTED, 100
    assert group_summary(jobs)[:3] == ("done", None, "Extrait ✔")


def test_eta_and_sort_keys():
    assert eta(50, 100, 10) == 5
    assert eta(100, 100, 10) is None and eta(0, None, 10) is None and eta(0, 100, 0) is None
    jobs = [Job(1, "u", ".", name="b.rar", state=State.DONE), Job(2, "u", ".", name="A.rar", state=State.ERROR,
                                                                   detail="Erreur : HTTP 404"),
            Job(3, "u", ".", name="c.rar", state=State.DOWNLOADING, done=1, total=4, speed=9)]
    assert [j.id for j in sorted(jobs, key=sort_key("#0"))] == [2, 1, 3]
    assert [j.id for j in sorted(jobs, key=sort_key("status"))] == [2, 3, 1]  # erreurs d'abord
    assert [j.id for j in sorted(jobs, key=sort_key("speed"), reverse=True)][0] == 3
