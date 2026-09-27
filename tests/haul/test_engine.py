import queue
import threading
import time

from haul.engine import Engine, Job


def test_pages_open_one_at_a_time_then_downloads_run_in_parallel(tmp_path):
    events, opened, downloads = queue.Queue(), [], []
    engine = None

    def open_page(url):  # simule le navigateur + userscript
        opened.append((time.monotonic(), url))
        threading.Timer(0.2, engine.link_found, (url, url.replace("fuckingfast.co/", "dl.fuckingfast.co/dl/"),
                                                  "UA")).start()

    def fake_download(job):
        downloads.append((time.monotonic(), job.dl_url))
        time.sleep(0.5)
        engine.emit(job, status="Terminé")

    engine = Engine(events, lambda *link: None, open_page=open_page)
    engine._download = fake_download
    for i in (1, 2):
        engine.submit(Job(i, f"https://fuckingfast.co/abc{i}#Jeu.part0{i}.rar", str(tmp_path)))

    finished = set()
    deadline = time.monotonic() + 10
    while len(finished) < 2 and time.monotonic() < deadline:
        try:
            job_id, fields = events.get(timeout=0.5)
        except queue.Empty:
            continue
        if fields.get("status") == "Terminé":
            finished.add(job_id)

    assert finished == {1, 2}
    assert [u for _, u in opened] == ["https://fuckingfast.co/abc1#Jeu.part01.rar",
                                      "https://fuckingfast.co/abc2#Jeu.part02.rar"]
    # la 2e page ne s'ouvre qu'une fois le lien de la 1re reçu…
    assert opened[1][0] >= opened[0][0] + 0.15
    # …mais le 1er téléchargement tourne encore quand le 2e démarre
    assert downloads[1][0] < downloads[0][0] + 0.5


def test_unknown_page_goes_to_callback(tmp_path):
    received = []
    engine = Engine(queue.Queue(), lambda *link: received.append(link), open_page=lambda url: None)
    close = engine.link_found("https://fuckingfast.co/zzz", "https://dl.fuckingfast.co/dl/t", None)
    assert close is False
    assert received == [("https://fuckingfast.co/zzz", "https://dl.fuckingfast.co/dl/t", None)]


def test_existing_file_is_skipped(tmp_path):
    (tmp_path / "Jeu.rar").write_bytes(b"x")
    events = queue.Queue()
    engine = Engine(events, lambda *link: None, open_page=lambda url: None)
    engine.submit(Job(1, "https://fuckingfast.co/a#Jeu.rar", str(tmp_path), name="Jeu.rar"))
    assert events.get(timeout=2) == (1, {"status": "Déjà présent"})
