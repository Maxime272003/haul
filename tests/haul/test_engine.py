import queue
import threading
import time

from haul.engine import Engine, Job, State


def wait_state(events, job_id, state, timeout=5):
    """Consomme les événements jusqu'à ce que job_id passe dans `state` ; retourne les champs reçus."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            jid, fields = events.get(timeout=0.2)
        except queue.Empty:
            continue
        if jid == job_id and fields.get("state") == state:
            return fields
    raise AssertionError(f"{job_id} jamais passé en {state}")


def send_link(engine, page):
    """Comme le userscript : une fois la page ouverte par l'app, renvoie son lien direct."""
    deadline = time.monotonic() + 5
    while not engine.is_waiting(page):
        assert time.monotonic() < deadline, page
        time.sleep(0.02)
    assert engine.link_found(page, page.replace("fuckingfast.co/", "dl.fuckingfast.co/dl/"), None)


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
        if fields.get("state") == State.QUEUED:
            finished.add(job_id)
    time.sleep(0.7)

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
    wait_state(events, 1, State.PRESENT)


def test_existing_file_with_wrong_size_is_not_skipped(tmp_path):
    (tmp_path / "Jeu.rar").write_bytes(b"x")
    events, opened = queue.Queue(), []
    engine = Engine(events, lambda *link: None, open_page=opened.append)
    engine.submit(Job(1, "https://fuckingfast.co/a#Jeu.rar", str(tmp_path), name="Jeu.rar", total=10))
    wait_state(events, 1, State.BROWSER)
    assert opened == ["https://fuckingfast.co/a#Jeu.rar"]


def test_never_opens_something_else_than_a_fuckingfast_page(tmp_path):
    events, opened = queue.Queue(), []
    engine = Engine(events, lambda *link: None, open_page=opened.append)
    engine.submit(Job(1, r"\\attaquant\partage\x.exe", str(tmp_path)))
    fields = wait_state(events, 1, State.ERROR)
    assert opened == []
    assert "recopie le lien" in fields["detail"]


def test_pause_in_browser_skips_to_next_page_then_resume(tmp_path):
    events, opened = queue.Queue(), []
    engine = Engine(events, lambda *link: None, open_page=opened.append)
    engine._download = lambda job: None  # pas de réseau
    first = Job(1, "https://fuckingfast.co/a", str(tmp_path))
    engine.submit(first)
    engine.submit(Job(2, "https://fuckingfast.co/b", str(tmp_path)))
    wait_state(events, 1, State.BROWSER)
    engine.pause(first)  # « passer ce lien »
    wait_state(events, 1, State.PAUSED)
    wait_state(events, 2, State.BROWSER)
    assert opened == ["https://fuckingfast.co/a", "https://fuckingfast.co/b"]

    engine.submit(first)  # reprise : la page est rouverte après la 2e
    wait_state(events, 1, State.WAITING)
    send_link(engine, "https://fuckingfast.co/b")
    wait_state(events, 1, State.BROWSER)
    assert opened[-1] == "https://fuckingfast.co/a"


def test_pause_while_waiting_in_queue_and_resume_does_not_duplicate(tmp_path):
    events, opened = queue.Queue(), []
    engine = Engine(events, lambda *link: None, open_page=opened.append)
    engine._download = lambda job: None  # pas de réseau
    engine.submit(Job(1, "https://fuckingfast.co/a", str(tmp_path)))
    second = Job(2, "https://fuckingfast.co/b", str(tmp_path))
    engine.submit(second)
    engine.pause(second)
    wait_state(events, 2, State.PAUSED)
    engine.submit(second)
    send_link(engine, "https://fuckingfast.co/a")
    wait_state(events, 2, State.BROWSER)
    send_link(engine, "https://fuckingfast.co/b")
    time.sleep(0.3)
    assert opened == ["https://fuckingfast.co/a", "https://fuckingfast.co/b"]


def test_pause_during_download_cancels_it(tmp_path):
    events = queue.Queue()
    engine = Engine(events, lambda *link: None, open_page=lambda url: None)
    started, stop = threading.Event(), threading.Event()

    class FakeDownloader:
        active_connections = 1

        def cancel(self):
            stop.set()

    def fake_download(job):
        with engine._lock:
            engine._downloaders[job.id] = FakeDownloader()
        started.set()
        stop.wait(5)
        from haul.downloader import Cancelled
        raise Cancelled("interrompu")

    engine._download = fake_download
    job = Job(1, "https://fuckingfast.co/a", str(tmp_path), dl_url="https://dl.fuckingfast.co/dl/a")
    engine.submit(job)
    assert started.wait(5)
    engine.pause(job)
    wait_state(events, 1, State.PAUSED)


def test_speed_limit_is_shared_between_connections(tmp_path):
    engine = Engine(queue.Queue(), lambda *link: None, open_page=lambda url: None)
    assert engine._connection_speed() == 0
    engine.set_max_speed(8 << 20)

    class D:
        active_connections = 4
    engine._downloaders = {1: D(), 2: D()}
    assert engine._connection_speed() == 1 << 20


def test_busy_server_requeues_file_until_another_one_finishes(tmp_path):
    from haul.engine import ServerBusy

    events = queue.Queue()
    engine = Engine(events, lambda *link: None, open_page=lambda url: None)
    engine.set_parallel(3)
    first_running, first_done, calls = threading.Event(), threading.Event(), []

    def fake_download(job):
        calls.append(job.id)
        if job.id == 1:
            first_running.set()
            first_done.wait(5)
        elif job.id == 2 and calls.count(2) == 1:
            raise ServerBusy("HTTP 429")  # le serveur n'accepte pas un 2e fichier pour l'instant

    engine._download = fake_download
    jobs = [Job(i, f"https://fuckingfast.co/{i}", str(tmp_path), dl_url=f"https://dl.fuckingfast.co/dl/{i}")
            for i in (1, 2, 3)]
    engine.submit(jobs[0])
    assert first_running.wait(5)
    engine.submit(jobs[1])
    fields = wait_state(events, 2, State.QUEUED)
    while "limite" not in fields.get("detail", ""):
        fields = wait_state(events, 2, State.QUEUED)
    engine.submit(jobs[2])  # plafond : 1 fichier à la fois tant que le 1er tourne
    time.sleep(0.3)
    assert calls == [1, 2]
    assert jobs[1].dl_url  # lien gardé
    first_done.set()
    deadline = time.monotonic() + 5
    while sorted(calls) != [1, 2, 2, 3] and time.monotonic() < deadline:
        time.sleep(0.05)
    assert sorted(calls) == [1, 2, 2, 3]


def test_pause_with_discard_deletes_partial_file_once_stopped(tmp_path, file_server):
    srv = file_server()
    events = queue.Queue()
    engine = Engine(events, lambda *link: None, open_page=lambda url: None)
    engine.set_connections(2)
    job = Job(1, "https://fuckingfast.co/a#f.bin", str(tmp_path), name="f.bin", dl_url=srv.url)
    engine.submit(job)
    wait_state(events, 1, State.DOWNLOADING)
    time.sleep(0.3)
    assert (tmp_path / "f.bin.part").exists()
    engine.pause(job, discard=True)  # « Tout supprimer » avec les téléchargements inachevés
    wait_state(events, 1, State.PAUSED)
    assert list(tmp_path.iterdir()) == []  # ni .part ni .part.json (réécrit à l'arrêt)
