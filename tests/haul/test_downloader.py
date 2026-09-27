import threading
import time

import pytest

from haul import downloader
from haul.downloader import Cancelled, Downloader, Refused

from .conftest import DATA

NO_AUTH = [({}, {})]


def fetch(url, dest, connections=8):
    d = Downloader(url, "http://referer", NO_AUTH, connections)
    d.probe()
    d.download(str(dest), lambda done, total: None)
    return d


def test_probe_reads_size_ranges_and_filename(file_server):
    srv = file_server()
    d = Downloader(srv.url, "x", NO_AUTH)
    d.probe()
    assert (d.total, d.ranges, d.filename) == (len(DATA), True, "Jeu test.part01.rar")


def test_segmented_download_is_byte_exact(file_server, tmp_path):
    srv = file_server()
    out = tmp_path / "f.bin"
    fetch(srv.url, out)
    assert out.read_bytes() == DATA
    assert srv.peak > 1  # plusieurs connexions en parallèle
    assert not (tmp_path / "f.bin.part.json").exists()


def test_single_connection_when_server_has_no_ranges(file_server, tmp_path):
    srv = file_server(ranges=False)
    out = tmp_path / "f.bin"
    d = fetch(srv.url, out)
    assert not d.ranges
    assert out.read_bytes() == DATA


def test_resume_after_cancel(file_server, tmp_path):
    srv = file_server()
    out = tmp_path / "f.bin"
    d = Downloader(srv.url, "x", NO_AUTH, 2)
    d.probe()
    threading.Timer(0.2, d.cancel).start()
    with pytest.raises(Cancelled):
        d.download(str(out), lambda done, total: None)
    assert (tmp_path / "f.bin.part.json").exists()
    partial = d.done
    assert 0 < partial < len(DATA)

    d2 = Downloader(srv.url, "x", NO_AUTH, 2)
    d2.probe()
    d2.download(str(out), lambda done, total: None)
    assert out.read_bytes() == DATA


def test_throttled_server_still_completes(file_server, tmp_path):
    srv = file_server(max_conns=2)
    out = tmp_path / "f.bin"
    fetch(srv.url, out, connections=8)
    assert out.read_bytes() == DATA
    assert srv.peak <= 2


def test_html_answer_is_refused(file_server):
    srv = file_server(html=True)
    with pytest.raises(Refused):
        Downloader(srv.url, "x", NO_AUTH).probe()


def test_unexpected_range_is_not_written(file_server, tmp_path, monkeypatch):
    monkeypatch.setattr(downloader, "MAX_RETRIES", 1)
    srv = file_server(wrong_range=True)
    out = tmp_path / "f.bin"
    with pytest.raises(OSError, match="plage inattendue"):
        fetch(srv.url, out, connections=2)
    assert not out.exists()


def test_speed_limit_slows_download(file_server, tmp_path):
    srv = file_server()
    d = Downloader(srv.url, "x", NO_AUTH, 2, speed_limit=lambda: 2 << 20)  # 2 × 2 Mo/s
    d.probe()
    start = time.monotonic()
    d.download(str(tmp_path / "f.bin"), lambda done, total: None)
    assert time.monotonic() - start > 2  # 12 Mo à 4 Mo/s ; sans limite, moins d'une seconde
    assert (tmp_path / "f.bin").read_bytes() == DATA


def test_allocate_sets_final_size_without_writing_zeros(tmp_path):
    path = tmp_path / "big.part"
    start = time.monotonic()
    downloader.allocate(str(path), 8 << 30)  # 8 Go : écrire les zéros prendrait plusieurs secondes
    assert time.monotonic() - start < 2
    assert path.stat().st_size == 8 << 30
    with open(path, "r+b") as f:  # écriture au milieu, comme un segment
        f.seek(5 << 30)
        f.write(b"abc")
    with open(path, "rb") as f:
        f.seek((5 << 30) - 2)
        assert f.read(5) == b"\0\0abc"


def test_probe_waits_when_server_is_busy(file_server, monkeypatch):
    monkeypatch.setattr(downloader, "PROBE_BACKOFF", (0.05, 0.05))
    srv = file_server(busy_first=2)  # autres fichiers en cours : 429 le temps qu'une connexion se libère
    d = Downloader(srv.url, "x", NO_AUTH)
    d.probe()
    assert d.total == len(DATA)
    with pytest.raises(Refused, match="429"):
        Downloader(file_server(busy_first=5).url, "x", NO_AUTH).probe()
