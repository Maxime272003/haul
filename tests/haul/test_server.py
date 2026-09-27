import json
import threading
import urllib.error
import urllib.request

import pytest

from haul.server import LinkServer


class FakeEngine:
    def __init__(self):
        self.found = []

    def is_waiting(self, page_url):
        return page_url.endswith("/wanted")

    def link_found(self, page_url, dl_url, user_agent):
        self.found.append((page_url, dl_url, user_agent))
        return True


@pytest.fixture
def server():
    engine = FakeEngine()
    srv = LinkServer(engine, port=0)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv, engine, f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


def post(url, body, origin=None):
    headers = {"Content-Type": "application/json", **({"Origin": origin} if origin else {})}
    req = urllib.request.Request(url, json.dumps(body).encode(), headers)
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, None


def test_found_forwards_link_to_engine(server):
    _, engine, base = server
    status, body = post(f"{base}/found", {"page_url": "https://fuckingfast.co/a",
                                          "dl_url": "https://dl.fuckingfast.co/dl/t", "user_agent": "UA"},
                        origin="moz-extension://123")
    assert (status, body) == (200, {"ok": True, "close": True})
    assert engine.found == [("https://fuckingfast.co/a", "https://dl.fuckingfast.co/dl/t", "UA")]


def test_wanted(server):
    _, _, base = server
    assert post(f"{base}/wanted", {"page_url": "https://fuckingfast.co/wanted"})[1] == {"wanted": True}
    assert post(f"{base}/wanted", {"page_url": "https://fuckingfast.co/other"})[1] == {"wanted": False}


def test_rejects_third_party_origin(server):
    _, engine, base = server
    status, _ = post(f"{base}/found", {"dl_url": "https://dl.fuckingfast.co/dl/t"}, origin="https://evil.example")
    assert status == 403
    assert engine.found == []


def test_rejects_non_fuckingfast_direct_link(server):
    _, engine, base = server
    status, _ = post(f"{base}/found", {"dl_url": "https://evil.example/malware.exe"})
    assert status == 400
    assert engine.found == []


def test_serves_userscript(server):
    _, _, base = server
    with urllib.request.urlopen(f"{base}/haul.user.js") as r:
        assert r.read().startswith(b"// ==UserScript==")
