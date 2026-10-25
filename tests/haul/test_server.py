import http.client
import json
import threading

import pytest

from haul.server import MAX_BODY, LinkServer, bundled_script_version, show_running_instance

TOKEN = "t" * 43


class FakeEngine:
    def __init__(self):
        self.found = []

    def page_checked(self, page_url):
        return page_url.endswith("/wanted")

    def link_found(self, page_url, dl_url, user_agent):
        self.found.append((page_url, dl_url, user_agent))
        return True


@pytest.fixture
def server():
    engine, bad, scripts, shown = FakeEngine(), [], [], []
    srv = LinkServer(engine, TOKEN, port=0, on_bad_token=bad.append, on_script=scripts.append,
                     on_show=lambda: shown.append(True))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    srv.bad_tokens, srv.scripts, srv.shown = bad, scripts, shown
    yield srv, engine
    srv.shutdown()


def request(srv, method, path, body=None, token=TOKEN, origin=None, host=None, headers=None):
    conn = http.client.HTTPConnection("127.0.0.1", srv.server_address[1], timeout=5)
    data = json.dumps(body).encode() if isinstance(body, dict) else body
    h = {"Content-Type": "application/json", **(headers or {})}
    if token:
        h["X-Haul-Token"] = token
    if origin:
        h["Origin"] = origin
    if host:
        h["Host"] = host
    conn.request(method, path, data, h)
    r = conn.getresponse()
    payload = r.read()
    conn.close()
    try:
        return r.status, json.loads(payload) if payload and r.status == 200 and method == "POST" else payload
    except ValueError:
        return r.status, payload


FOUND = {"page_url": "https://fuckingfast.co/a", "dl_url": "https://dl.fuckingfast.co/dl/t", "user_agent": "UA"}


def test_found_forwards_link_to_engine(server):
    srv, engine = server
    status, body = request(srv, "POST", "/found", FOUND, origin="moz-extension://123")
    assert (status, body) == (200, {"ok": True, "close": True})
    assert engine.found == [("https://fuckingfast.co/a", "https://dl.fuckingfast.co/dl/t", "UA")]


def test_wanted(server):
    srv, _ = server
    assert request(srv, "POST", "/wanted", {"page_url": "https://fuckingfast.co/wanted"})[1] == {"wanted": True}
    assert request(srv, "POST", "/wanted", {"page_url": "https://fuckingfast.co/other"})[1] == {"wanted": False}


def test_rejects_third_party_origin(server):
    srv, engine = server
    status, _ = request(srv, "POST", "/found", FOUND, origin="https://evil.example")
    assert status == 403
    assert engine.found == []


@pytest.mark.parametrize(("token", "kind"), [(None, "missing"), ("mauvais", "wrong")])
def test_rejects_missing_or_wrong_token_even_with_null_origin(server, token, kind):
    # une iframe « sandbox » de n'importe quel site envoie Origin: null
    srv, engine = server
    status, _ = request(srv, "POST", "/found", FOUND, token=token, origin="null")
    assert status == 401
    assert engine.found == []
    assert srv.bad_tokens == [kind]  # ancien script sans jeton / jeton périmé : message différent


def test_page_url_that_is_not_a_fuckingfast_page_is_dropped(server):
    # sinon « Réessayer » passerait ce chemin à os.startfile, qui lancerait l'exécutable
    srv, engine = server
    for page in (r"\\attaquant\partage\x.exe", "file:///C:/Windows/System32/calc.exe",
                 'https://fuckingfast.co/a#" --arg', "https://fuckingfast.co.evil.example/a"):
        engine.found.clear()
        status, _ = request(srv, "POST", "/found", {**FOUND, "page_url": page})
        assert status == 200
        assert engine.found == [("", FOUND["dl_url"], "UA")]


def test_rejects_non_fuckingfast_direct_link(server):
    srv, engine = server
    status, _ = request(srv, "POST", "/found", {"dl_url": "https://evil.example/malware.exe"})
    assert status == 400
    assert engine.found == []


def test_rejects_oversized_body_and_foreign_host(server):
    srv, engine = server
    assert request(srv, "POST", "/found", b"x" * (MAX_BODY + 1))[0] == 413
    # DNS rebinding : la page d'un site dont le nom pointe vers 127.0.0.1
    assert request(srv, "POST", "/found", FOUND, host="evil.example:17655")[0] == 403
    assert request(srv, "GET", "/haul.user.js", host="evil.example:17655")[0] == 403
    assert engine.found == []


def test_serves_userscript_without_any_secret(server):
    # le jeton n'est plus écrit dans le script : le réinstaller n'est jamais nécessaire
    srv, _ = server
    status, body = request(srv, "GET", "/haul.user.js", token=None)
    assert status == 200
    assert body.startswith(b"// ==UserScript==")
    assert TOKEN.encode() not in body


def test_token_is_readable_by_the_extension_only(server):
    srv, _ = server
    for origin in (None, "chrome-extension://abc", "moz-extension://abc"):
        status, body = request(srv, "GET", "/token", token=None, origin=origin, headers={"Sec-Fetch-Dest": "empty"})
        assert (status, json.loads(body)) == (200, {"token": TOKEN})
    # une page web (même fuckingfast.co), une iframe « sandbox », une balise <script> ou <iframe> : non
    for origin in ("https://evil.example", "https://fuckingfast.co", "null"):
        assert request(srv, "GET", "/token", token=None, origin=origin)[0] == 403
    for dest in ("script", "iframe", "document"):
        assert request(srv, "GET", "/token", token=None, headers={"Sec-Fetch-Dest": dest})[0] == 403
    assert request(srv, "GET", "/token", token=None, host="evil.example:17655")[0] == 403


def test_reports_userscript_version(server):
    srv, _ = server
    request(srv, "POST", "/wanted", {"page_url": "https://fuckingfast.co/a"}, headers={"X-Haul-Script": "3.3"})
    request(srv, "POST", "/wanted", {"page_url": "https://fuckingfast.co/a"})  # script 3.2 : sans version
    request(srv, "POST", "/wanted", {"page_url": "https://fuckingfast.co/a"}, headers={"X-Haul-Script": "<b>"})
    assert srv.scripts == ["3.3", "", ""]


def test_second_launch_brings_running_instance_to_front(server):
    srv, _ = server
    assert show_running_instance(TOKEN, port=srv.server_address[1])
    assert srv.shown == [True]
    assert not show_running_instance("mauvais", port=srv.server_address[1])
    # une page web ne peut pas le déclencher, même avec le jeton
    assert request(srv, "POST", "/show", {}, origin="moz-extension://abc")[0] == 403
    assert srv.shown == [True]


def test_bundled_script_version():
    assert bundled_script_version() == "3.3"
