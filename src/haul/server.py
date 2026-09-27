"""Serveur HTTP local (127.0.0.1) qui fait le lien avec le userscript du navigateur.

- GET  /haul.user.js : sert le userscript (installation en un clic dans Violentmonkey/Tampermonkey)
- POST /wanted       : la page a-t-elle été ouverte par l'app ? (le script clique alors DOWNLOAD)
- POST /found        : lien direct récupéré par le script
"""

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .links import DL_RE
from .paths import USERSCRIPT_PATH

PORT = 17655
USERSCRIPT_URL = f"http://127.0.0.1:{PORT}/haul.user.js"

# Le userscript passe par son extension (moz-/chrome-extension://) ou par la page fuckingfast.co ;
# toute autre origine est un site web tiers qui n'a rien à faire ici.
ALLOWED_ORIGINS = ("chrome-extension://", "moz-extension://", "https://fuckingfast.co", "https://www.fuckingfast.co")


class LinkServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, engine, port=PORT):
        self.engine = engine
        super().__init__(("127.0.0.1", port), LinkHandler)


class LinkHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _reply(self, code, body=b"", ctype="application/json"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _json(self, data):
        self._reply(200, json.dumps(data).encode())

    def do_GET(self):
        if self.path != "/haul.user.js":
            return self._reply(404)
        self._reply(200, USERSCRIPT_PATH.read_bytes(), "text/javascript; charset=utf-8")

    def do_POST(self):
        origin = self.headers.get("Origin", "")
        if self.path not in ("/found", "/wanted") or (origin and origin != "null"
                                                      and not origin.startswith(ALLOWED_ORIGINS)):
            return self._reply(403)
        try:
            data = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))))
            page_url = data.get("page_url") or ""
            if self.path == "/wanted":
                return self._json({"wanted": self.server.engine.is_waiting(page_url)})
            dl_url = data["dl_url"]
            if not DL_RE.fullmatch(dl_url):
                raise ValueError(dl_url)
        except (ValueError, KeyError, TypeError, AttributeError):
            return self._reply(400)
        close = self.server.engine.link_found(page_url, dl_url, data.get("user_agent"))
        self._json({"ok": True, "close": close})
