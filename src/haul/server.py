"""Serveur HTTP local (127.0.0.1) qui fait le lien avec le userscript du navigateur.

- GET  /haul.user.js : sert le userscript (installation en un clic dans Violentmonkey/Tampermonkey)
- POST /wanted       : la page a-t-elle été ouverte par l'app ? (le script clique alors DOWNLOAD)
- POST /found        : lien direct récupéré par le script

Protections : le userscript servi contient un jeton secret propre à l'installation, exigé sur chaque
POST (en-tête X-Haul-Token). Un site web ne peut donc pas injecter de lien, même depuis une iframe
« sandbox » (Origin: null). L'en-tête Host est vérifié (contre le DNS rebinding) et le script n'est
pas servi à une balise <script> d'une page tierce, qui pourrait sinon en lire le jeton.
"""

import hmac
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .links import DL_RE, is_page_url
from .paths import USERSCRIPT_PATH

PORT = 17655
USERSCRIPT_URL = f"http://127.0.0.1:{PORT}/haul.user.js"
TOKEN_PLACEHOLDER = "__HAUL_TOKEN__"
MAX_BODY = 16 << 10

# Le userscript passe par son extension (moz-/chrome-extension://) ou par la page fuckingfast.co ;
# toute autre origine est un site web tiers qui n'a rien à faire ici.
ALLOWED_ORIGINS = ("chrome-extension://", "moz-extension://", "https://fuckingfast.co", "https://www.fuckingfast.co")


class LinkServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, engine, token, port=PORT, on_bad_token=lambda: None):
        self.engine = engine
        self.token = token
        self.on_bad_token = on_bad_token  # userscript installé avant l'ajout du jeton
        super().__init__(("127.0.0.1", port), LinkHandler)


class LinkHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _reply(self, code, body=b"", ctype="application/json"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, data):
        self._reply(200, json.dumps(data).encode())

    def _host_ok(self):
        port = self.server.server_address[1]
        return self.headers.get("Host", "").lower() in (f"127.0.0.1:{port}", f"localhost:{port}")

    def do_GET(self):
        if not self._host_ok():
            return self._reply(403)
        if self.path != "/haul.user.js":
            return self._reply(404)
        # Navigation (installation) ou requête de l'extension : oui. <script>, <iframe>… : non.
        if self.headers.get("Sec-Fetch-Dest", "document") not in ("document", "empty"):
            return self._reply(403)
        script = USERSCRIPT_PATH.read_text(encoding="utf-8").replace(TOKEN_PLACEHOLDER, self.server.token)
        self._reply(200, script.encode(), "text/javascript; charset=utf-8")

    def do_POST(self):
        origin = self.headers.get("Origin", "")
        if (not self._host_ok() or self.path not in ("/found", "/wanted")
                or (origin and origin != "null" and not origin.startswith(ALLOWED_ORIGINS))):
            return self._reply(403)
        if not hmac.compare_digest(self.headers.get("X-Haul-Token", "").encode(), self.server.token.encode()):
            self.server.on_bad_token()
            return self._reply(401)
        try:
            length = int(self.headers.get("Content-Length", 0))
            if not 0 <= length <= MAX_BODY:
                return self._reply(413)
            data = json.loads(self.rfile.read(length))
            page_url = data.get("page_url") or ""
            if not is_page_url(page_url):
                page_url = ""  # jamais ouvert ni affiché : seul le lien direct compte
            if self.path == "/wanted":
                return self._json({"wanted": bool(page_url) and self.server.engine.is_waiting(page_url)})
            dl_url = data["dl_url"]
            if not isinstance(dl_url, str) or not DL_RE.fullmatch(dl_url):
                raise ValueError(dl_url)
            user_agent = data.get("user_agent")
            if not isinstance(user_agent, str) or len(user_agent) > 512 or not user_agent.isprintable():
                user_agent = None
        except (ValueError, KeyError, TypeError, AttributeError):
            return self._reply(400)
        close = self.server.engine.link_found(page_url, dl_url, user_agent)
        self._json({"ok": True, "close": close})
