"""Serveur HTTP local (127.0.0.1) qui fait le lien avec le userscript du navigateur.

- GET  /haul.user.js : sert le userscript (installation en un clic dans Violentmonkey/Tampermonkey)
- GET  /token        : jeton secret de l'installation, lu par le userscript au moment de l'utiliser
- POST /wanted       : la page a-t-elle été ouverte par l'app ? (le script clique alors DOWNLOAD)
- POST /found        : lien direct récupéré par le script
- POST /show         : un 2e lancement de Haul demande à cette instance de s'afficher

Protections : chaque POST doit porter le jeton secret de l'installation (en-tête X-Haul-Token). Un
site web ne peut donc pas injecter de lien, même depuis une iframe « sandbox » (Origin: null) : il
ne peut pas lire /token, servi sans en-tête CORS et refusé à toute origine autre qu'une extension,
à une balise <script> ou à une iframe. Le userscript, lui, passe par GM_xmlhttpRequest (extension,
pas de CORS). L'en-tête Host est vérifié partout (contre le DNS rebinding).

Le jeton n'est pas écrit dans le script : il n'y a jamais besoin de réinstaller le script quand il change.
"""

import hmac
import json
import logging
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .links import DL_RE, is_page_url
from .paths import USERSCRIPT_PATH

log = logging.getLogger(__name__)

PORT = 17655
USERSCRIPT_URL = f"http://127.0.0.1:{PORT}/haul.user.js"
MAX_BODY = 16 << 10

EXTENSION_ORIGINS = ("chrome-extension://", "moz-extension://", "safari-web-extension://")
# Le userscript passe par son extension ou par la page fuckingfast.co ; toute autre origine est un
# site web tiers qui n'a rien à faire ici.
ALLOWED_ORIGINS = (*EXTENSION_ORIGINS, "https://fuckingfast.co", "https://www.fuckingfast.co")


class LinkServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, engine, token, port=PORT, on_bad_token=lambda kind: None, on_script=lambda version: None,
                 on_show=lambda: None):
        self.engine = engine
        self.token = token
        # kind : « missing » (ancien script, sans jeton) ou « wrong » (jeton écrit dans un script 3.1)
        self.on_bad_token = on_bad_token
        self.on_script = on_script  # le userscript s'est manifesté (version, ou "" avant la 3.3)
        self.on_show = on_show
        super().__init__(("127.0.0.1", port), LinkHandler)


class LinkHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _reply(self, code, body=b"", ctype="application/json"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
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
        if self.path == "/haul.user.js":
            return self._reply(200, USERSCRIPT_PATH.read_bytes(), "text/javascript; charset=utf-8")
        if self.path == "/token":
            origin = self.headers.get("Origin", "")
            if ((origin and not origin.startswith(EXTENSION_ORIGINS))
                    or self.headers.get("Sec-Fetch-Dest", "empty") != "empty"):
                return self._reply(403)
            return self._json({"token": self.server.token})
        self._reply(404)

    def do_POST(self):
        origin = self.headers.get("Origin", "")
        if (not self._host_ok() or self.path not in ("/found", "/wanted", "/show")
                or (origin and origin != "null" and not origin.startswith(ALLOWED_ORIGINS))):
            return self._reply(403)
        sent = self.headers.get("X-Haul-Token", "")
        if not hmac.compare_digest(sent.encode(), self.server.token.encode()):
            kind = "wrong" if sent else "missing"
            log.warning("Requête %s refusée : jeton %s (Origin %r, User-Agent %r)", self.path,
                        "périmé" if sent else "absent", origin, self.headers.get("User-Agent", "")[:120])
            self.server.on_bad_token(kind)
            return self._reply(401)
        if self.path == "/show":
            if origin:  # seulement un autre lancement de Haul, jamais le navigateur
                return self._reply(403)
            self.server.on_show()
            return self._json({"ok": True})
        version = self.headers.get("X-Haul-Script", "")
        self.server.on_script(version if len(version) <= 16 and version.replace(".", "").isdigit() else "")
        try:
            length = int(self.headers.get("Content-Length", 0))
            if not 0 <= length <= MAX_BODY:
                return self._reply(413)
            data = json.loads(self.rfile.read(length))
            page_url = data.get("page_url") or ""
            if not is_page_url(page_url):
                page_url = ""  # jamais ouvert ni affiché : seul le lien direct compte
            if self.path == "/wanted":
                return self._json({"wanted": bool(page_url) and self.server.engine.page_checked(page_url)})
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


def show_running_instance(token, port=PORT, timeout=3):
    """Demande à l'instance déjà lancée de s'afficher ; True si elle a répondu."""
    import http.client
    try:
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
        try:
            conn.request("POST", "/show", b"{}", {"Content-Type": "application/json", "X-Haul-Token": token})
            return conn.getresponse().status == 200
        finally:
            conn.close()
    except OSError:
        return False
