import random
import re
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

DATA = random.Random(1).randbytes(12 << 20)


class FileServer(ThreadingHTTPServer):
    """Serveur de fichier local : Range, limite de connexions simultanées, débit par connexion."""

    daemon_threads = True

    def __init__(self, data, ranges=True, max_conns=None, html=False, wrong_range=False):
        self.data, self.ranges, self.max_conns, self.html = data, ranges, max_conns, html
        self.wrong_range = wrong_range  # ignore le début demandé (hors sonde) : réponse à ne pas écrire
        self.active = 0
        self.peak = 0
        self.lock = threading.Lock()
        super().__init__(("127.0.0.1", 0), _Handler)

    @property
    def url(self):
        return f"http://127.0.0.1:{self.server_address[1]}/f"


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        srv = self.server
        if srv.html:
            body = b"<html>captcha</html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        with srv.lock:
            if srv.max_conns and srv.active >= srv.max_conns:
                self.send_response(429)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            srv.active += 1
            srv.peak = max(srv.peak, srv.active)
        try:
            m = re.match(r"bytes=(\d+)-(\d*)", self.headers.get("Range", "")) if srv.ranges else None
            a, b = 0, len(srv.data) - 1
            if m:
                a, b = int(m.group(1)), int(m.group(2)) if m.group(2) else len(srv.data) - 1
                if srv.wrong_range and a > 0:
                    a, b = 0, b - a
                self.send_response(206)
                self.send_header("Content-Range", f"bytes {a}-{b}/{len(srv.data)}")
            else:
                self.send_response(200)
            self.send_header("Content-Length", str(b - a + 1))
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Disposition", 'attachment; filename="Jeu test.part01.rar"')
            self.end_headers()
            for pos in range(a, b + 1, 256 << 10):
                self.wfile.write(srv.data[pos:min(pos + (256 << 10), b + 1)])
                time.sleep(0.02)  # ~12 Mo/s par connexion
        except OSError:
            pass
        finally:
            with srv.lock:
                srv.active -= 1


@pytest.fixture
def file_server():
    servers = []

    def start(**kwargs):
        srv = FileServer(DATA, **kwargs)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        servers.append(srv)
        return srv

    yield start
    for srv in servers:
        srv.shutdown()
