"""Tests du client VirusTotal avec une session HTTP simulee (aucun appel reseau)."""

from __future__ import annotations

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

import requests

from vtzip.vt import (
    DIRECT_UPLOAD_LIMIT,
    KNOWN,
    UNKNOWN,
    QuotaExceeded,
    RateLimiter,
    VirusTotalClient,
    VTError,
)


class FakeResponse:
    def __init__(self, status_code: int, payload=None, text: str = ""):
        self.status_code = status_code
        self._payload = payload
        self.text = text

    def json(self):
        if self._payload is None:
            raise ValueError("pas de JSON")
        return self._payload


class FakeSession:
    """Rejoue une liste de reponses et enregistre les appels effectues."""

    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []
        self.headers = {}

    def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        if not self.responses:
            raise AssertionError(f"appel inattendu : {method} {url}")
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


FILE_PAYLOAD = {
    "data": {
        "attributes": {
            "last_analysis_stats": {"malicious": 4, "suspicious": 1, "undetected": 60},
            "last_analysis_results": {
                "Alpha": {"category": "malicious", "result": "Trojan.RedLine"},
                "Beta": {"category": "malicious", "result": "HackTool:Win32/Keygen"},
            },
            "type_description": "Win32 EXE",
        }
    }
}

SHA = "d" * 64


def make_client(responses, **kwargs):
    client = VirusTotalClient("k" * 64, rpm=0, **kwargs)
    client.session = FakeSession(responses)
    return client


class TestLookup(unittest.TestCase):
    def test_fichier_connu(self):
        client = make_client([FakeResponse(200, FILE_PAYLOAD)])
        verdict = client.lookup_hash(SHA)
        self.assertEqual(verdict.status, KNOWN)
        self.assertEqual(verdict.malicious, 4)
        self.assertEqual(len(verdict.engine_hits), 2)
        method, url, _ = client.session.calls[0]
        self.assertEqual(method, "GET")
        self.assertTrue(url.endswith(f"/files/{SHA}"))
        self.assertEqual(client.requests_made, 1)

    def test_fichier_inconnu_404(self):
        client = make_client([FakeResponse(404, {"error": {"code": "NotFoundError"}})])
        verdict = client.lookup_hash(SHA)
        self.assertEqual(verdict.status, UNKNOWN)
        self.assertIn("VirusTotal", verdict.message)
        self.assertTrue(verdict.permalink.endswith(SHA))

    def test_cle_invalide_401(self):
        client = make_client([FakeResponse(401, {"error": {"message": "Wrong key"}})])
        with self.assertRaises(VTError) as ctx:
            client.lookup_hash(SHA)
        self.assertIn("401", str(ctx.exception))

    def test_quota_429(self):
        client = make_client([FakeResponse(429, {"error": {"code": "QuotaExceededError"}})])
        with self.assertRaises(QuotaExceeded):
            client.lookup_hash(SHA)

    def test_erreur_serveur_remonte_le_message(self):
        client = make_client([FakeResponse(503, {"error": {"message": "indisponible"}})])
        with self.assertRaises(VTError) as ctx:
            client.lookup_hash(SHA)
        self.assertIn("503", str(ctx.exception))
        self.assertIn("indisponible", str(ctx.exception))

    def test_erreur_reseau(self):
        client = make_client([requests.ConnectionError("pas de route")])
        with self.assertRaises(VTError) as ctx:
            client.lookup_hash(SHA)
        self.assertIn("réseau", str(ctx.exception))

    def test_reponse_non_json(self):
        client = make_client([FakeResponse(500, None, text="<html>oops</html>")])
        with self.assertRaises(VTError):
            client.lookup_hash(SHA)


class MemoryCache:
    def __init__(self):
        self.data = {}

    def get(self, key):
        return self.data.get(key)

    def set(self, key, value):
        self.data[key] = value

    def flush(self):
        pass


class TestCache(unittest.TestCase):
    def test_le_second_appel_ne_touche_pas_le_reseau(self):
        cache = MemoryCache()
        client = make_client([FakeResponse(200, FILE_PAYLOAD)], cache=cache)
        first = client.lookup_hash(SHA)
        second = client.lookup_hash(SHA)  # aucune reponse restante : doit venir du cache
        self.assertEqual(client.requests_made, 1)
        self.assertEqual(second.malicious, first.malicious)
        self.assertEqual(second.engine_hits, first.engine_hits)
        self.assertEqual(second.status, KNOWN)


class TestUpload(unittest.TestCase):
    def setUp(self):
        self._tmp = TemporaryDirectory()
        self.path = Path(self._tmp.name) / "petit.zip"
        self.path.write_bytes(b"PK\x03\x04" + b"\0" * 100)

    def tearDown(self):
        self._tmp.cleanup()

    def test_upload_direct(self):
        client = make_client([FakeResponse(200, {"data": {"id": "analyse-1"}})])
        self.assertEqual(client.upload(self.path), "analyse-1")
        method, url, kwargs = client.session.calls[0]
        self.assertEqual(method, "POST")
        self.assertTrue(url.endswith("/files"))
        self.assertIn("file", kwargs["files"])

    def test_gros_fichier_passe_par_upload_url(self):
        client = make_client([
            FakeResponse(200, {"data": "https://upload.virustotal.com/xyz"}),
            FakeResponse(200, {"data": {"id": "analyse-2"}}),
        ])
        # on evite d'ecrire 33 Mo sur le disque : la taille est lue via stat()
        big = self.path
        original_stat = Path.stat

        def fake_stat(self, *args, **kw):
            result = original_stat(self, *args, **kw)
            if self == big:
                class S:
                    st_size = DIRECT_UPLOAD_LIMIT + 1
                return S()
            return result

        Path.stat = fake_stat
        try:
            self.assertEqual(client.upload(big), "analyse-2")
        finally:
            Path.stat = original_stat
        self.assertTrue(client.session.calls[0][1].endswith("/files/upload_url"))
        self.assertEqual(client.session.calls[1][1], "https://upload.virustotal.com/xyz")

    def test_attente_d_analyse(self):
        client = make_client([
            FakeResponse(200, {"data": {"attributes": {"status": "queued"}}}),
            FakeResponse(200, {"data": {"attributes": {"status": "completed"}}}),
        ])
        seen = []
        status = client.wait_for_analysis("id", on_poll=lambda s, n: seen.append(s))
        self.assertEqual(status, "completed")
        self.assertEqual(seen, ["queued", "completed"])


class TestQuotaInterruption(unittest.TestCase):
    """Un quota epuise en cours de scan doit etre annonce, pas subi en silence."""

    def setUp(self):
        self._tmp = TemporaryDirectory()
        self.dir = Path(self._tmp.name)
        for name in ("a.exe", "b.exe", "c.exe"):
            (self.dir / name).write_bytes(b"MZ" + name.encode())

    def tearDown(self):
        self._tmp.cleanup()

    def test_les_fichiers_suivants_sont_marques_non_verifies(self):
        from vtzip.scanner import Scanner, collect_files

        client = make_client([
            FakeResponse(200, FILE_PAYLOAD),
            FakeResponse(429, {"error": {"code": "QuotaExceededError"}}),
        ])
        scanner = Scanner(client)
        results = [scanner.scan_file(path) for path in collect_files(self.dir)]

        self.assertTrue(scanner.quota_hit)
        self.assertIsNotNone(scanner.quota_message)
        # 1er fichier verifie, 2e en erreur de quota, 3e explicitement non verifie
        self.assertEqual(results[0].verdict.status, KNOWN)
        self.assertIn("Quota", results[1].verdict.message)
        self.assertIn("Quota", results[2].verdict.message)
        # et surtout : aucun appel reseau supplementaire n'a ete tente
        self.assertEqual(client.requests_made, 2)

    def test_le_message_distingue_offline_et_quota(self):
        from vtzip.scanner import Scanner

        offline = Scanner(None)
        verdict, _ = offline._lookup("a" * 64)
        self.assertNotIn("Quota", verdict.message)


class TestRateLimiter(unittest.TestCase):
    def test_rpm_zero_ne_bride_pas(self):
        limiter = RateLimiter(0)
        for _ in range(50):
            limiter.acquire()  # ne doit jamais bloquer

    def test_fenetre_glissante_previent_avant_d_attendre(self):
        waits = []
        limiter = RateLimiter(2, on_wait=waits.append)
        limiter._calls.extend([__import__("time").monotonic()] * 2)
        original_sleep = __import__("time").sleep
        import time as _time

        _time.sleep = lambda s: None
        try:
            limiter.acquire()
        finally:
            _time.sleep = original_sleep
        self.assertEqual(len(waits), 1)
        self.assertGreater(waits[0], 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
