import hashlib

import pytest

from haul import updater
from haul.updater import UpdateError, is_newer, next_version, parse_version

EXE = b"MZ nouvel executable" * 1000
DIGEST = hashlib.sha256(EXE).hexdigest()
BASE = "https://github.com/Maxime272003/haul/releases/download/v1.0.3/"


def test_versions():
    assert parse_version("v1.2.3") == parse_version("1.2.3") == (1, 2, 3)
    assert parse_version("1.2") is None and parse_version("v1.2.3-beta") is None and parse_version(None) is None
    assert is_newer("v1.0.10", "1.0.9") and not is_newer("v1.0.9", "1.0.9") and not is_newer("x", "1.0.0")


def test_next_version_increments_the_last_release_unless_code_is_ahead():
    assert next_version("1.0.0", []) == "1.0.0"  # première release
    assert next_version("1.0.0", ["v1.0.0"]) == "1.0.1"
    assert next_version("1.0.0", ["v1.0.0", "v1.0.9", "v1.0.10", "autre"]) == "1.0.11"
    assert next_version("1.1.0", ["v1.0.11"]) == "1.1.0"  # montée de version à la main
    with pytest.raises(ValueError):
        next_version("dev", [])


class FakeResponse:
    def __init__(self, status=200, json=None, text="", content=b""):
        self.status_code, self._json, self.text, self.content = status, json, text, content
        self.headers = {"Content-Length": str(len(content))} if content else {}

    def json(self):
        return self._json

    def raise_for_status(self):
        if self.status_code >= 400:
            raise OSError(f"HTTP {self.status_code}")

    def iter_content(self, size):
        for i in range(0, len(self.content), size):
            yield self.content[i:i + size]

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class FakeSession:
    def __init__(self, routes):
        self.routes = routes

    def get(self, url, **kwargs):
        return self.routes[url]

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def release_json(tag="v1.0.3", base=BASE):
    return {"tag_name": tag, "html_url": "https://github.com/Maxime272003/haul/releases/tag/" + tag, "body": "notes",
            "assets": [{"name": "Haul.exe", "browser_download_url": base + "Haul.exe", "size": len(EXE)},
                       {"name": "Haul.exe.sha256", "browser_download_url": base + "Haul.exe.sha256"}]}


def use(monkeypatch, routes):
    monkeypatch.setattr(updater, "_session", lambda current: FakeSession(routes))


def test_latest_release_only_when_newer(monkeypatch):
    use(monkeypatch, {updater.LATEST_URL: FakeResponse(json=release_json())})
    release = updater.latest_release("1.0.2")
    assert (release["version"], release["url"]) == ("1.0.3", BASE + "Haul.exe")
    assert updater.latest_release("1.0.3") is None
    use(monkeypatch, {updater.LATEST_URL: FakeResponse(status=404)})
    assert updater.latest_release("1.0.2") is None  # aucune release publiée


def test_latest_release_refuses_downloads_from_elsewhere(monkeypatch):
    use(monkeypatch, {updater.LATEST_URL: FakeResponse(json=release_json(base="https://evil.example/"))})
    with pytest.raises(UpdateError):
        updater.latest_release("1.0.2")


def test_download_checks_sha256_then_install_swaps_the_executable(monkeypatch, tmp_path):
    exe = tmp_path / "Haul.exe"
    exe.write_bytes(b"ancien")
    release = {"url": BASE + "Haul.exe", "sha256_url": BASE + "Haul.exe.sha256", "size": len(EXE)}
    use(monkeypatch, {release["sha256_url"]: FakeResponse(text=f"{DIGEST}  Haul.exe\r\n"),
                      release["url"]: FakeResponse(content=EXE)})
    progress = []
    new = updater.download(release, "1.0.2", str(exe), lambda done, total: progress.append((done, total)))
    assert new == str(exe) + ".new" and progress[-1] == (len(EXE), len(EXE))
    updater.install(new, str(exe))
    assert exe.read_bytes() == EXE and (tmp_path / "Haul.exe.old").read_bytes() == b"ancien"
    updater.cleanup(str(exe))
    assert sorted(p.name for p in tmp_path.iterdir()) == ["Haul.exe"]


def test_corrupted_download_is_discarded(monkeypatch, tmp_path):
    exe = tmp_path / "Haul.exe"
    exe.write_bytes(b"ancien")
    release = {"url": BASE + "Haul.exe", "sha256_url": BASE + "Haul.exe.sha256", "size": len(EXE)}
    use(monkeypatch, {release["sha256_url"]: FakeResponse(text="0" * 64),
                      release["url"]: FakeResponse(content=EXE)})
    with pytest.raises(UpdateError, match="SHA-256"):
        updater.download(release, "1.0.2", str(exe))
    assert sorted(p.name for p in tmp_path.iterdir()) == ["Haul.exe"]
    with pytest.raises(UpdateError):
        updater.parse_checksum("pas d'empreinte")
