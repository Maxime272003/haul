# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

Haul is a Windows-only Tkinter download manager for FuckingFast links (clipboard watching, multi-connection downloads, VirusTotal check via the bundled `vtzip` package, then WinRAR extraction). The codebase, UI strings, comments, docstrings, commit messages and CHANGELOG are written in **French** — keep it that way.

## Commands

All tooling runs from the `.venv` (PowerShell):

```powershell
py -3.12 -m venv .venv
.venv\Scripts\python -m pip install -e ".[dev]"
.venv\Scripts\haul                                   # run the app (or: python -m haul)
.venv\Scripts\pytest                                 # all tests
.venv\Scripts\pytest tests\haul\test_engine.py::test_name   # single test
.venv\Scripts\ruff check src tests                   # lint (line length 120, py310 target)
.\scripts\build.ps1                                  # PyInstaller -> dist\Haul.exe
.venv\Scripts\python scripts\make_icon.py            # regenerate assets\haul.ico / haul.png (Pillow)
.venv\Scripts\vtzip --deep C:\path                   # vtzip standalone CLI
.venv\Scripts\python scripts\bench.py <url>          # throughput benchmark (files x connections)
```

CI (`.github/workflows/ci.yml`) runs ruff + pytest on Windows with Python 3.10 and 3.12, then builds the exe. WinRAR-dependent tests in `tests/haul/test_postprocess.py` are skipped if WinRAR is not installed. Download tests use the local `file_server` fixture in `tests/haul/conftest.py` (Range support, 429 simulation, connection limits, wrong ranges) — no network needed.

## Architecture

End-to-end flow: clipboard (HTML format, `clipboard.py` + `links.py`), dropped files or the "Ajouter des liens…" dialog → `Engine` opens each page in the user's browser **one at a time** (captcha validated once covers the next ones) → the userscript `src/haul/assets/haul.user.js` clicks DOWNLOAD and POSTs the direct link to the local server → `Downloader` fetches it with segmented ranges → as soon as every volume of a set in the list is on disk (`postprocess.ready_for_postprocess`), `gui._postprocess` runs `postprocess.process` in a worker thread: `scan` (vtzip), then UnRAR extraction.

**Threading model** — the key cross-file invariant:

- `Engine` (`engine.py`) never mutates `Job` fields shown in the UI directly; it publishes `(job.id, {field: value})` into `App.events`. The GUI thread drains it every 200 ms (`App._drain_events`) and applies fields to the `Job`. Messages with `job_id=None` are status-bar messages from the post-process worker.
- Other threads hand work to the Tk thread via `App.calls` (callables) and `App.incoming` (links for pages the app didn't open). Never touch Tk widgets off the main thread.
- Inside `Engine`, one resolver thread handles the browser/captcha step (`_to_resolve` list + `_resolve_ready` condition, reorderable by `prioritize()`; a job is popped and registered in `_waiting` — keyed by `page_key` — in the same critical section so `pause()` always finds it); download threads are started by `_pump()` up to `max_parallel` (temporarily lowered via `_busy_cap` when the server answers 429/503). Pause is cooperative: `pause()` cancels the `Downloader`, sets the waiting event or cancels a retry timer, and the worker publishes `PAUSED`.
- Failures: network errors (`downloader.NETWORK_ERRORS`, refused connections) go to `State.RETRY` with a `threading.Timer` (`RETRY_DELAYS`); `LinkExpired` reopens the page once; `DiskFull` (checked after the probe, counting other downloads on the same drive) is a plain error that keeps `dl_url`. `submit()` resets these counters.
- `State` (`engine.py`) is the typed job state; `ACTIVE` / `ON_DISK` sets drive GUI logic. Add new states there and in `LABELS`, and `gui.KINDS` (a test asserts every state is covered).

**Downloader** (`downloader.py`, curl_cffi with Chrome TLS fingerprint for Cloudflare): probe, then N range connections writing to a sparse `<name>.part` with resume state in `<name>.part.json`. Each segment's `Content-Range` must match exactly what was requested. A free connection takes half of the biggest in-progress segment (`_split`, under lock; the owner re-reads `seg[1]` at every chunk), and a request is restarted when the speed limit changes by more than 20 %. `Refused.busy` distinguishes a saturated server (keep the link, requeue) from an expired link (`job.dl_url = None`, `LinkExpired`).

**Local server** (`server.py`, `127.0.0.1:17655`): `/haul.user.js`, `/token`, `/wanted`, `/found`, `/show` (a second launch asks the running instance to show itself; token required, no `Origin`). The userscript sends its version in `X-Haul-Script` (`on_script`), and `/wanted` goes through `Engine.page_checked`, which lets the engine warn (`NO_SCRIPT`) when an opened page never hears from the script. Security checks are deliberate and tested in `test_server.py`: Host header check (DNS rebinding), per-install token in `X-Haul-Token` (from `config.json`), `/token` readable only by extension origins with `Sec-Fetch-Dest: empty`, body size cap, URL regexes from `links.py`. Only `https://fuckingfast.co/…` page URLs may reach `os.startfile` (`is_page_url`). The userscript does not embed the token — it fetches it, so changing the script means bumping its `@version` (served for auto-update), and `on_bad_token` reports outdated copies.

**Post-processing** (`postprocess.py`): `BLOCKING_LEVELS` = malicious/suspicious/error (unknown and generic detections intentionally do *not* block — see `docs/vtzip.md`). Before extraction: WinRAR ≥ 7.13 (CVE-2025-6218/8088), every entry of every volume (`UnRAR lb`) checked for absolute paths / `..` / NTFS streams, link entries and unpacked size from `UnRAR lt` (ignored if unparseable). UnRAR then extracts into a hidden temp dir next to the archive (CRCs checked, removed on failure) and `place_extracted` moves the content without ever overwriting (`unique_path`). `process()` only publishes through `put` / `status` callbacks — it never mutates jobs. vtzip is imported lazily from here and from `dialogs.py`.

**Desktop integration** (`desktop.py`): named mutex for single instance (`__main__` then POSTs `/show`), port owner lookup, HKCU `Run` autostart (`--minimized`), `Tray` (own thread + hidden window + message loop; `on_command` must only forward to `App.calls`), `FileDrop` (subclassed Tk window procedure). Every ctypes call uses a private `WinDLL` instance with explicit argtypes and fails soft.

**vtzip** (`src/vtzip/`) is a standalone package (own CLI, config in `%APPDATA%\vtzip`, DPAPI-encrypted API key, 24 h result cache) that Haul consumes as a library; keep it free of `haul` imports.

**Persistence** (`paths.py`): everything lives in `%APPDATA%\Haul` (`config.json`, `queue.json`, `haul.log`, `reports/`), never next to the exe. JSON files are written atomically via `.tmp` + `replace`. `config.load()` only accepts keys present in `DEFAULTS` with the same type — add new settings to `DEFAULTS`. Bundled assets resolve through `sys._MEIPASS` when frozen.

`gui.py` is the large Tk `App` (list grouped by volume set, sortable, filterable — `_layout()` rebuilds order/groups when `layout_dirty`); `dialogs.py` holds secondary windows; `theme.py` (light/dark palette, ttk styles, drawn shapes/PNG generation) and `widgets.py` (fluid layout, steppers, tooltips) support it; `notify.py` wraps Win32 notifications and taskbar progress.

## Conventions

- `__main__.setup_logging` uses a rotating `haul.log` and routes uncaught exceptions (main, threads, Tk callbacks via `App._on_tk_error`) to it.
- `.editorconfig`: LF endings (CRLF for `.ps1`), 4-space indent, 2 for yml/json/toml.
- User-facing changes go in `CHANGELOG.md` under `[Non publié]` (Keep a Changelog, in French). Version lives in `src/haul/__init__.py`: it is the *base* version — every push to `main` publishes a GitHub release (`ci.yml` job `release`) whose number `scripts/next_version.py` derives from the existing `vX.Y.Z` tags (patch + 1, or the base if it is higher) and writes into the built exe only. Bump `__version__` by hand only for a minor/major release.
- **Self-update** (`updater.py`): the frozen app polls `releases/latest` of the public repo, downloads `Haul.exe` next to itself (`.new`, SHA-256 from the `Haul.exe.sha256` asset, URLs restricted to this repo's release downloads), and `_on_close` swaps it in (running exe renamed to `.old`, cleaned at next start). A restart relaunches with `--wait-pid` so the new process waits for the old one before taking the single-instance mutex. Release assets must keep the names `Haul.exe` and `Haul.exe.sha256`.
