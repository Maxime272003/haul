import os
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from haul import postprocess
from haul.engine import Job, State
from haul.postprocess import (
    ExtractionBlocked,
    ScanReport,
    archive_sets,
    check_entries,
    extract,
    find_winrar,
    parse_technical_listing,
    place_extracted,
    prepare_extraction,
    ready_for_postprocess,
    set_volumes,
    unsafe_entry,
)


def job(dest, name, i=0):
    return Job(i, f"https://fuckingfast.co/x{i}", str(dest), name=name, state=State.DONE)


def test_archive_sets_groups_volumes_and_finds_first_volume_on_disk(tmp_path):
    for n in ("Jeu.part01.rar", "Jeu.part02.rar", "Jeu.part03.rar", "Bonus.rar", "vo.bin"):
        (tmp_path / n).write_bytes(b"")
    # le volume 1 n'est pas dans la liste (téléchargé lors d'une session précédente)
    jobs = [job(tmp_path, n, i) for i, n in enumerate(["Jeu.part02.rar", "Jeu.part03.rar", "Bonus.rar", "vo.bin"])]
    sets = archive_sets(jobs)
    assert {Path(k).name: sorted(j.name for j in v) for k, v in sets.items()} == {
        "Jeu.part01.rar": ["Jeu.part02.rar", "Jeu.part03.rar"],
        "Bonus.rar": ["Bonus.rar"],
    }


def test_archive_sets_ignores_similar_prefix(tmp_path):
    for n in ("Jeu.part1.rar", "Jeu Deluxe.part1.rar"):
        (tmp_path / n).write_bytes(b"")
    sets = archive_sets([job(tmp_path, "Jeu Deluxe.part1.rar")])
    assert [Path(k).name for k in sets] == ["Jeu Deluxe.part1.rar"]


def test_scan_report_propagates_first_volume_verdict(tmp_path):
    first, other = tmp_path / "Jeu.part01.rar", tmp_path / "Jeu.part02.rar"
    report = ScanReport(
        results=[SimpleNamespace(path=first, level="unknown", label="INCONNU DE VT"),
                 SimpleNamespace(path=tmp_path / "vo.bin", level="malicious", label="MALVEILLANT")],
        grouped={"Jeu.part01.rar": [other]},
    )
    verdicts = report.verdicts()
    assert verdicts[os.path.normcase(str(other))] == ("unknown", "INCONNU DE VT")
    assert verdicts[os.path.normcase(str(tmp_path / "vo.bin"))] == ("malicious", "MALVEILLANT")


RAR = r"C:\Program Files\WinRAR\Rar.exe"


@pytest.mark.skipif(not (find_winrar() and os.path.exists(RAR)), reason="WinRAR absent")
def test_extract_multivolume_without_overwriting(tmp_path):
    dest = make_rar(tmp_path)
    (dest / "Jeu").mkdir()
    (dest / "Jeu" / "sauvegarde.dat").write_bytes(b"ancien")  # version précédente : à garder
    unrar = prepare_extraction(find_winrar(), str(dest / "Jeu.part1.rar"))
    progress = []
    code, folder = extract(unrar, str(dest / "Jeu.part1.rar"), progress.append)
    assert (code, folder) == (0, str(dest / "Jeu (2)"))
    assert (dest / "Jeu (2)" / "setup.exe").stat().st_size == 600_000
    assert (dest / "Jeu" / "sauvegarde.dat").read_bytes() == b"ancien"
    assert not [p for p in dest.iterdir() if p.name.startswith(".haul-")]  # dossier temporaire retiré


def test_unsafe_entries():
    for name in (r"..\x.exe", r"Jeu\..\..\x.exe", "/etc/x", r"C:\Windows\x.exe", r"setup.exe:..\..\x.lnk"):
        assert unsafe_entry(name), name
    for name in (r"Jeu\setup.exe", "Jeu", "a..b.txt", r"..jeu\x"):
        assert not unsafe_entry(name), name


def make_extracted(tmp_path, *names):
    tmp = tmp_path / ".haul-x"
    for name in names:
        path = tmp / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"x")
    return str(tmp)


def test_extracted_content_goes_into_the_game_folder_when_it_only_holds_its_volumes(tmp_path):
    for n in ("Jeu.part01.rar", "Jeu.part02.rar"):
        (tmp_path / n).write_bytes(b"")
    tmp = make_extracted(tmp_path, "setup.exe", "fg-01.bin", r"MD5/a.md5")
    assert place_extracted(tmp, str(tmp_path / "Jeu.part01.rar")) == str(tmp_path)
    assert sorted(p.name for p in tmp_path.iterdir()) == ["Jeu.part01.rar", "Jeu.part02.rar", "MD5", "fg-01.bin",
                                                          "setup.exe"]


def test_extracted_single_folder_never_overwrites_an_existing_one(tmp_path):
    (tmp_path / "Jeu.rar").write_bytes(b"")
    (tmp_path / "autre.txt").write_bytes(b"")
    (tmp_path / "Jeu").mkdir()
    (tmp_path / "Jeu" / "save.dat").write_bytes(b"sauvegarde")
    tmp = make_extracted(tmp_path, "Jeu/setup.exe")
    assert place_extracted(tmp, str(tmp_path / "Jeu.rar")) == str(tmp_path / "Jeu (2)")
    assert (tmp_path / "Jeu" / "save.dat").read_bytes() == b"sauvegarde"
    assert (tmp_path / "Jeu (2)" / "setup.exe").exists()
    assert not (tmp_path / ".haul-x").exists()


def test_loose_files_go_into_a_subfolder_named_after_the_game(tmp_path):
    first = tmp_path / "Elden_Ring_--_fitgirl-repacks.site_--_.part01.rar"
    first.write_bytes(b"")
    (tmp_path / "autre.rar").write_bytes(b"")
    tmp = make_extracted(tmp_path, "setup.exe", "fg-01.bin")
    assert place_extracted(tmp, str(first)) == str(tmp_path / "Elden Ring")
    (tmp_path / "setup.exe").write_bytes(b"")  # même un dossier dédié : un nom pris force le sous-dossier
    tmp = make_extracted(tmp_path, "setup.exe")
    assert place_extracted(tmp, str(first)) == str(tmp_path / "Elden Ring (2)")


LT_OUTPUT = """
Archive: Jeu.part1.rar
Details: RAR 5, volume

        Name: Jeu\\setup.exe
        Type: File
        Size: 600000
 Packed size: 204800

        Name: Jeu
        Type: Directory

        Name: Jeu\\lien
        Type: Symbolic link
      Target: C:\\Windows

Archive: Jeu.part2.rar
        Name: Jeu\\setup.exe
        Type: File
        Size: 600000
"""


def test_technical_listing_types_and_sizes():
    assert parse_technical_listing(LT_OUTPUT) == {
        "Jeu\\setup.exe": ("file", 600000), "Jeu": ("directory", None), "Jeu\\lien": ("symbolic link", None)}


def test_links_and_lack_of_space_block_extraction(tmp_path):
    names = ["Jeu", "Jeu\\setup.exe"]
    details = {"Jeu": ("directory", None), "Jeu\\setup.exe": ("file", 1 << 30)}
    check_entries(names, details, str(tmp_path), free_space=8 << 30)
    with pytest.raises(ExtractionBlocked, match="espace disque insuffisant"):
        check_entries(names, details, str(tmp_path), free_space=1 << 30)
    with pytest.raises(ExtractionBlocked, match="lien dans l'archive"):
        check_entries(names, {**details, "Jeu\\l": ("junction", None)}, str(tmp_path), free_space=8 << 30)
    with pytest.raises(ExtractionBlocked, match="chemin dangereux"):
        check_entries(["..\\x.exe"], {}, str(tmp_path), free_space=8 << 30)
    check_entries(names, {}, str(tmp_path), free_space=0)  # listage technique illisible : noms seuls


def test_archive_is_processed_as_soon_as_its_volumes_are_downloaded(tmp_path):
    jobs = [job(tmp_path, "A.part1.rar", 1), job(tmp_path, "A.part2.rar", 2), job(tmp_path, "B.part1.rar", 3),
            job(tmp_path, "B.part2.rar", 4), job(tmp_path, "notes.txt", 5)]
    jobs[3].state = State.DOWNLOADING
    assert [j.id for j in ready_for_postprocess(jobs)] == [1, 2, 5]
    jobs[0].processed = jobs[1].processed = jobs[4].processed = True
    jobs[3].state = State.ERROR  # un volume en échec : le jeu attend
    assert ready_for_postprocess(jobs) == []
    jobs[3].state = State.DONE
    assert [j.id for j in ready_for_postprocess(jobs)] == [3, 4]


def test_set_volumes_lists_only_the_same_set(tmp_path):
    for n in ("Jeu.part1.rar", "Jeu.part2.rar", "Jeu.rar", "Jeu Deluxe.part1.rar", "Jeu.part1.rar.part"):
        (tmp_path / n).write_bytes(b"")
    assert [Path(p).name for p in set_volumes(str(tmp_path / "Jeu.part1.rar"))] == ["Jeu.part1.rar",
                                                                                   "Jeu.part2.rar"]
    assert [Path(p).name for p in set_volumes(str(tmp_path / "Jeu.rar"))] == ["Jeu.rar"]


def test_process_scans_then_extracts_and_recycles_archives(tmp_path, monkeypatch):
    for n in ("Jeu.part1.rar", "Jeu.part2.rar", "vo.bin"):
        (tmp_path / n).write_bytes(b"x")
    batch = [job(tmp_path, n, i) for i, n in enumerate(["Jeu.part1.rar", "Jeu.part2.rar", "vo.bin"])]
    report = ScanReport([SimpleNamespace(path=tmp_path / "Jeu.part1.rar", level="unknown", label="INCONNU DE VT"),
                         SimpleNamespace(path=tmp_path / "vo.bin", level="clean", label="PROPRE")],
                        {"Jeu.part1.rar": [tmp_path / "Jeu.part2.rar"]})
    report.save = lambda: None
    monkeypatch.setattr(postprocess, "scan", lambda paths, notify: report)
    monkeypatch.setattr(postprocess, "prepare_extraction", lambda winrar, first: "UnRAR.exe")
    monkeypatch.setattr(postprocess, "extract", lambda unrar, first, progress: progress(50) or (0, str(tmp_path)))
    recycled = []
    monkeypatch.setattr(postprocess, "recycle", lambda paths: recycled.extend(paths) or True)
    events, messages, reports = [], [], []
    postprocess.process(batch, True, "WinRAR.exe", lambda j, **f: events.append((j.id, f)),
                        lambda m, done=False, kind=None: messages.append((m, done, kind)), delete_archives=True,
                        on_report=reports.append)
    assert reports == [report]
    assert (2, {"vt": "PROPRE"}) in events and (1, {"vt": "INCONNU DE VT"}) in events
    assert (0, {"state": State.EXTRACTING, "detail": "Extraction… 50 %"}) in events
    assert events[-1] == (1, {"state": State.EXTRACTED, "detail": "Extrait ✔ · archives à la corbeille"})
    assert [Path(p).name for p in recycled] == ["Jeu.part1.rar", "Jeu.part2.rar"]
    assert messages[-1][1:] == (True, "ok")


def test_process_blocks_extraction_on_malicious_verdict(tmp_path, monkeypatch):
    (tmp_path / "Jeu.rar").write_bytes(b"x")
    batch = [job(tmp_path, "Jeu.rar")]
    report = ScanReport([SimpleNamespace(path=tmp_path / "Jeu.rar", level="malicious", label="MALVEILLANT")], {})
    report.save = lambda: None
    monkeypatch.setattr(postprocess, "scan", lambda paths, notify: report)
    monkeypatch.setattr(postprocess, "extract", lambda *a: pytest.fail("extraction lancée"))
    events, messages = [], []
    postprocess.process(batch, True, "WinRAR.exe", lambda j, **f: events.append(f),
                        lambda m, done=False, kind=None: messages.append((m, kind)))
    assert events[-1] == {"state": State.BLOCKED, "detail": "Extraction bloquée : analyse VirusTotal"}
    assert messages[-1][1] == "error" and "MALVEILLANT" in messages[-1][0]


def test_old_winrar_is_refused(monkeypatch):
    monkeypatch.setattr(postprocess, "file_version", lambda path: (6, 24))
    assert "CVE-2025-8088" in postprocess.winrar_problem("WinRAR.exe")
    with pytest.raises(ExtractionBlocked, match="7.13"):
        prepare_extraction("WinRAR.exe", "Jeu.rar")
    monkeypatch.setattr(postprocess, "file_version", lambda path: (7, 13))
    assert postprocess.winrar_problem("WinRAR.exe") is None


def make_rar(tmp_path, volume_size="200k"):
    src = tmp_path / "src" / "Jeu"
    src.mkdir(parents=True)
    (src / "setup.exe").write_bytes(os.urandom(600_000))
    dest = tmp_path / "dl"
    dest.mkdir()
    subprocess.run([RAR, "a", "-ep1", "-m0", f"-v{volume_size}", "-idq", str(dest / "Jeu.rar"), str(src)], check=True)
    return dest


@pytest.mark.skipif(not (find_winrar() and os.path.exists(RAR)), reason="WinRAR absent")
def test_missing_volume_fails_without_leaving_anything(tmp_path):
    dest = make_rar(tmp_path)
    first = str(dest / "Jeu.part1.rar")
    unrar = prepare_extraction(find_winrar(), first)
    (dest / "Jeu.part3.rar").unlink()
    with pytest.raises(ExtractionBlocked):
        prepare_extraction(find_winrar(), first)  # listage de tous les volumes
    code, folder = extract(unrar, first)
    assert code != 0 and folder is None
    assert all(p.name.endswith(".rar") for p in dest.iterdir())  # ni dossier temporaire ni contenu partiel
