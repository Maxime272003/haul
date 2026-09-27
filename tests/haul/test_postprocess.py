import os
import shutil
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from haul.engine import Job
from haul.postprocess import ScanReport, archive_sets, extract, find_winrar


def job(dest, name, i=0):
    return Job(i, f"https://fuckingfast.co/x{i}", str(dest), name=name, status="Terminé")


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
def test_extract_multivolume_and_overwrite(tmp_path):
    src = tmp_path / "src" / "Jeu"
    src.mkdir(parents=True)
    payload = os.urandom(600_000)
    (src / "setup.exe").write_bytes(payload)
    dest = tmp_path / "dl"
    dest.mkdir()
    subprocess.run([RAR, "a", "-ep1", "-m0", "-v200k", "-idq", str(dest / "Jeu.rar"), str(src)], check=True)
    shutil.rmtree(tmp_path / "src")
    (dest / "Jeu").mkdir()
    (dest / "Jeu" / "setup.exe").write_bytes(b"ancien")
    os.utime(dest / "Jeu" / "setup.exe", (0, 0))  # plus ancien : doit être remplacé sans question

    assert extract(find_winrar(), str(dest / "Jeu.part1.rar")) == 0
    assert (dest / "Jeu" / "setup.exe").read_bytes() == payload
