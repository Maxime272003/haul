"""Tests du support RAR : parsing du listage, volumes, scan profond.

Le parsing est teste sur des sorties figees (anglais ET francais) pour verifier
qu'il ne depend pas de la langue de UnRAR. Les tests d'integration sont ignores
si UnRAR n'est pas installe sur la machine.
"""

from __future__ import annotations

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from vtzip.rarscan import (
    count_volumes,
    find_unrar,
    group_volume_sets,
    inspect_rar,
    is_first_volume,
    iter_entry_hashes,
    parse_unrar_listing,
    volume_info,
)

LISTING_FR = """
UNRAR 7.22 x64 Freeware      Copyright (c) 1993-2026 Alexander Roshal

Archive: C:\\jeux\\repack.rar
Détails: RAR 5

 Attributs      Taille    Date   Heure   Nom
----------- ----------  ---------- -----  ----
    ..A....       2048  2026-07-25 15:32  setup.exe
    ..A....       1024  2026-07-25 15:32  Crack\\activator.exe
    ..A....         45  2026-07-25 15:32  Lisez moi.txt
    ...D...          0  2026-07-25 15:32  Crack
----------- ----------  ---------- -----  ----
                  3117                    4
"""

LISTING_EN = """
UNRAR 7.22 x64 Freeware      Copyright (c) 1993-2026 Alexander Roshal

Archive: C:\\games\\repack.rar
Details: RAR 5

 Attributes      Size     Date    Time   Name
----------- ---------  ---------- -----  ----
    ..A....      2048  2026-07-25 15:32  setup.exe
*   ..A....      4096  2026-07-25 15:32  secret.dll
----------- ---------  ---------- -----  ----
                 6144                    2
"""


class TestParsing(unittest.TestCase):
    def test_listage_francais(self):
        entries = parse_unrar_listing(LISTING_FR)
        self.assertEqual(len(entries), 4)
        self.assertEqual(entries[0].name, "setup.exe")
        self.assertEqual(entries[0].size, 2048)
        self.assertFalse(entries[0].is_dir)
        self.assertEqual(entries[1].name, "Crack\\activator.exe")
        self.assertEqual(entries[1].basename, "activator.exe")
        self.assertTrue(entries[3].is_dir)

    def test_listage_anglais_et_marqueur_de_chiffrement(self):
        entries = parse_unrar_listing(LISTING_EN)
        self.assertEqual(len(entries), 2)
        self.assertFalse(entries[0].encrypted)
        self.assertTrue(entries[1].encrypted)
        self.assertEqual(entries[1].name, "secret.dll")
        self.assertEqual(entries[1].size, 4096)

    def test_nom_avec_espaces(self):
        entries = parse_unrar_listing(LISTING_FR)
        self.assertIn("Lisez moi.txt", [e.name for e in entries])

    def test_sortie_vide_ou_bruit(self):
        self.assertEqual(parse_unrar_listing(""), [])
        self.assertEqual(parse_unrar_listing("Mot de passe incorrect\n"), [])


class TestVolumes(unittest.TestCase):
    def test_numero_de_volume_moderne(self):
        self.assertEqual(volume_info(Path("jeu.part01.rar")), ("jeu", 1))
        self.assertEqual(volume_info(Path("jeu.part07.rar")), ("jeu", 7))
        self.assertEqual(volume_info(Path("JEU.PART02.RAR")), ("jeu", 2))

    def test_numero_de_volume_ancien(self):
        # jeu.rar est le volume 1, jeu.r00 le deuxieme.
        self.assertEqual(volume_info(Path("jeu.rar")), ("jeu", 1))
        self.assertEqual(volume_info(Path("jeu.r00")), ("jeu", 2))
        self.assertEqual(volume_info(Path("jeu.r13")), ("jeu", 15))

    def test_fichier_hors_jeu(self):
        self.assertEqual(volume_info(Path("data.bin")), (None, None))

    def test_premier_volume(self):
        self.assertTrue(is_first_volume(Path("jeu.part01.rar")))
        self.assertTrue(is_first_volume(Path("data.bin")))
        self.assertFalse(is_first_volume(Path("jeu.part02.rar")))


class TestGroupVolumeSets(unittest.TestCase):
    def setUp(self):
        self._tmp = TemporaryDirectory()
        self.dir = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def _touch(self, *names: str) -> list[Path]:
        paths = []
        for name in names:
            path = self.dir / name
            path.write_bytes(b"x" * 10)
            paths.append(path)
        return paths

    def test_un_jeu_se_reduit_au_premier_volume(self):
        paths = self._touch(*[f"jeu.part{i:02d}.rar" for i in range(1, 11)])
        kept, dropped = group_volume_sets(paths)
        self.assertEqual([p.name for p in kept], ["jeu.part01.rar"])
        self.assertEqual(len(dropped["jeu.part01.rar"]), 9)

    def test_les_autres_fichiers_sont_conserves(self):
        paths = self._touch("jeu.part01.rar", "jeu.part02.rar",
                            "data.bin", "autre.zip")
        kept, _ = group_volume_sets(paths)
        self.assertEqual(
            sorted(p.name for p in kept),
            ["autre.zip", "data.bin", "jeu.part01.rar"],
        )

    def test_un_rar_seul_n_est_pas_traite_comme_un_jeu(self):
        paths = self._touch("solo.rar")
        kept, dropped = group_volume_sets(paths)
        self.assertEqual([p.name for p in kept], ["solo.rar"])
        self.assertEqual(dropped, {})

    def test_comptage_des_volumes(self):
        paths = self._touch(*[f"jeu.part{i:02d}.rar" for i in range(1, 6)])
        self.assertEqual(count_volumes(paths[0]), 5)

    def test_deux_jeux_distincts(self):
        paths = self._touch("a.part01.rar", "a.part02.rar",
                            "b.part01.rar", "b.part02.rar")
        kept, dropped = group_volume_sets(paths)
        self.assertEqual(sorted(p.name for p in kept), ["a.part01.rar", "b.part01.rar"])
        self.assertEqual(len(dropped), 2)


@unittest.skipUnless(find_unrar(), "UnRAR non installé")
class TestIntegrationRar(unittest.TestCase):
    """Tests de bout en bout sur de vraies archives creees avec Rar.exe."""

    @classmethod
    def setUpClass(cls):
        import subprocess

        cls._tmp = TemporaryDirectory()
        cls.dir = Path(cls._tmp.name)
        content = cls.dir / "src"
        content.mkdir()
        (content / "setup.exe").write_bytes(b"MZ" + b"\0" * 500)
        (content / "facture.pdf.exe").write_bytes(b"MZ" + b"\0" * 100)
        (content / "readme.txt").write_text("bonjour")
        crack = content / "Crack"
        crack.mkdir()
        (crack / "activator.exe").write_bytes(b"MZ" + b"\0" * 300)

        rar = Path(find_unrar()).parent / "Rar.exe"
        cls.rar_tool = rar if rar.is_file() else None
        if cls.rar_tool is None:
            return
        cls.archive = cls.dir / "repack.rar"
        subprocess.run(
            [str(rar), "a", "-r", "-idq", "-ep1", str(cls.archive), str(content)],
            check=True, capture_output=True,
        )

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def setUp(self):
        if getattr(self, "rar_tool", None) is None:
            self.skipTest("Rar.exe absent (UnRAR seul ne cree pas d'archive)")

    def test_inspection_reelle(self):
        report = inspect_rar(self.archive)
        self.assertTrue(report.readable, report.error)
        self.assertEqual(report.fmt, "rar")
        names = {e.basename for e in report.entries if not e.is_dir}
        self.assertIn("setup.exe", names)
        self.assertIn("activator.exe", names)
        codes = {f.code for f in report.findings}
        self.assertIn("executable", codes)
        self.assertIn("double_extension", codes)

    def test_hash_dune_entree_sans_extraction(self):
        import hashlib

        report = inspect_rar(self.archive)
        target = [e for e in report.entries
                  if e.basename == "setup.exe" and not e.is_dir]
        self.assertTrue(target, "setup.exe absent du listage")
        results = list(iter_entry_hashes(self.archive, target, 1, 10 * 1024 * 1024))
        entry, sha256, reason = results[0]
        self.assertIsNone(reason, f"raison inattendue : {reason}")
        expected = hashlib.sha256(b"MZ" + b"\0" * 500).hexdigest()
        self.assertEqual(sha256, expected)

    def test_archive_chiffree_signale_les_en_tetes(self):
        import subprocess

        encrypted = self.dir / "chiffre.rar"
        subprocess.run(
            [str(self.rar_tool), "a", "-idq", "-hpSECRET", str(encrypted),
             str(self.dir / "src" / "readme.txt")],
            check=True, capture_output=True,
        )
        report = inspect_rar(encrypted)
        self.assertFalse(report.readable)
        self.assertTrue(report.encrypted)
        self.assertIn("encrypted_headers", {f.code for f in report.findings})


if __name__ == "__main__":
    unittest.main(verbosity=2)
