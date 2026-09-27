"""Tests unitaires : classification des detections, heuristiques zip, verdicts."""

from __future__ import annotations

import unittest
import zipfile
from pathlib import Path
from tempfile import TemporaryDirectory

from vtzip.scanner import (
    L_CLEAN,
    L_ERROR,
    L_GENERIC,
    L_MALICIOUS,
    L_SUSPICIOUS,
    L_UNKNOWN,
    InnerResult,
    ScanResult,
    _finalize,
    collect_files,
    verdict_level,
    worst,
)
from vtzip.threats import CRITICAL, GENERIC, OTHER, classify, summarize
from vtzip.vt import ERROR, KNOWN, SKIPPED, UNKNOWN, FileVerdict, _parse_file_object
from vtzip.zipscan import (
    WARN,
    ArchiveReport,
    Entry,
    Finding,
    display_name,
    inspect_zip,
    sniff_type,
)


class TestClassification(unittest.TestCase):
    def test_familles_connues_sont_critiques(self):
        for result in ("Trojan.Win32.RedLine.abc", "Gen:Variant.Lumma.1",
                       "Win32/AsyncRAT.A", "Trojan:Win32/XMRig!MTB",
                       "Backdoor.Amadey", "Vidar.Stealer"):
            with self.subTest(result=result):
                self.assertEqual(classify("Engine", result).level, CRITICAL)

    def test_bruit_de_crack_est_generique(self):
        for result in ("HackTool:Win32/Keygen", "Riskware.Patcher",
                       "PUA.Crack", "Gen:Variant.Packed.1", "not-a-virus:Keygen",
                       "Win32:Themida-packed", "ML.Attribute.HighConfidence"):
            with self.subTest(result=result):
                self.assertEqual(classify("Engine", result).level, GENERIC)

    def test_libelles_boilerplate_des_moteurs(self):
        # Libelles releves sur de vrais scans : aucun ne nomme de famille, ils ne
        # doivent donc pas faire monter le verdict. La regle est structurelle
        # (plus rien de nommant apres retrait des tokens de remplissage), pas une
        # liste de motifs, qui ne couvrirait jamais 70 moteurs.
        for result in ("Malicious", "Unsafe", "W32.Malware.Gen",
                       "Trojan.Malware.695641994.susgen", "W32.AIDetectMalware",
                       "BehavesLike.Win32.Dropper.fc", "Trojan:Win32/Wacatac.B!ml",
                       "Program:Win32/Wacapew.C!ml", "Gen:Variant.Tedy.512345",
                       "HEUR/AGEN.1319544", "Riskware/Application",
                       "TrojanDownloader:Win32/Generic", "Win32.Trojan.Gen.Static"):
            with self.subTest(result=result):
                self.assertEqual(classify("Engine", result).level, GENERIC)

    def test_detection_nommee_inconnue_reste_a_examiner(self):
        # Un nom qui subsiste apres nettoyage : famille inconnue de la table,
        # donc a examiner. Rovnix est un vrai bootkit non repertorie ici.
        for result in ("Trojan.Zlorp.42", "Win32.Blorptastic.A",
                       "TrojanDropper:Win32/Rovnix"):
            with self.subTest(result=result):
                self.assertEqual(classify("Engine", result).level, OTHER)

    def test_la_famille_la_plus_specifique_gagne(self):
        detection = classify("Engine", "Ransom.Win32.LockBit.gen")
        self.assertEqual(detection.family, "lockbit")
        self.assertEqual(detection.kind, "ransomware")

    def test_mots_courts_exigent_un_mot_entier(self):
        # "stop" est une famille de ransomware, mais pas dans "stopwatch".
        self.assertEqual(classify("Engine", "Ransom.STOP.gen").level, CRITICAL)
        self.assertNotEqual(classify("Engine", "Tool.Stopwatch").level, CRITICAL)

    def test_resume_priorise_le_critique(self):
        summary = summarize([
            ("A", "HackTool:Win32/Keygen"),
            ("B", "Trojan.RedLine.Stealer"),
            ("C", "Riskware.Crack"),
        ])
        self.assertEqual(summary.detections[0].level, CRITICAL)
        self.assertEqual(summary.families, ["redline"])
        self.assertEqual(summary.kinds, ["stealer"])
        self.assertEqual(len(summary.generic), 2)


class TestVerdictLevel(unittest.TestCase):
    def test_famille_identifiee_est_malveillant_meme_avec_peu_de_moteurs(self):
        verdict = FileVerdict(status=KNOWN, malicious=3, engines=70)
        threat = summarize([("A", "Trojan.Lumma"), ("B", "Gen:Variant.Lumma.2"),
                            ("C", "HackTool")])
        self.assertEqual(verdict_level(verdict, threat), L_MALICIOUS)

    def test_famille_nommee_par_un_seul_moteur_nest_pas_corroboree(self):
        # Cas reel : setup.exe d'un repack, 18/71. Un seul moteur (Ikarus) dit
        # "Meterpreter" tandis que l'etiquette agregee de VirusTotal dit
        # "trojan.crack/pomal". Les editeurs bavards collent des noms de RAT sur
        # tout binaire qui manipule de la memoire : SUSPECT, pas MALVEILLANT.
        hits = [("Ikarus", "Trojan.Win64.Meterpreter"),
                ("Kingsoft", "Win32.Troj.pomal.v"),
                ("Microsoft", "Trojan:Win32/Pomal!rfn"),
                ("Sangfor", "Trojan.Win32.Agent.Vpyx"),
                ("McAfee", "Artemis!71D5B6735FBD")]
        threat = summarize(hits, ["trojan.crack/pomal", "crack", "pomal"])
        self.assertFalse(threat.corroborated)
        self.assertEqual(threat.families, ["meterpreter"])
        self.assertEqual(
            verdict_level(FileVerdict(status=KNOWN, malicious=18, engines=71), threat),
            L_SUSPICIOUS,
        )

    def test_etiquette_virustotal_corrobore_un_moteur_isole(self):
        hits = [("Ikarus", "Trojan.Win32.RedLine"), ("Autre", "Gen:Variant.Zop")]
        threat = summarize(hits, ["trojan.redline/stealer", "redline"])
        self.assertTrue(threat.corroborated)
        self.assertEqual(
            verdict_level(FileVerdict(status=KNOWN, malicious=2, engines=70), threat),
            L_MALICIOUS,
        )

    def test_deux_moteurs_concordants_suffisent_sans_etiquette(self):
        hits = [("A", "Trojan.Amadey"), ("B", "Win32/Amadey.gen")]
        threat = summarize(hits, [])
        self.assertTrue(threat.corroborated)

    def test_beaucoup_de_generiques_reste_generique(self):
        # Le cas typique du crack : 12 moteurs qui crient HackTool ne doivent pas
        # se lire comme une menace, sinon le classificateur ne sert a rien.
        verdict = FileVerdict(status=KNOWN, malicious=0, suspicious=12, engines=70)
        threat = summarize([(f"E{i}", "HackTool:Win32/Keygen") for i in range(12)])
        self.assertEqual(verdict_level(verdict, threat), L_GENERIC)

    def test_detections_nommees_selon_le_consensus(self):
        few = summarize([("A", "Trojan.Zlorp"), ("B", "Win32.Blah")])
        self.assertEqual(
            verdict_level(FileVerdict(status=KNOWN, malicious=2, engines=70), few),
            L_SUSPICIOUS,
        )
        many = summarize([(f"E{i}", "Trojan.Zlorp.gen") for i in range(6)])
        self.assertEqual(
            verdict_level(FileVerdict(status=KNOWN, malicious=6, engines=70), many),
            L_MALICIOUS,
        )

    def test_seuils_sans_famille(self):
        self.assertEqual(
            verdict_level(FileVerdict(status=KNOWN, malicious=6, engines=70), summarize([])),
            L_MALICIOUS,
        )
        self.assertEqual(
            verdict_level(FileVerdict(status=KNOWN, malicious=1, engines=70), summarize([])),
            L_SUSPICIOUS,
        )
        self.assertEqual(
            verdict_level(FileVerdict(status=KNOWN, engines=70), summarize([])),
            L_CLEAN,
        )

    def test_statuts_non_connus(self):
        self.assertEqual(verdict_level(FileVerdict(status=UNKNOWN), None), L_UNKNOWN)
        self.assertEqual(verdict_level(FileVerdict(status=SKIPPED), None), L_UNKNOWN)
        self.assertEqual(verdict_level(FileVerdict(status=ERROR), None), L_ERROR)

    def test_worst_prend_le_pire(self):
        self.assertEqual(worst([L_CLEAN, L_GENERIC, L_MALICIOUS]), L_MALICIOUS)
        self.assertEqual(worst([L_CLEAN, L_UNKNOWN]), L_UNKNOWN)
        self.assertEqual(worst([]), L_CLEAN)


class TestFinalizeVerdict(unittest.TestCase):
    """Verifie ce qui fait monter le verdict global d'une archive."""

    def _result(self, findings, inner_levels=(), outer=None):
        report = ArchiveReport(is_archive=True, readable=True, fmt="rar")
        report.findings = [Finding(WARN, code, code) for code in findings]
        report.encrypted = "encrypted" in findings
        result = ScanResult(path=Path("repack.rar"))
        result.archive = report
        result.verdict = outer or FileVerdict(status=UNKNOWN)
        result.inner = [
            InnerResult(entry=Entry("x", 1, 1, False, False, 0), level=level)
            for level in inner_levels
        ]
        _finalize(result)
        return result

    def test_contenir_un_executable_ne_rend_pas_suspect(self):
        # Cas reel : un repack contient QuickSFV.EXE, dont les 4 detections sont
        # generiques. Le verdict doit rester "generique", pas "suspect" : toute
        # archive d'installation contient un installeur.
        result = self._result(["executable"], inner_levels=[L_GENERIC])
        self.assertEqual(result.level, L_GENERIC)

    def test_la_tromperie_rend_suspect(self):
        for code in ("double_extension", "bidi_override", "zip_slip",
                     "zip_bomb", "type_mismatch", "encrypted"):
            with self.subTest(code=code):
                self.assertEqual(self._result([code]).level, L_SUSPICIOUS)

    def test_signalements_de_contexte_seuls_ne_changent_rien(self):
        result = self._result(["executable", "macro_doc", "nested_archive"])
        self.assertEqual(result.level, L_UNKNOWN)  # ce que dit VT, rien de plus

    def test_une_famille_interne_domine_tout(self):
        result = self._result(["executable"], inner_levels=[L_CLEAN, L_MALICIOUS])
        self.assertEqual(result.level, L_MALICIOUS)

    def test_archive_chiffree_et_propre_declenche_la_note(self):
        result = self._result(
            ["encrypted"],
            outer=FileVerdict(status=KNOWN, malicious=0, engines=70),
        )
        self.assertTrue(any("mot de passe" in note for note in result.notes))


class TestSummaryRendering(unittest.TestCase):
    """Le recap doit rendre compte de TOUS les fichiers de la cible.

    Un dossier de 12 fichiers dont 9 volumes regroupes affichait un tableau de
    3 lignes, sans rien dire des 9 autres : on croyait le scan interrompu.
    """

    def _render(self, results, grouped):
        import io

        from rich.console import Console

        from vtzip.render import render_summary

        # file=StringIO : on capture sans polluer la sortie des tests.
        console = Console(record=True, width=120, file=io.StringIO())
        render_summary(console, results, grouped=grouped)
        return console.export_text()

    def _result(self, name, level=L_UNKNOWN):
        result = ScanResult(path=Path(name), level=level)
        return result

    def test_le_recap_annonce_le_total_et_les_regroupes(self):
        results = [self._result("jeu.part01.rar"), self._result("data.bin"),
                   self._result("autre.bin")]
        grouped = {"jeu.part01.rar": [Path(f"jeu.part{i:02d}.rar") for i in range(2, 11)]}
        output = self._render(results, grouped)
        self.assertIn("12 fichiers dans la cible", output)
        self.assertIn("3 hashé(s)", output)
        self.assertIn("9 volume(s) regroupé(s)", output)
        self.assertIn("couvre les 10 volumes", output)

    def test_sans_regroupement_pas_de_mention(self):
        results = [self._result("a.zip"), self._result("b.zip")]
        output = self._render(results, None)
        self.assertNotIn("regroupé", output)
        self.assertIn("Verdict global", output)

    def test_un_seul_fichier_regroupe_affiche_quand_meme_le_bilan(self):
        # Un seul resultat : le tableau est normalement omis, mais s'il y a des
        # volumes ecartes il faut quand meme le dire.
        results = [self._result("jeu.part01.rar")]
        grouped = {"jeu.part01.rar": [Path("jeu.part02.rar")]}
        output = self._render(results, grouped)
        self.assertIn("2 fichiers dans la cible", output)


class TestParseFileObject(unittest.TestCase):
    def test_extraction_des_champs(self):
        payload = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "harmless": 0, "malicious": 3, "suspicious": 1,
                        "undetected": 60, "timeout": 1, "type-unsupported": 5,
                    },
                    "last_analysis_results": {
                        "Alpha": {"category": "malicious", "result": "Trojan.RedLine"},
                        "Beta": {"category": "suspicious", "result": "HackTool"},
                        "Gamma": {"category": "undetected", "result": None},
                    },
                    "reputation": -14,
                    "type_description": "Win32 EXE",
                    "times_submitted": 7,
                    "last_analysis_date": 1700000000,
                    "names": ["setup.exe", "crack.exe"],
                    "popular_threat_classification": {
                        "suggested_threat_label": "trojan.redline/stealer",
                        "popular_threat_name": [{"value": "redline"}],
                    },
                }
            }
        }
        verdict = _parse_file_object(payload, "a" * 64)
        self.assertEqual(verdict.status, KNOWN)
        self.assertEqual(verdict.malicious, 3)
        self.assertEqual(verdict.suspicious, 1)
        self.assertEqual(verdict.flagged, 4)
        # 'type-unsupported' ne compte pas comme un moteur ayant analyse.
        self.assertEqual(verdict.engines, 65)
        self.assertEqual(verdict.reputation, -14)
        self.assertEqual(len(verdict.engine_hits), 2)
        self.assertIn("trojan.redline/stealer", verdict.labels)
        self.assertTrue(verdict.permalink.endswith("a" * 64))

    def test_payload_vide_ne_casse_pas(self):
        verdict = _parse_file_object({}, "b" * 64)
        self.assertEqual(verdict.engines, 0)
        self.assertEqual(verdict.flagged, 0)

    def test_aller_retour_par_le_cache(self):
        original = _parse_file_object(
            {"data": {"attributes": {
                "last_analysis_stats": {"malicious": 2, "undetected": 60},
                "last_analysis_results": {"A": {"category": "malicious", "result": "X"}},
            }}},
            "c" * 64,
        )
        cached = original.as_dict()
        restored = FileVerdict(**{**cached, "engine_hits": []})
        restored.engine_hits = [(h["engine"], h["result"]) for h in cached["engine_hits"]]
        self.assertEqual(restored.malicious, original.malicious)
        self.assertEqual(restored.engine_hits, original.engine_hits)


class TestZipHeuristics(unittest.TestCase):
    def setUp(self):
        self._tmp = TemporaryDirectory()
        self.dir = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def _zip(self, name: str, entries: dict[str, bytes | str]) -> Path:
        path = self.dir / name
        with zipfile.ZipFile(path, "w") as zf:
            for entry_name, content in entries.items():
                zf.writestr(entry_name, content)
        return path

    def codes(self, path: Path) -> set[str]:
        return {f.code for f in inspect_zip(path).findings}

    def test_archive_propre_sans_signalement(self):
        path = self._zip("ok.zip", {"a.txt": "hello", "docs/b.md": "# hi"})
        report = inspect_zip(path)
        self.assertTrue(report.is_archive and report.readable)
        self.assertEqual(report.findings, [])
        self.assertEqual(len([e for e in report.entries if not e.is_dir]), 2)

    def test_executable_et_double_extension(self):
        codes = self.codes(self._zip("x.zip", {"facture.pdf.exe": b"MZ"}))
        self.assertIn("executable", codes)
        self.assertIn("double_extension", codes)

    def test_zip_slip(self):
        codes = self.codes(self._zip("s.zip", {"../evil.txt": "x"}))
        self.assertIn("zip_slip", codes)

    def test_chemin_absolu_windows(self):
        codes = self.codes(self._zip("s2.zip", {"C:/Windows/System32/a.dll": b"MZ"}))
        self.assertIn("zip_slip", codes)

    def test_caractere_bidirectionnel(self):
        codes = self.codes(self._zip("b.zip", {"photo\u202egnp.exe": b"MZ"}))
        self.assertIn("bidi_override", codes)

    def test_nom_reserve_et_bizarre(self):
        codes = self.codes(self._zip("r.zip", {"con.bat": "x", "trailing .txt ": "y"}))
        self.assertIn("reserved_name", codes)
        self.assertIn("odd_name", codes)

    def test_archive_vide(self):
        path = self.dir / "e.zip"
        with zipfile.ZipFile(path, "w"):
            pass
        self.assertIn("empty", self.codes(path))

    def test_macro_et_archive_imbriquee(self):
        codes = self.codes(self._zip("m.zip", {"a.docm": b"x", "inner.rar": b"y"}))
        self.assertIn("macro_doc", codes)
        self.assertIn("nested_archive", codes)

    def test_faux_zip_detecte_par_les_magic_bytes(self):
        path = self.dir / "fake.zip"
        path.write_bytes(b"MZ" + b"\0" * 100)
        report = inspect_zip(path)
        self.assertFalse(report.is_archive)
        self.assertIn("type_mismatch", {f.code for f in report.findings})
        self.assertIn("executable Windows", report.detected_type or "")

    def test_zip_corrompu(self):
        path = self.dir / "broken.zip"
        path.write_bytes(b"PK\x03\x04" + b"\0" * 50)
        report = inspect_zip(path)
        self.assertTrue(report.is_archive)
        self.assertFalse(report.readable)
        self.assertIn("corrupt", {f.code for f in report.findings})

    def test_sniff_type(self):
        path = self._zip("z.zip", {"a": "b"})
        self.assertEqual(sniff_type(path), (True, "archive ZIP"))
        pdf = self.dir / "d.pdf"
        pdf.write_bytes(b"%PDF-1.7")
        self.assertEqual(sniff_type(pdf), (False, "document PDF"))

    def test_ratio_de_compression(self):
        path = self.dir / "bomb.zip"
        with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("big.bin", b"\0" * (600 * 1024 * 1024))
        self.assertIn("zip_bomb", self.codes(path))


class TestDisplayName(unittest.TestCase):
    def test_les_caracteres_bidi_sont_echappes(self):
        self.assertEqual(display_name("a\u202eb"), "a\\u202eb")

    def test_les_controles_sont_echappes(self):
        self.assertEqual(display_name("a\x00\x1fb"), "a\\u0000\\u001fb")

    def test_texte_normal_intact(self):
        self.assertEqual(display_name("Crack/activateur é.exe"), "Crack/activateur é.exe")


class TestCollectFiles(unittest.TestCase):
    def setUp(self):
        self._tmp = TemporaryDirectory()
        self.dir = Path(self._tmp.name)
        (self.dir / "sub").mkdir()
        for name in ("setup.exe", "data.pak", "lib.dll", "readme.txt",
                     "sub/crack.exe", "sub/movie.mp4"):
            (self.dir / name).write_bytes(b"x")

    def tearDown(self):
        self._tmp.cleanup()

    def test_ne_garde_que_les_fichiers_a_risque(self):
        names = {p.name for p in collect_files(self.dir)}
        self.assertEqual(names, {"setup.exe", "lib.dll", "crack.exe"})

    def test_all_files_prend_tout(self):
        self.assertEqual(len(collect_files(self.dir, risky_only=False)), 6)

    def test_sans_recursion(self):
        names = {p.name for p in collect_files(self.dir, recursive=False)}
        self.assertEqual(names, {"setup.exe", "lib.dll"})

    def test_les_executables_passent_en_premier(self):
        files = collect_files(self.dir, risky_only=False)
        self.assertTrue(files[0].suffix.lower() in {".exe", ".dll"})


if __name__ == "__main__":
    unittest.main(verbosity=2)
