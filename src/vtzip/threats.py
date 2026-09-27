"""Lecture des detections VirusTotal.

Un "12/70" n'est pas interpretable brut. Sur un repack de jeu ou un keygen, les
moteurs remontent presque toujours des detections generiques (HackTool, Riskware,
PUA, Packed, Patched) qui decrivent ce que le programme fait legitimement :
patcher un binaire, ecrire en memoire. Ce qui doit reellement arreter, c'est le
nom d'une famille precise de malware -- stealer, RAT, loader, mineur, ransomware.

Ce module classe donc chaque detection en trois categories :
  CRITICAL -> famille identifiee, on n'execute pas
  GENERIC  -> bruit attendu pour un crack / outil de patch
  OTHER    -> detection nommee mais non classee, a regarder
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

CRITICAL = "critical"
GENERIC = "generic"
OTHER = "other"

# Familles a impact direct (vol de donnees, controle distant, minage, chiffrement).
MALWARE_FAMILIES: dict[str, str] = {
    # -- infostealers
    "redline": "stealer", "lumma": "stealer", "lummac": "stealer",
    "vidar": "stealer", "raccoon": "stealer", "stealc": "stealer",
    "rhadamanthys": "stealer", "meduza": "stealer", "cryptbot": "stealer",
    "arkei": "stealer", "mars stealer": "stealer", "marsstealer": "stealer",
    "aurora": "stealer", "bandit": "stealer", "banditstealer": "stealer",
    "pennywise": "stealer", "mystic": "stealer", "atomic": "stealer",
    "amos": "stealer", "phemedrone": "stealer", "kematian": "stealer",
    "blankgrabber": "stealer", "skuld": "stealer", "exela": "stealer",
    "azorult": "stealer", "agenttesla": "stealer", "agent tesla": "stealer",
    "formbook": "stealer", "xloader": "stealer", "loki": "stealer",
    "lokibot": "stealer", "racealer": "stealer", "titan": "stealer",
    "erbium": "stealer", "vipersoftx": "stealer", "luca": "stealer",
    "typhon": "stealer", "acr": "stealer", "elusive": "stealer",
    # -- RAT / backdoor
    "asyncrat": "rat", "async rat": "rat", "quasar": "rat", "njrat": "rat",
    "remcos": "rat", "nanocore": "rat", "darkcomet": "rat", "venomrat": "rat",
    "xworm": "rat", "warzone": "rat", "avemaria": "rat", "ave maria": "rat",
    "orcus": "rat", "netwire": "rat", "revenge": "rat", "babylon": "rat",
    "dcrat": "rat", "poison ivy": "rat", "poisonivy": "rat", "plugx": "rat",
    "gh0st": "rat", "sectoprat": "rat", "smallnet": "rat", "limerat": "rat",
    "metasploit": "rat", "meterpreter": "rat", "cobaltstrike": "rat",
    "cobalt strike": "rat", "sliver": "rat", "havoc": "rat", "brute ratel": "rat",
    # -- loaders / botnets
    "amadey": "loader", "smokeloader": "loader", "smoke loader": "loader",
    "privateloader": "loader", "socgholish": "loader", "gootloader": "loader",
    "bumblebee": "loader", "icedid": "loader", "qakbot": "loader",
    "qbot": "loader", "emotet": "loader", "trickbot": "loader",
    "dridex": "loader", "gozi": "loader", "ursnif": "loader",
    "danabot": "loader", "guloader": "loader", "cloudeye": "loader",
    "raspberryrobin": "loader", "phorpiex": "loader", "glupteba": "loader",
    "laplas": "loader", "matanbuchus": "loader", "pikabot": "loader",
    "latrodectus": "loader", "hijackloader": "loader", "idatloader": "loader",
    "purplefox": "loader", "socks5systemz": "loader", "nitrogen": "loader",
    # -- mineurs
    "xmrig": "miner", "coinminer": "miner", "coinhive": "miner",
    "cryptominer": "miner", "minerd": "miner", "bitcoinminer": "miner",
    "phoenixminer": "miner", "nbminer": "miner", "silentcryptominer": "miner",
    "monero": "miner", "lolminer": "miner",
    # -- ransomware
    "ransom": "ransomware", "lockbit": "ransomware", "wannacry": "ransomware",
    "stop": "ransomware", "djvu": "ransomware", "conti": "ransomware",
    "blackcat": "ransomware", "alphv": "ransomware", "akira": "ransomware",
    "royal": "ransomware", "hive": "ransomware", "medusalocker": "ransomware",
    "phobos": "ransomware", "gandcrab": "ransomware", "cerber": "ransomware",
    "revil": "ransomware", "sodinokibi": "ransomware", "cryptolocker": "ransomware",
    "blackbasta": "ransomware", "playcrypt": "ransomware", "rhysida": "ransomware",
    # -- clippers / divers
    "clipbanker": "clipper", "clipper": "clipper", "cryptoclipper": "clipper",
    "keylogger": "keylogger", "snakekeylogger": "keylogger",
    "rootkit": "rootkit", "bootkit": "rootkit",
    "wiper": "wiper", "backdoor.win32": "backdoor",
}

# Detections attendues sur un crack / keygen / patcher : bruit, pas preuve.
GENERIC_PATTERNS = (
    "hacktool", "hack tool", "riskware", "pua", "pup", "potentially unwanted",
    "unwanted", "not-a-virus", "notavirus", "keygen", "cracktool", "crack",
    "patcher", "patched", "packed", "packer", "obfuscat", "protector",
    "themida", "vmprotect", "upx", "enigma", "aspack", "confuser",
    "gen:variant", "gen:heur", "heuristic", "heur.", "ml.attribute",
    "malicious confidence", "unsafe", "suspicious", "suspect", "generic",
    "gen.", "artemis", "score", "static ai", "aidetect", "machinelearning",
    "malware.ai", "ai:packer", "attribute.highconfidence", "deepscan",
    "trojan.gen", "trojan.generic", "w32.aidetect", "smartscreen",
    "bundler", "adware", "downloader.generic", "application",
)

# Certaines familles sont trop generiques pour lever une alerte critique seules.
AMBIGUOUS_FAMILY_HITS = {"stop", "ransom", "crack", "monero", "metasploit"}

# Tokens qui ne nomment rien : plateformes, categories de menace, marqueurs de
# moteur. Un libelle compose uniquement de ces briques est du boilerplate, quel
# que soit le moteur : "W32.Malware.Gen", "Trojan.Malware.695641994.susgen" ou
# "Malicious" ne designent aucune famille. Cette approche par decomposition
# remplace une liste de motifs qui ne pourrait jamais couvrir 70 moteurs.
STRUCTURAL_TOKENS = {
    # plateformes, langages, conteneurs
    "win", "win32", "win64", "w32", "w64", "x86", "x64", "msil", "dotnet", "net",
    "script", "scr", "js", "jscript", "vbs", "vba", "vbscript", "html", "htm",
    "android", "apk", "osx", "macos", "linux", "unix", "elf", "multi", "dos",
    "bat", "cmd", "powershell", "python", "java", "class", "office", "doc",
    "docx", "xls", "xlsx", "ppt", "pdf", "swf", "php", "perl", "ruby", "lnk",
    "nsis", "inno", "autoit", "delphi", "borland", "archive", "zip", "rar",
    "binary", "exe", "dll", "file", "files", "text", "data", "test",
    # categories de menace
    "trojan", "trj", "troj", "trojandropper", "trojandownloader", "virus",
    "worm", "backdoor", "bkdr", "dropper", "dropped", "downloader", "dldr",
    "adware", "riskware", "hacktool", "tool", "tools", "pua", "pup", "spyware",
    "stealer", "ransom", "ransomware", "rootkit", "malware", "malicious",
    "unsafe", "suspicious", "suspect", "susp", "susgen", "unwanted",
    "potentially", "grayware", "greyware", "application", "program", "software",
    "bundler", "bundle", "installer", "setup", "keygen", "crack", "cracked",
    "patcher", "patch", "patched", "kms", "activator", "injector", "exploit",
    "phishing", "spam", "joke", "hoax", "corrupt", "damaged", "infected",
    # marqueurs generiques et de moteur
    "generic", "gen", "genericml", "genericrxaa", "variant", "heur", "heuristic",
    "ml", "ai", "aidetect", "aidetectmalware", "cloud", "static", "attribute",
    "highconfidence", "confidence", "score", "reputation", "detected",
    "undetected", "behaveslike", "behavior", "behaviour", "deepscan", "circ",
    "gencirc", "artemis", "zen", "nemesis", "mtb", "rfn", "rdml", "gdsda",
    "unwanted2", "packed", "packer", "obfuscated", "obfuscator", "protector",
    "crypt", "crypter", "crypted", "encoded", "encrypted", "morphine",
    # familles fourre-tout des grands moteurs : autant de bruit qu'un "Gen"
    "wacatac", "wacapew", "kryptik", "krypt", "sabsik", "occamy", "zusy", "convagent",
    "eldorado", "agent", "agentb", "midie", "starter", "razy", "barys",
    "injuke", "malpack", "vagrant", "casdet", "fragtor", "leonem", "tnega",
    "banload", "autorun", "small", "graftor", "symmi", "bulz", "chapak",
}

# Motifs a filtrer avant tokenisation (contiennent des separateurs internes).
_HEXISH_RE = re.compile(r"^(?=.*\d)[0-9a-f]{4,}$")
_TOKEN_SPLIT_RE = re.compile(r"[^A-Za-z0-9]+")


def _is_meaningful_token(token: str) -> bool:
    """Un token nomme-t-il quelque chose, ou est-ce du remplissage ?"""
    if len(token) < 4 or token in STRUCTURAL_TOKENS:
        return False
    if token.isdigit() or _HEXISH_RE.match(token):
        return False
    # Majorite de chiffres : identifiant de detection cloud, pas un nom.
    digits = sum(1 for char in token if char.isdigit())
    return digits * 2 < len(token)


@dataclass
class Detection:
    engine: str
    result: str
    level: str
    family: str | None = None
    kind: str | None = None

    def as_dict(self) -> dict:
        return {
            "engine": self.engine,
            "result": self.result,
            "level": self.level,
            "family": self.family,
            "kind": self.kind,
        }


@dataclass
class ThreatSummary:
    detections: list[Detection]
    # Etiquette agregee de VirusTotal (popular_threat_classification), qui
    # resume ce sur quoi les moteurs convergent reellement.
    vt_labels: list[str] = field(default_factory=list)

    @property
    def corroborated(self) -> bool:
        """La famille identifiee est-elle confirmee par autre chose qu'un moteur ?

        Un moteur isole qui nomme une famille ne suffit pas : les editeurs les
        plus bavards collent "Meterpreter" ou "CobaltStrike" sur tout binaire
        qui manipule de la memoire. On exige soit deux moteurs concordants, soit
        que VirusTotal reprenne la famille dans son etiquette agregee.
        """
        if not self.critical:
            return False
        if len(self.critical) >= 2:
            return True
        labels = " ".join(self.vt_labels).lower()
        return any(det.family and det.family in labels for det in self.critical)

    @property
    def critical(self) -> list[Detection]:
        return [d for d in self.detections if d.level == CRITICAL]

    @property
    def generic(self) -> list[Detection]:
        return [d for d in self.detections if d.level == GENERIC]

    @property
    def other(self) -> list[Detection]:
        return [d for d in self.detections if d.level == OTHER]

    @property
    def families(self) -> list[str]:
        seen: dict[str, None] = {}
        for det in self.critical:
            if det.family:
                seen.setdefault(det.family, None)
        return list(seen)

    @property
    def kinds(self) -> list[str]:
        seen: dict[str, None] = {}
        for det in self.critical:
            if det.kind:
                seen.setdefault(det.kind, None)
        return list(seen)

    def as_dict(self) -> dict:
        return {
            "critical_count": len(self.critical),
            "generic_count": len(self.generic),
            "other_count": len(self.other),
            "families": self.families,
            "kinds": self.kinds,
            "corroborated": self.corroborated,
            "vt_labels": self.vt_labels,
            "detections": [d.as_dict() for d in self.detections],
        }


def _match_family(text: str) -> tuple[str | None, str | None]:
    """Cherche une famille connue, en preferant le nom le plus specifique.

    "Ransom.Win32.LockBit" contient a la fois "ransom" et "lockbit" : on retient
    le second, plus informatif.
    """
    matches: list[tuple[str, str]] = []
    for family, kind in MALWARE_FAMILIES.items():
        if family not in text:
            continue
        # Mot entier pour les noms courts/ambigus, sinon simple sous-chaine.
        if family in AMBIGUOUS_FAMILY_HITS or len(family) <= 4:
            if not re.search(rf"(?<![a-z0-9]){re.escape(family)}(?![a-z0-9])", text):
                continue
        matches.append((family, kind))
    if not matches:
        return None, None
    return max(matches, key=lambda pair: len(pair[0]))


def classify(engine: str, result: str | None) -> Detection:
    """Range une detection en CRITICAL / GENERIC / OTHER.

    Ordre volontaire : une famille connue l'emporte toujours ; sinon, un libelle
    qui ne contient aucun nom exploitable est du bruit ; il ne reste en OTHER que
    ce qui nomme quelque chose d'inconnu de la table des familles.
    """
    raw = (result or "").strip()
    if not raw:
        return Detection(engine, "?", GENERIC)

    text = raw.lower()
    family, kind = _match_family(text)
    if family:
        return Detection(engine, raw, CRITICAL, family=family, kind=kind)
    if any(pattern in text for pattern in GENERIC_PATTERNS):
        return Detection(engine, raw, GENERIC)

    tokens = [tok for tok in _TOKEN_SPLIT_RE.split(text) if tok]
    if not any(_is_meaningful_token(tok) for tok in tokens):
        return Detection(engine, raw, GENERIC)
    return Detection(engine, raw, OTHER)


def summarize(engine_hits: list[tuple[str, str]],
              vt_labels: list[str] | None = None) -> ThreatSummary:
    detections = [classify(engine, result) for engine, result in engine_hits]
    order = {CRITICAL: 0, OTHER: 1, GENERIC: 2}
    detections.sort(key=lambda d: (order[d.level], d.engine.lower()))
    return ThreatSummary(detections, vt_labels=list(vt_labels or []))


KIND_LABELS = {
    "stealer": "vol d'identifiants (navigateurs, wallets, sessions)",
    "rat": "accès distant / prise de contrôle de la machine",
    "loader": "téléchargeur de charge secondaire",
    "miner": "mineur de cryptomonnaie (utilise ton CPU/GPU)",
    "ransomware": "rançongiciel (chiffrement de tes fichiers)",
    "clipper": "détournement du presse-papiers (adresses crypto)",
    "keylogger": "enregistreur de frappe",
    "rootkit": "dissimulation au niveau du système",
    "wiper": "destruction de données",
    "backdoor": "porte dérobée",
}


def explain_kinds(kinds: list[str]) -> list[str]:
    return [f"{kind} : {KIND_LABELS[kind]}" for kind in kinds if kind in KIND_LABELS]
