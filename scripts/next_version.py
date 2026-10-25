"""Version de la prochaine release, d'après les tags vX.Y.Z et src/haul/__init__.py (utilisé par la CI).

Sans montée de version à la main, chaque release incrémente le correctif de la précédente ; pour
passer à 1.1.0 ou 2.0.0, il suffit de changer __version__ dans src/haul/__init__.py.

Usage : python scripts/next_version.py [--write]
    --write : écrit la version dans src/haul/__init__.py (pour l'exécutable construit ensuite)
"""

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
INIT = ROOT / "src" / "haul" / "__init__.py"
sys.path.insert(0, str(ROOT / "src"))

from haul.updater import next_version  # noqa: E402

VERSION_LINE = re.compile(r'^__version__ = "([^"]+)"$', re.M)


def main():
    text = INIT.read_text(encoding="utf-8")
    base = VERSION_LINE.search(text).group(1)
    tags = subprocess.run(["git", "tag", "--list", "v*"], capture_output=True, text=True, check=True,
                          cwd=ROOT).stdout.split()
    version = next_version(base, tags)
    if "--write" in sys.argv[1:]:
        INIT.write_text(VERSION_LINE.sub(f'__version__ = "{version}"', text), encoding="utf-8")
    print(version)


if __name__ == "__main__":
    main()
