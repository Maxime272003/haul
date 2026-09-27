"""Mesure le débit de Haul selon « fichiers simultanés » × « connexions par fichier ».

Chaque configuration télécharge P fichiers en même temps (les URL données, tour à tour) avec le vrai
téléchargeur de Haul pendant --duration secondes, puis annule et supprime les fichiers. Le débit
est compté après --warmup secondes (ouverture des connexions, montée en débit TCP). Une pause de
--cooldown secondes sépare deux configurations, pour que les limites du serveur retombent.

    python scripts/bench.py URL [URL…] [--duration 30] [--warmup 6] [--cooldown 10] [--rounds 1]
                            [--configs 1x1,1x2,2x4,…] [--json resultats.json]

Pour FuckingFast, passe un ou plusieurs liens directs dl.fuckingfast.co récupérés par le
userscript (ils sont écrits dans %APPDATA%\\Haul\\haul.log, ligne « Lien reçu pour … ») : c'est
la seule façon de mesurer sa limite par connexion et le nombre de connexions qu'il accepte.
Un lien direct expire : lance le benchmark juste après l'avoir récupéré.
"""

import argparse
import json
import os
import random
import shutil
import sys
import tempfile
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from haul.downloader import Cancelled, Downloader, Refused  # noqa: E402

DEFAULT_CONFIGS = ",".join(f"{f}x{c}" for f in range(1, 7) for c in (1, 2, 4, 8, 16))


def run(urls, files, conns, duration, warmup, workdir):
    """Mesure une configuration : {mbps, refusals, connections, errors}."""
    downloaders, threads, errors = [], [], []
    try:
        for i in range(files):
            url = urls[i % len(urls)]
            d = Downloader(url, url, [({}, {})], conns)
            d.probe()
            downloaders.append(d)

            def go(d=d, dest=os.path.join(workdir, f"f{i}.bin")):
                try:
                    d.download(dest, lambda done, total: None)
                except Cancelled:
                    pass
                except Exception as e:  # noqa: BLE001 - on veut le compter, pas planter
                    errors.append(f"{type(e).__name__}: {e}")
            threads.append(threading.Thread(target=go, daemon=True))
            threads[-1].start()
        time.sleep(warmup)
        b0, t0 = sum(d.done for d in downloaders), time.monotonic()
        time.sleep(duration - warmup)
        b1, t1 = sum(d.done for d in downloaders), time.monotonic()
        connections = sum(d.active_connections for d in downloaders)
    except Refused as e:
        return {"mbps": None, "refusals": 0, "connections": 0, "errors": [f"sonde refusée : {e}"]}
    finally:
        for d in downloaders:
            d.cancel()
        for t in threads:
            t.join(30)
    return {"mbps": (b1 - b0) / (t1 - t0) / 1e6, "refusals": sum(d.refusals for d in downloaders),
            "connections": connections, "errors": errors}


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("urls", nargs="+")
    parser.add_argument("--duration", type=float, default=30)
    parser.add_argument("--warmup", type=float, default=6)
    parser.add_argument("--cooldown", type=float, default=10)
    parser.add_argument("--rounds", type=int, default=1, help="passes (ordre des configurations mélangé)")
    parser.add_argument("--configs", default=DEFAULT_CONFIGS, help="liste « fichiers x connexions »")
    parser.add_argument("--json", help="enregistre les mesures brutes dans ce fichier (au fil de l'eau)")
    args = parser.parse_args()
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    configs = [tuple(int(n) for n in c.split("x")) for c in args.configs.split(",")]

    results = {c: [] for c in configs}
    total_bytes = 0.0
    for rnd in range(args.rounds):
        order = configs[:]
        random.shuffle(order)
        for files, conns in order:
            workdir = tempfile.mkdtemp(prefix="haul-bench-")
            try:
                r = run(args.urls, files, conns, args.duration, args.warmup, workdir)
            finally:
                shutil.rmtree(workdir, ignore_errors=True)
            results[(files, conns)].append(r)
            if r["mbps"] is None:
                print(f"passe {rnd + 1}  {files} fichier(s) × {conns:>2} connexion(s) : {r['errors'][0]}", flush=True)
            else:
                total_bytes += r["mbps"] * args.duration * 1e6
                print(f"passe {rnd + 1}  {files} fichier(s) × {conns:>2} connexion(s) : {r['mbps']:6.2f} Mo/s"
                      f"  connexions actives={r['connections']:>2}  refus={r['refusals']}"
                      f"{'  erreurs=' + str(len(r['errors'])) if r['errors'] else ''}", flush=True)
            if args.json:
                Path(args.json).write_text(json.dumps({f"{f}x{c}": v for (f, c), v in results.items()}, indent=1),
                                           encoding="utf-8")
            time.sleep(args.cooldown)

    print(f"\n≈ {total_bytes / 1e9:.1f} Go téléchargés\n")
    print("fichiers × connexions   demandées   actives   débit moyen   min – max      refus")
    measured = {c: [r for r in runs if r["mbps"] is not None] for c, runs in results.items()}
    ranked = sorted((c for c in measured if measured[c]),
                    key=lambda c: -sum(r["mbps"] for r in measured[c]) / len(measured[c]))
    for files, conns in ranked:
        runs = measured[(files, conns)]
        rates = [r["mbps"] for r in runs]
        print(f"{files:>8} × {conns:<11} {files * conns:>9}   {max(r['connections'] for r in runs):>7}"
              f"   {sum(rates) / len(rates):8.2f} Mo/s   {min(rates):5.2f} – {max(rates):5.2f}"
              f"   {sum(r['refusals'] for r in runs):>6}")
    failed = [c for c in results if not measured[c]]
    if failed:
        print("sans mesure (sonde refusée) :", ", ".join(f"{f}x{c}" for f, c in failed))


if __name__ == "__main__":
    main()
