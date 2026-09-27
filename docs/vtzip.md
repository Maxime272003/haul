# vtzip

> Module de vérification VirusTotal de [Haul](../README.md), utilisable aussi seul.

App terminal qui vérifie tes téléchargements sur VirusTotal **avant** que tu les dézippes.

Le principe : elle calcule le SHA-256 en local et interroge VirusTotal par hash. Rien n'est
envoyé, VirusTotal répond avec le rapport si quelqu'un a déjà soumis le même fichier. En
parallèle, elle ouvre le zip **sans l'extraire** pour lister ce qu'il contient et signaler
les pièges classiques.

## Installation

vtzip fait partie du dépôt Haul (`src/vtzip`) et s'installe avec lui :

```powershell
.venv\Scripts\python -m pip install -e ".[dev]"   # depuis la racine du dépôt
.venv\Scripts\vtzip config set-key                # ta clé API (masquée, chiffrée DPAPI sous Windows)
```

Clé API : compte gratuit sur [virustotal.com](https://www.virustotal.com), menu profil >
API key. La clé est stockée dans `%APPDATA%\vtzip\config.json` ; la variable
d'environnement `VT_API_KEY` a priorité si elle existe.

Haul appelle vtzip directement (mode `--deep`) quand toute sa liste est téléchargée ; la
commande `vtzip` reste utilisable seule, comme ci-dessous.

## Usage

```powershell
vtzip repack.zip                     # hash + lookup + inspection de l'archive
vtzip --deep repack.zip              # vérifie AUSSI chaque fichier interne, sans extraire
vtzip --deep C:\Games\Khazan         # tout un dossier de repack d'un coup
vtzip watch                          # surveille le dossier Téléchargements en continu
vtzip C:\Jeux\RepackExtrait          # scan d'un dossier déjà extrait (exe/dll seulement)
vtzip hash gros.iso                  # juste le SHA-256, à coller dans la barre VT
```

## ZIP et RAR

Les deux formats sont inspectés sans extraction, avec les mêmes heuristiques.

- **ZIP** : lecture directe par `zipfile`, aucune dépendance.
- **RAR** : listage délégué à `UnRAR.exe` (livré avec WinRAR) ou `7z.exe`, cherchés dans le
  PATH puis dans `C:\Program Files\WinRAR` et `C:\Program Files\7-Zip`. Chemin surchargeable
  via la variable `VTZIP_UNRAR`. En `--deep`, le contenu d'une entrée est streamé depuis
  `unrar p` et hashé au vol — y compris quand le fichier est réparti sur plusieurs volumes.
  Rien n'est jamais écrit sur le disque.

Le parsing du listage RAR s'appuie sur la structure du tableau, pas sur les libellés de
colonnes, parce qu'UnRAR est traduit (`Nom`/`Taille` sur une machine française).

**Jeux multi-volumes** (`jeu.part01.rar` … `jeu.part10.rar`, ou `jeu.rar` + `jeu.r00`) :
seul le premier volume est analysé par défaut, et le contenu complet du jeu est listé
depuis lui. Hasher les 9 autres volumes d'un repack de 20 Go n'apporte rien — si la release
est connue de VirusTotal, le premier volume suffit à le dire ; sinon aucun ne le sera. Pour
vérifier l'intégrité des parties, utilise le fichier de somme de contrôle de la release,
pas VirusTotal. `--all-parts` force le traitement de tous les volumes.

Une archive à **en-têtes chiffrés** est signalée explicitement : ni la liste des fichiers
ni leur contenu ne sont analysables, par aucun antivirus.

Options utiles :

| Option | Effet |
| --- | --- |
| `--deep` | Hashe chaque fichier interne en streaming et l'interroge sur VT. Priorise les exécutables. |
| `--deep-max N` | Nombre d'entrées internes vérifiées (défaut 12). Chaque entrée = 1 requête. |
| `--offline` | Zéro réseau : hash + analyse locale de l'archive seulement. |
| `--upload` | Envoie le fichier s'il est inconnu de VT. **Le fichier quitte ta machine.** |
| `--wait` | Avec `--upload`, attend le résultat de l'analyse. |
| `--quarantine DOSSIER` | Déplace les fichiers malveillants/suspects hors du dossier de téléchargement. |
| `--all-parts` | Hashe tous les volumes d'un jeu multi-parties au lieu du premier seul. |
| `--json` | Sortie machine, pour scripter. |
| `--rpm 0` | Désactive le bridage (clé premium ; par défaut 4 req/min). |
| `--verbose` | Panneau détaillé même pour les fichiers sans signalement. |

Codes de sortie : `0` propre, `2` malveillant, `3` suspect, `4` détections génériques,
`5` inconnu de VirusTotal, `6` erreur.

## Ce que l'app détecte sans extraire l'archive

Lecture du *central directory* du zip, donc aucun fichier n'est écrit sur le disque :

- **exécutables et scripts** (`.exe`, `.bat`, `.ps1`, `.vbs`, `.lnk`, `.dll`, `.msi`…)
- **double extension** trompeuse : `facture.pdf.exe`
- **caractère bidirectionnel** (RTLO) dans un nom : l'explorateur affiche `photo.png`
  là où le fichier est un `.exe`. Le nom est échappé avant affichage, jamais rendu brut.
- **Zip Slip** : entrée en `../..` ou chemin absolu, qui écrirait hors du dossier cible
- **archive chiffrée** : signalée comme telle, parce qu'un `0/70` sur une archive dont
  les moteurs ne peuvent pas lire le contenu ne veut rien dire
- **zip bomb** : ratio de compression et taille décompressée
- **type réel** via les magic bytes : un `.zip` qui est en fait un PE, un RAR, un PDF
- **documents à macros**, **archives imbriquées**, noms réservés Windows, archive corrompue

## Comment lire le verdict

Le nombre brut de moteurs ne veut pas dire grand-chose sur un crack ou un repack. L'app
classe donc chaque détection :

- **MALVEILLANT** — une famille est nommée **et corroborée** : RedLine, Lumma, Vidar,
  Amadey, AsyncRAT, XMRig, LockBit… L'app précise le type (vol d'identifiants, accès
  distant, mineur, rançongiciel). Deux moteurs concordants suffisent : on n'exécute pas.

  La corroboration est exigée parce qu'un moteur isolé ne vaut pas condamnation : les
  éditeurs les plus bavards collent `Meterpreter` ou `CobaltStrike` sur tout binaire qui
  manipule de la mémoire. Il faut donc soit deux moteurs qui nomment une famille, soit
  que VirusTotal la reprenne dans son étiquette agrégée
  (`popular_threat_classification`). Un seul moteur non corroboré descend en SUSPECT,
  avec une note qui le dit explicitement.
- **DÉTECTIONS GÉNÉRIQUES** — aucun nom de famille, seulement du boilerplate :
  `HackTool`, `Riskware`, `Malicious`, `W32.Malware.Gen`, `Wacatac`, `Gen:Variant`,
  `BehavesLike…`, `AIDetectMalware`… Bruit attendu d'un programme qui patche un
  exécutable, ou faux positif sur un petit utilitaire ancien non signé. Même à 30
  moteurs, ça reste cette catégorie. Va voir l'onglet **Behavior** du rapport VT :
  connexions sortantes, clés de registre en Run, tâches planifiées, accès aux profils
  navigateur = stealer.

  Le tri ne repose pas sur une liste de motifs — elle ne couvrirait jamais les
  conventions de 70 moteurs. Le libellé est décomposé en tokens, dont on retire les
  plateformes (`Win32`, `MSIL`), les catégories (`Trojan`, `Dropper`, `Riskware`), les
  marqueurs de moteur (`Gen`, `ML`, `HEUR`, `susgen`, `!ml`), les fourre-tout des grands
  éditeurs (`Wacatac`, `Kryptik`, `Agent`) et les identifiants numériques. S'il ne reste
  aucun nom, c'est générique. Sinon la détection remonte en SUSPECT, même si la famille
  est inconnue de la table.
- **SUSPECT** — détections nommées mais non répertoriées, ou signalement de tromperie
  dans l'archive.
- **INCONNU DE VT** — personne n'a jamais soumis ce fichier. Ce n'est **pas** un feu vert.

### Ce qui fait monter le verdict, et ce qui reste du contexte

Tous les signalements d'archive ne se valent pas. Seuls ceux qui relèvent de la
**tromperie** ou de l'**impossibilité d'analyser** font monter le verdict : double
extension, caractère RTLO, Zip Slip, zip bomb, type réel différent de l'extension,
archive chiffrée.

« Contient des exécutables » est affiché mais **ne fait pas** monter le verdict : une
archive d'installation contient un installeur, c'est vrai de 100 % des repacks et ça
n'informe donc de rien. Ce qui compte, c'est le verdict VirusTotal de ces exécutables,
que `--deep` va justement chercher. Sans cette distinction, tout repack ressortait
« SUSPECT » et l'information utile se noyait dans le bruit.

## Méthode conseillée pour un repack

Un dossier type — 10 volumes RAR de 2 Go et deux `.bin` de données — s'analyse d'une
seule commande :

```powershell
vtzip --deep C:\Games\Khazan
```

Ce qui se passe : les 10 volumes sont reconnus comme un jeu et réduits au premier (18 Go
de hash évités), le contenu complet de l'archive est listé depuis ce volume, les
exécutables trouvés à l'intérieur (`setup.exe`, `Crack\activator.exe`) sont hashés en
streaming et interrogés sur VirusTotal, et les `.bin` sont vérifiés par hash. Compte une
dizaine de requêtes, donc ~3 min avec le quota gratuit de 4/min ; une barre de progression
s'affiche pendant le hash des gros fichiers.

Ensuite :

1. **Archive de plus de 650 Mo** : l'upload est impossible, mais le lookup par hash marche
   quelle que soit la taille. `vtzip hash gros.iso` te donne aussi le hash à comparer à
   celui publié par la source.
2. **Après extraction** : `vtzip C:\Jeux\RepackExtrait` ne hashe que les exécutables,
   DLL et archives — pas les 40 Go de données du jeu.
3. **Le moment réellement critique** reste l'exécution de l'installeur en admin. Si on te
   demande de désactiver ton antivirus, mets une **exclusion sur un dossier précis** plutôt
   que de couper Defender entièrement, et réactive tout de suite après. Windows Sandbox
   (Windows Pro) permet de lancer l'installeur et d'observer son comportement.

## Notes

- **Quota** : l'API publique est limitée à 4 requêtes/minute et 500/jour. L'app bride
  automatiquement et met en cache les résultats 24 h (`%APPDATA%\vtzip\cache.json`,
  contournable avec `--no-cache`).
- **Vie privée** : par défaut, seul un hash est transmis. `--upload` change ça et envoie
  le fichier — tout ce qui est uploadé sur VirusTotal devient consultable par les autres
  abonnés de la plateforme.
- Un lookup par hash reflète l'analyse d'un fichier *identique au bit près*. Un repack
  recompressé donnera un hash différent, donc « inconnu », même si son contenu est connu :
  c'est exactement pourquoi `--deep` existe.

## Tests

```powershell
.venv\Scripts\pytest tests/vtzip
```

77 tests : classification des détections, heuristiques d'archive (dont RTLO, Zip Slip, zip
bomb, faux zip), niveaux de verdict, client VirusTotal avec session HTTP simulée, parsing
du listage RAR en français et en anglais, détection des jeux de volumes. Les tests RAR de
bout en bout créent de vraies archives et sont ignorés si WinRAR est absent.
