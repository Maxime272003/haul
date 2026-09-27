<div align="center">

<img src="src/haul/assets/haul.png" width="96" alt="Haul">

# Haul

**Gestionnaire de téléchargements pour FuckingFast, sur Windows.**<br>
Copie les liens, Haul s'occupe du reste : téléchargement multi-connexions, analyse VirusTotal, extraction WinRAR.

![Python](https://img.shields.io/badge/python-3.10%2B-3776AB?logo=python&logoColor=white)
![Windows](https://img.shields.io/badge/plateforme-Windows-0078D6?logo=windows&logoColor=white)
![Licence](https://img.shields.io/badge/licence-MIT-green)

</div>

---

## Fonctionnalités

- **Presse-papier surveillé** — sélectionne une liste de liens sur une page web et fais Ctrl+C :
  les URL sont lues dans la version HTML du presse-papier, même si le texte copié ne montre que
  les noms de fichiers.
- **Captcha respecté** — chaque page s'ouvre dans ton navigateur habituel, où tu valides le
  captcha si Cloudflare en demande un. Une validation vaut pour les liens suivants.
- **Téléchargement hors navigateur** — un userscript récupère le lien direct et l'envoie à Haul,
  qui télécharge en **plusieurs connexions par fichier**, plusieurs fichiers en parallèle,
  avec **reprise** après coupure.
- **Analyse VirusTotal avant extraction** — via [vtzip](docs/vtzip.md) (inclus) : hash des
  fichiers et des exécutables *à l'intérieur* des archives, sans rien extraire ni envoyer.
- **Extraction WinRAR automatique** — quand toute la liste est téléchargée et que l'analyse ne
  signale rien : *Extraire et mettre à jour*, *Remplacer sans demander*. Chaque archive est
  d'abord vérifiée (voir [Sécurité](#sécurité)).
- **Pause, reprise, liste conservée** — pause par fichier, « passer » une page qui attend un
  captcha ; la liste est retrouvée au lancement suivant, les téléchargements interrompus en pause.
- **Notifications Windows** — quand un captcha attend dans le navigateur, quand la liste est
  finie ; progression affichée sur le bouton de la barre des tâches.

## Comment ça marche

```mermaid
flowchart LR
    A[Ctrl+C sur une liste de liens] --> B[Haul ouvre chaque page<br>dans le navigateur]
    B --> C{Captcha ?}
    C -- oui --> D[Tu le valides]
    C -- non --> E
    D --> E[Le userscript clique DOWNLOAD<br>et envoie le lien direct à Haul]
    E --> F[Téléchargement<br>multi-connexions]
    F --> G[Analyse VirusTotal<br>vtzip --deep]
    G -- rien de grave --> H[Extraction WinRAR]
    G -- malveillant / suspect / non vérifié --> I[Extraction bloquée]
```

Le userscript communique avec Haul par un petit serveur HTTP local (`127.0.0.1:17655`), protégé
par un jeton secret propre à ton installation (voir [Sécurité](#sécurité)).

## Installation

### Prérequis

- Windows 10/11, [WinRAR](https://www.win-rar.com/) (pour l'extraction et le listage des RAR)
- Un navigateur avec [Violentmonkey](https://violentmonkey.github.io/) ou Tampermonkey
- Une clé API VirusTotal gratuite (profil > *API key* sur [virustotal.com](https://www.virustotal.com))
- Python 3.10+ pour lancer depuis les sources ou construire l'exécutable

### Depuis les sources

```powershell
git clone <url-du-depot> haul
cd haul
py -3.12 -m venv .venv
.venv\Scripts\python -m pip install -e ".[dev]"
.venv\Scripts\haul                     # lance l'application
```

### Exécutable autonome

```powershell
.\scripts\build.ps1                    # produit dist\Haul.exe (aucun Python requis pour l'utiliser)
```

### Première utilisation

1. Lance Haul, puis clique **Installer le script navigateur** : Violentmonkey propose
   d'installer le userscript. *Mise à jour depuis une version précédente : réinstalle-le*, le
   script contient désormais le jeton de ton installation (Haul le signale sinon).
2. Clique **Clé VirusTotal…**, colle ta clé API, *Tester* puis *Enregistrer*.
3. Copie une liste de liens `fuckingfast.co` depuis une page web : les téléchargements démarrent.

## Utilisation

| Réglage | Effet |
| --- | --- |
| Surveiller le presse-papier | Ajoute automatiquement les liens copiés. |
| Fichiers simultanés | Nombre de fichiers téléchargés en même temps (2–3 conseillés). |
| Connexions par fichier | Découpage de chaque fichier (8 conseillé). |
| Débit max | Plafond du débit total, de 1 à 100 Mo/s, ou illimité. |
| Analyser avec VirusTotal | Analyse le lot quand toute la liste est téléchargée. |
| Clé VirusTotal… | Saisie, test et enregistrement (chiffré) de la clé API. |
| Puis extraire avec WinRAR | Extrait les archives si l'analyse ne bloque pas. |
| Notifications | Prévient quand la fenêtre n'est pas au premier plan : captcha à valider, liste terminée, extraction terminée ou bloquée. |

Boutons :

- **Mettre en pause / Reprendre** : agit sur les fichiers sélectionnés (<kbd>Ctrl</kbd>+<kbd>A</kbd>
  pour tout sélectionner) ; le libellé suit la sélection ;
- **Tout suspendre / Tout reprendre** : met toute la liste en pause (fichiers partiels gardés, la
  reprise repart de là). Tant que Haul est suspendu, les liens copiés sont ajoutés en pause au
  lieu d'ouvrir des pages dans le navigateur ;

puis **Réessayer les échecs** (reprend là où le
fichier s'était arrêté, rouvre la page si le lien a expiré), **Retirer les terminés**,
**Analyser / extraire maintenant**, **Rapport VirusTotal** (rapport détaillé de vtzip),
**Installer le script navigateur**. Un bouton est grisé quand il n'a rien à faire.

Fermer la fenêtre pendant des téléchargements demande confirmation ; ils sont mis en pause et
la liste est retrouvée au lancement suivant (« Tout reprendre »).

Dans la liste :

- une ligne sélectionnée affiche son statut complet dans la barre d'état, et un texte trop long
  pour sa colonne s'affiche en entier au survol ;
- clic droit : *Afficher dans l'Explorateur*, *Copier le lien de la page*, *Rouvrir la page*
  (captcha en attente), *Mettre en pause* (ou *Passer ce lien* pour une page qui attend le
  captcha : la suivante s'ouvre), *Reprendre*, *Réessayer*, *Retirer de la liste* ;
- double-clic : afficher le fichier ; <kbd>Espace</kbd> : pause / reprise ; <kbd>Suppr</kbd> :
  retirer (un fichier en cours est mis en pause, le fichier partiel reste pour une reprise) ;
- <kbd>Ctrl</kbd>+<kbd>V</kbd> dans la fenêtre ajoute les liens du presse-papier (utile quand la
  surveillance est désactivée).

L'apparence suit le mode clair ou sombre de Windows ; pour l'imposer, mets `"theme": "light"` ou
`"theme": "dark"` dans `config.json` (voir [Données](#données)).

### Politique d'extraction

| Verdict vtzip | Extraction |
| --- | --- |
| PROPRE, INCONNU DE VT, DÉTECTIONS GÉNÉRIQUES | ✅ lancée |
| MALVEILLANT, SUSPECT | ⛔ bloquée |
| Analyse impossible (quota, réseau, clé absente) | ⛔ bloquée |

Un repack recompressé est presque toujours *inconnu* de VirusTotal, et les détections
génériques sont le bruit attendu sur un crack : voir [docs/vtzip.md](docs/vtzip.md). Pour extraire
malgré un blocage, désactive *Analyser avec VirusTotal* puis clique *Analyser / extraire maintenant*.

Quel que soit le verdict, l'extraction n'a lieu qu'après les vérifications décrites ci-dessous.

## Sécurité

**Avant chaque extraction**, Haul vérifie l'archive et bloque (statut *Extraction bloquée*, rien
n'est écrit) si :

- WinRAR est antérieur à la **7.13** : les versions précédentes permettent à une archive piégée
  d'écrire hors du dossier d'extraction (CVE-2025-6218, CVE-2025-8088) ;
- une entrée de l'archive, dans n'importe quel volume, a un chemin absolu, contient `..` ou un
  flux NTFS (`:`) ;
- le test d'intégrité (`UnRAR t`) échoue : volume manquant, corrompu ou tronqué.

L'archive est extraite dans son dossier si tout son contenu est dans un seul dossier, sinon dans
un sous-dossier à son nom : rien n'est éparpillé ni écrasé en vrac dans le dossier de
téléchargement.

**Serveur local** : chaque requête du userscript porte un jeton secret, généré au premier
lancement et inséré dans le script quand Haul le sert. Un site web ne peut donc pas injecter de
lien, même depuis une iframe *sandbox*. L'en-tête `Host` est vérifié (DNS rebinding), la taille des
requêtes est limitée, le script n'est pas servi à une balise `<script>` d'une page tierce, et
seules les URL de page `https://fuckingfast.co/…` peuvent être ouvertes dans le navigateur.

**Intégrité des téléchargements** : chaque segment reçu doit correspondre exactement à la plage
demandée, et un fichier déjà présent n'est ignoré que s'il a la taille annoncée par le serveur.

**Clé API VirusTotal** : chiffrée avec DPAPI, lisible seulement par ton compte Windows. Une clé
enregistrée en clair par une version précédente est chiffrée à la première lecture.

## Données

| Emplacement | Contenu |
| --- | --- |
| `%APPDATA%\Haul\config.json` | Réglages de l'application (dont `theme` : `system`, `light` ou `dark`) et jeton du userscript |
| `%APPDATA%\Haul\queue.json` | Liste des téléchargements, retrouvée au lancement suivant |
| `%APPDATA%\Haul\haul.log` | Journal (liens reçus, erreurs, extractions) |
| `%APPDATA%\Haul\reports\` | Rapports VirusTotal au format JSON |
| `%APPDATA%\vtzip\` | Clé API (chiffrée) et cache des résultats VirusTotal (24 h) |

## Structure du dépôt

```
├── src/
│   ├── haul/                  application
│   │   ├── __main__.py        point d'entrée (haul, python -m haul, Haul.exe)
│   │   ├── gui.py             fenêtre Tkinter
│   │   ├── theme.py           apparence : palette claire/sombre, styles ttk, formes dessinées
│   │   ├── widgets.py         disposition fluide, sélecteurs, infobulles
│   │   ├── engine.py          file de téléchargements, états, pause / reprise
│   │   ├── notify.py          notifications, progression dans la barre des tâches (Win32)
│   │   ├── downloader.py      téléchargement segmenté avec reprise (curl_cffi)
│   │   ├── server.py          serveur local pour le userscript
│   │   ├── postprocess.py     analyse VirusTotal, vérification et extraction WinRAR
│   │   ├── clipboard.py       lecture du presse-papier HTML (Win32)
│   │   ├── links.py           reconnaissance des liens
│   │   ├── config.py, paths.py
│   │   └── assets/            userscript, icône
│   └── vtzip/                 vérification VirusTotal (aussi utilisable en ligne de commande)
├── tests/                     pytest : haul/ et vtzip/
├── scripts/                   build.ps1 (exécutable), bench.py (débit), make_icon.py
└── docs/vtzip.md              documentation de vtzip
```

## Développement

```powershell
.venv\Scripts\pytest               # tests (les tests WinRAR sont ignorés si WinRAR est absent)
.venv\Scripts\ruff check src tests # lint
```

vtzip reste utilisable seul : `.venv\Scripts\vtzip --deep C:\chemin\du\dossier`.

### Mesurer le débit

`scripts/bench.py` télécharge avec le vrai téléchargeur de Haul chaque combinaison *fichiers
simultanés × connexions par fichier* (de 1 à 6 × 1 à 16) pendant 30 s, et classe les résultats :

```powershell
.venv\Scripts\python scripts\bench.py https://nbg1-speed.hetzner.com/10GB.bin
.venv\Scripts\python scripts\bench.py <lien direct dl.fuckingfast.co> --configs 1x4,2x4,2x8,3x4
```

Pour FuckingFast, le lien direct se trouve dans `%APPDATA%\Haul\haul.log` (ligne « Lien reçu
pour … ») ; il expire, lance le benchmark juste après l'avoir récupéré.

## Licence

[MIT](LICENSE)
