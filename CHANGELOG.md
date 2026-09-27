# Changelog

Format inspiré de [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/), versions selon
[SemVer](https://semver.org/lang/fr/).

## [Non publié]

### Corrigé
- « Retirer les terminés » empêchait d'ajouter de nouveau les mêmes liens.
- Un fichier déjà présent mais tronqué était considéré comme terminé : sa taille est maintenant
  comparée à celle annoncée par le serveur.
- Un segment reçu avec une autre plage que celle demandée n'est plus écrit dans le fichier.
- Démarrage des gros téléchargements : le fichier `.part` était agrandi à sa taille finale en
  écrivant des zéros (Python sous Windows), soit ~10 s de disque avant le premier octet pour
  10 Go, et chaque octet écrit deux fois. Il est maintenant créé « creux » (NTFS) : instantané.
- Un 429/503 à la connexion (serveur occupé par les autres fichiers) mettait le fichier en erreur
  et lui faisait perdre son lien direct : Haul patiente et redemande (5, 15 puis 30 s). Si le
  serveur refuse toujours, le fichier retourne en file (lien gardé) et le nombre de fichiers
  simultanés est ramené à ce que le serveur accepte, jusqu'à ce qu'un téléchargement se termine.

### Modifié
- Écriture des téléchargements bufferisée (un fichier ouvert par connexion, tampon de 1 Mo),
  compteurs de progression sans verrou.
- États des fichiers typés (`State`) au lieu de libellés comparés comme du texte.
- Nouvelle interface : cartes et boutons arrondis, interrupteurs, sélecteurs − / +, icône d'état
  par fichier (anneau de progression, coche, alerte), résumé de la liste et état vide explicite.
- Thème clair ou sombre selon Windows, barre de titre assortie ; réglage `theme` dans `config.json`
  pour l'imposer. Interface nette aux échelles d'affichage Windows (125 %, 150 %…).
- Plus aucun bouton ni texte coupé : réglages et boutons passent à la ligne quand la fenêtre est
  étroite, le message d'état aussi, les colonnes sont dimensionnées d'après leur contenu.

### Sécurité
- Serveur local protégé par un jeton secret propre à l'installation (en-tête `X-Haul-Token`,
  inséré dans le userscript servi) : un site web ne peut plus injecter de lien, même depuis une
  iframe *sandbox* (`Origin: null`). **Le userscript doit être réinstallé** (version 3.1, qui se
  met ensuite à jour depuis l'application).
- Seules les URL de page `https://fuckingfast.co/…` peuvent être ouvertes par l'application : une
  URL de page arbitraire envoyée au serveur local pouvait être passée à `os.startfile` via
  « Réessayer » (exécution d'un programme). Vérification de l'en-tête `Host` (DNS rebinding),
  taille des requêtes limitée, userscript refusé aux balises `<script>` de pages tierces.
- Vérifications avant chaque extraction : WinRAR 7.13 minimum (CVE-2025-6218, CVE-2025-8088),
  chemins de toutes les entrées de tous les volumes (absolu, `..`, flux NTFS), test d'intégrité.
  Extraction dans un sous-dossier au nom de l'archive quand son contenu n'est pas déjà dans un
  seul dossier.
- Clé API VirusTotal chiffrée avec DPAPI ; une ancienne clé en clair est chiffrée à la première lecture.

### Ajouté
- Pause / reprise par fichier : bouton *Mettre en pause / Reprendre* pour la sélection
  (<kbd>Ctrl</kbd>+<kbd>A</kbd> pour tout sélectionner), menu contextuel, touche Espace ; *Passer ce
  lien* pour une page qui attend un captcha ; *Rouvrir la page*.
- *Tout suspendre / Tout reprendre* : met toute la liste en pause ; tant que Haul est suspendu,
  les liens ajoutés arrivent en pause au lieu d'ouvrir des pages.
- `scripts/bench.py` : mesure le débit de chaque combinaison fichiers simultanés × connexions
  par fichier avec le vrai téléchargeur (voir README, *Mesurer le débit*).
- Liste des téléchargements sauvegardée (`%APPDATA%\Haul\queue.json`) et retrouvée au lancement
  suivant, les téléchargements interrompus en pause. Confirmation avant de quitter pendant des
  téléchargements.
- Fenêtre *Clé VirusTotal…* : saisie, test et enregistrement de la clé sans ligne de commande ;
  ouverte automatiquement quand l'analyse échoue faute de clé.
- Notifications Windows (captcha à valider, liste terminée, extraction terminée ou bloquée),
  bouton de la barre des tâches qui clignote, progression affichée sur ce bouton.
- Réglage *Débit max* (plafond du débit total, réparti entre les connexions).
- Texte complet d'une cellule au survol, statut complet de la ligne sélectionnée dans la barre d'état.
- Menu contextuel (afficher dans l'Explorateur, copier le lien, réessayer, retirer), double-clic,
  touche Suppr, Ctrl+V pour ajouter les liens du presse-papier.
- Boutons grisés quand ils n'ont rien à faire ; message clair quand les liens copiés sont déjà
  dans la liste.

## [1.0.0] — 2026-09-27

Première version publiée sous le nom **Haul** (anciennement *multi-dl*).

### Ajouté
- Surveillance du presse-papier, y compris la version HTML (liens derrière les noms de fichiers).
- Ouverture des pages FuckingFast dans le navigateur habituel, une à la fois ; userscript
  (Violentmonkey/Tampermonkey) qui récupère le lien direct et clique DOWNLOAD sur les pages
  ouvertes par l'application.
- Téléchargement segmenté multi-connexions avec reprise, gestion des serveurs qui limitent
  les connexions (429/503).
- Analyse VirusTotal du lot avec vtzip, exécutée dans le processus ; extraction bloquée si un
  fichier est malveillant, suspect ou non vérifié ; rapport détaillé consultable dans l'application.
- Extraction WinRAR automatique (*Extraire et mettre à jour*, *Remplacer sans demander*).
- Débit total affiché, exécutable autonome `Haul.exe` (PyInstaller).
- vtzip intégré au dépôt (auparavant projet séparé) ; UnRAR lancé sans fenêtre console.
