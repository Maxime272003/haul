# Changelog

Format inspiré de [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/), versions selon
[SemVer](https://semver.org/lang/fr/).

## [Non publié]

### Corrigé
- Un fichier du même nom déjà présent dans le dossier était considéré comme téléchargé tant que
  sa taille n'était pas connue (lien tout juste ajouté), même tronqué ou d'une autre version : il
  est maintenant comparé à la taille annoncée par le serveur.
- Lancer Haul une deuxième fois ouvrait des pages sans pouvoir recevoir leurs liens (erreur au bout
  de 10 min) : la fenêtre déjà ouverte est maintenant affichée à la place.
- L'extraction pouvait écraser un dossier existant du même nom (version précédente du jeu, avec ses
  sauvegardes) : rien n'est plus jamais écrasé, un nom pris reçoit un suffixe « (2) ».
- Les erreurs de l'interface et des threads n'étaient écrites nulle part avec `Haul.exe` (pas de
  console) : elles vont dans `haul.log`, qui ne grossit plus sans fin (3 fichiers de 5 Mo).
- Noms de fichiers réservés par Windows (`CON`, `NUL`, `COM1`…) renommés.
- Plus besoin de réinstaller le userscript : la version 3.2 ne contient plus le jeton, elle le
  demande à Haul (`/token`, lisible seulement par l'extension) et le redemande s'il a changé. Une
  requête refusée indique maintenant si c'est une ancienne copie du script (sans jeton) qui tourne
  encore dans un navigateur, ou un script 3.1 à mettre à jour une dernière fois.
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
- Extraction par UnRAR, sans fenêtre, dans un dossier temporaire renommé à la fin : les volumes ne
  sont lus qu'une fois (le test d'intégrité séparé disparaît, les CRC sont vérifiés pendant
  l'extraction), un échec ne laisse rien. Avancement en pourcentage dans la liste.
- Chaque jeu est analysé et extrait dès que tous ses volumes sont téléchargés, sans attendre le
  reste de la liste.
- Fin de téléchargement plus rapide : une connexion libre prend la moitié du plus gros segment
  restant au lieu d'attendre les autres.
- Le débit max s'applique en une seconde, même au milieu d'un gros segment.
- Vitesse affichée lissée.
- Userscript 3.3 (mise à jour automatique) : envoie sa version à Haul.
- Code : fenêtres secondaires dans `dialogs.py`, enchaînement analyse / extraction dans
  `postprocess.process` (testé sans interface).
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
- Extraction refusée si l'archive contient un lien (symbolique, jonction, lien dur) ou si le disque
  n'a pas la place pour son contenu.
- Si le port 17655 est occupé par un autre programme, Haul indique lequel.
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
- Temps restant par fichier (colonne Vitesse) et pour l'ensemble.
- Espace disque vérifié avant chaque téléchargement (en comptant ceux en cours) : message clair au
  lieu d'une erreur en plein fichier.
- Nouvel essai automatique après une erreur réseau (1, 5 puis 15 min, état « Nouvel essai
  bientôt ») ; un lien direct expiré rouvre sa page une fois.
- Le lien direct est gardé dans la liste sauvegardée : la reprise au lancement suivant ne rouvre
  la page que s'il a expiré.
- Indicateur du script navigateur sous le titre (version, actif) ; avertissement quand une page
  ouverte n'a aucune nouvelle du script au bout de 20 s.
- Réglage *Un dossier par jeu* : chaque jeu dans un sous-dossier à son nom, bonus compris.
- Réglage *Archives à la corbeille après extraction*.
- Icône dans la zone de notification (afficher, tout suspendre, ouvrir le dossier, quitter) ;
  réduire la fenêtre l'y range. Réglage *Démarrer avec Windows* (réduit).
- Liste : volumes d'un même jeu regroupés sous une ligne repliable, tri par colonne, champ
  *Filtrer* (Ctrl+F), *Placer en tête / en fin de file* (Alt+↑ / Alt+↓).
- *Ajouter des liens…* (coller ou importer un fichier) et dépôt de fichiers `.html` / `.txt` /
  `.url` sur la fenêtre.
- Pause / reprise par fichier : bouton *Mettre en pause / Reprendre* pour la sélection
  (<kbd>Ctrl</kbd>+<kbd>A</kbd> pour tout sélectionner), menu contextuel, touche Espace ; *Passer ce
  lien* pour une page qui attend un captcha ; *Rouvrir la page*.
- *Tout suspendre / Tout reprendre* : met toute la liste en pause ; tant que Haul est suspendu,
  les liens ajoutés arrivent en pause au lieu d'ouvrir des pages.
- *Tout supprimer* : vide la liste après confirmation (les téléchargements en cours sont arrêtés,
  les fichiers terminés restent sur le disque) ; option pour supprimer aussi les téléchargements
  inachevés (`.part` et état de reprise, effacés une fois le téléchargement arrêté).
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
