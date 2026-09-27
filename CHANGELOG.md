# Changelog

Format inspiré de [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/), versions selon
[SemVer](https://semver.org/lang/fr/).

## [Non publié]

### Modifié
- Nouvelle interface : cartes et boutons arrondis, interrupteurs, sélecteurs − / +, icône d'état
  par fichier (anneau de progression, coche, alerte), résumé de la liste et état vide explicite.
- Thème clair ou sombre selon Windows, barre de titre assortie ; réglage `theme` dans `config.json`
  pour l'imposer. Interface nette aux échelles d'affichage Windows (125 %, 150 %…).
- Plus aucun bouton ni texte coupé : réglages et boutons passent à la ligne quand la fenêtre est
  étroite, le message d'état aussi, les colonnes sont dimensionnées d'après leur contenu.

### Ajouté
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
