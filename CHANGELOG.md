# Changelog

Format inspiré de [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/), versions selon
[SemVer](https://semver.org/lang/fr/).

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
