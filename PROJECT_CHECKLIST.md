# Checklist Complète du Projet de Sécurité

## 📋 Vue d'Ensemble du Projet

**Projet** : Sécurité Informatique - CI/CD & Challenges Web
**Parties** : 2 parties distinctes
**Statut Global** : ⬜ En cours

---

## 🎯 Partie 1 : CI/CD avec Application Vulnérable

### ✅ Checklist Technique

#### Application Python
- [x] Application Flask fonctionnelle
- [x] Vulnérabilités implémentées :
  - [x] SQL Injection (login et search)
  - [x] Path Traversal (download)
  - [x] Information Disclosure (erreurs SQL)
- [x] Endpoint de santé (/health)
- [x] Base de données SQLite
- [x] Fichiers de test générés

#### Tests
- [x] Tests unitaires avec pytest
- [x] Couverture de code >80%
- [x] Tests de vulnérabilités
- [x] Tests de santé

#### Docker
- [x] Dockerfile multi-stage
- [x] .dockerignore configuré
- [x] Image optimisée (utilisateur non-root)
- [x] Healthcheck configuré
- [x] docker-compose.yml (2 versions)

#### Pipeline CI/CD (.github/workflows/ci-cd.yml)
- [x] Job 1 : Tests multi-versions Python (3.9, 3.10, 3.11, 3.12)
  - [x] Installation des dépendances
  - [x] Analyse statique (Flake8)
  - [x] Exécution des tests
  - [x] Rapport de couverture
- [x] Job 2 : Scan Trivy Filesystem
  - [x] Analyse du code source
  - [x] Détection des vulnérabilités
  - [x] Upload SARIF
- [x] Job 3 : Build & Scan Docker
  - [x] Construction de l'image
  - [x] Scan Trivy de l'image
  - [x] Test du conteneur
- [x] Job 4 : Push Docker Hub
  - [x] Multi-architecture (amd64, arm64)
  - [x] Tags automatiques
  - [x] Uniquement sur main
- [x] Job 5 : Rapport final

#### Documentation
- [x] README.md complet
- [x] QUICKSTART.md
- [x] SECURITY.md (analyse des vulnérabilités)
- [x] CONTRIBUTING.md (guide de personnalisation)
- [x] Makefile (commandes automatisées)

#### Version Sécurisée
- [x] app_secure.py créé
- [x] Corrections de toutes les vulnérabilités
- [x] Comparaison possible entre versions

### 🚀 Actions à Faire pour la Partie 1

#### Configuration GitHub
- [ ] Créer un repository GitHub
- [ ] Initialiser git localement
```bash
git init
git add .
git commit -m "Initial commit: Projet CI/CD Sécurité"
git branch -M main
git remote add origin https://github.com/VOTRE_USERNAME/ProjetSecu.git
git push -u origin main
```

#### Configuration des Secrets
- [ ] Créer un compte Docker Hub (si pas déjà fait)
- [ ] Générer un Access Token Docker Hub
- [ ] Ajouter les secrets GitHub :
  - [ ] `DOCKER_USERNAME` : Votre username Docker Hub
  - [ ] `DOCKER_PASSWORD` : Votre token Docker Hub

#### Tests Locaux
- [ ] Installer les dépendances : `pip install -r requirements.txt`
- [ ] Lancer l'application : `python app.py`
- [ ] Tester l'accès : http://localhost:5000
- [ ] Exécuter les tests : `pytest test_app.py -v`
- [ ] Vérifier la couverture : `pytest --cov=app`

#### Tests des Vulnérabilités
- [ ] Tester SQL Injection :
  - [ ] Username: `admin' OR '1'='1--`
  - [ ] Capturer un screenshot
- [ ] Tester Path Traversal :
  - [ ] File: `../app.py`
  - [ ] Capturer un screenshot
- [ ] Lancer exploit_demo.py
  - [ ] `python exploit_demo.py`

#### Docker
- [ ] Build local : `docker build -t bibliotheque-app .`
- [ ] Test local : `docker run -p 5000:5000 bibliotheque-app`
- [ ] Vérifier l'accès : http://localhost:5000
- [ ] (Optionnel) Scanner avec Trivy local

#### Pipeline GitHub Actions
- [ ] Vérifier que le pipeline se lance automatiquement
- [ ] Consulter l'onglet Actions
- [ ] Vérifier que tous les jobs passent
- [ ] Vérifier les résultats Trivy
- [ ] Vérifier le push Docker Hub (si sur main)

#### Personnalisation (Recommandé)
- [ ] Modifier les noms de variables
- [ ] Ajouter des commentaires personnels
- [ ] Changer les messages/textes
- [ ] Ajouter votre nom dans les commentaires
- [ ] (Bonus) Ajouter une vulnérabilité XSS

#### Captures d'Écran pour le Rapport
- [ ] Application fonctionnelle
- [ ] Tests qui passent
- [ ] Résultats Trivy (vulnérabilités détectées)
- [ ] Pipeline GitHub Actions (tous les jobs)
- [ ] Image Docker Hub
- [ ] Démonstration des vulnérabilités

---

## 🔒 Partie 2 : Challenges de Sécurité Web

### 📝 Checklist des Challenges

#### Challenge 1 : Path Traversal - Null Byte Bypass
- **URL** : https://portswigger.net/web-security/file-path-traversal/lab-validate-file-extension-null-byte-bypass
- [ ] Challenge complété
- [ ] Flag récupéré
- [ ] Documentation dans CHALLENGES.md
  - [ ] Étapes de découverte
  - [ ] Payload utilisé : `../../../etc/passwd%00.jpg`
  - [ ] Explication du null byte
  - [ ] Screenshots
  - [ ] Recommandations de sécurisation
  - [ ] Références

#### Challenge 2 : PHP Filters
- **URL** : https://www.root-me.org/fr/Challenges/Web-Serveur/PHP-Filters
- [ ] Challenge complété
- [ ] Flag récupéré
- [ ] Documentation dans CHALLENGES.md
  - [ ] Étapes de découverte
  - [ ] Payload : `php://filter/convert.base64-encode/resource=...`
  - [ ] Décodage du base64
  - [ ] Screenshots
  - [ ] Recommandations
  - [ ] Références

#### Challenge 3 : CSRF - Contournement de Jeton
- **URL** : https://www.root-me.org/fr/Challenges/Web-Client/CSRF-contournement-de-jeton
- [ ] Challenge complété
- [ ] Flag récupéré
- [ ] Documentation dans CHALLENGES.md
  - [ ] Étapes de découverte
  - [ ] Payload (formulaire HTML)
  - [ ] Technique de bypass du token
  - [ ] Screenshots
  - [ ] Recommandations
  - [ ] Références

#### Challenge 4 : CSRF - Token Not Tied to Session
- **URL** : https://portswigger.net/web-security/csrf/bypassing-token-validation/lab-token-not-tied-to-user-session
- [ ] Challenge complété
- [ ] Flag récupéré
- [ ] Documentation dans CHALLENGES.md
  - [ ] Étapes de découverte
  - [ ] Payload avec token d'un autre utilisateur
  - [ ] Explication de la faille
  - [ ] Screenshots
  - [ ] Recommandations
  - [ ] Références

#### Challenge 5 : CSRF - Referer Validation Bypass
- **URL** : https://portswigger.net/web-security/csrf/bypassing-referer-based-defenses/lab-referer-validation-depends-on-header-being-present
- [ ] Challenge complété
- [ ] Flag récupéré
- [ ] Documentation dans CHALLENGES.md
  - [ ] Étapes de découverte
  - [ ] Payload avec `<meta name="referrer" content="no-referrer">`
  - [ ] Explication du bypass
  - [ ] Screenshots
  - [ ] Recommandations
  - [ ] Références

#### Challenge 6 : JWT - Jeton Révoqué
- **URL** : https://www.root-me.org/fr/Challenges/Web-Serveur/JWT-Jeton-revoque
- [ ] Challenge complété
- [ ] Flag récupéré
- [ ] Documentation dans CHALLENGES.md
  - [ ] Étapes de découverte
  - [ ] Décodage du JWT sur jwt.io
  - [ ] Technique de réutilisation
  - [ ] Screenshots
  - [ ] Recommandations (blacklist, JTI)
  - [ ] Références

#### Challenge 7 : SQL Injection - Error Based
- **URL** : https://www.root-me.org/fr/Challenges/Web-Serveur/SQL-injection-Error
- [ ] Challenge complété
- [ ] Flag récupéré
- [ ] Documentation dans CHALLENGES.md
  - [ ] Étapes de découverte
  - [ ] Payload EXTRACTVALUE ou UPDATEXML
  - [ ] Extraction des données via erreurs
  - [ ] Screenshots
  - [ ] Recommandations
  - [ ] Références

#### Challenge 8 : Command Injection - Filter Bypass
- **URL** : https://www.root-me.org/fr/Challenges/Web-Serveur/Injection-de-commande-Contournement-de-filtre
- [ ] Challenge complété
- [ ] Flag récupéré
- [ ] Documentation dans CHALLENGES.md
  - [ ] Étapes de découverte
  - [ ] Payload avec bypass (newline, ${IFS}, etc.)
  - [ ] Technique de contournement
  - [ ] Screenshots
  - [ ] Recommandations
  - [ ] Références

#### Challenge 9 : XSS Stockée 2
- **URL** : https://www.root-me.org/fr/Challenges/Web-Client/XSS-Stockee-2
- [ ] Challenge complété
- [ ] Flag récupéré
- [ ] Documentation dans CHALLENGES.md
  - [ ] Étapes de découverte
  - [ ] Payload (event handlers, balises alternatives)
  - [ ] Bypass des filtres
  - [ ] Screenshots
  - [ ] Recommandations
  - [ ] Références

#### Challenge 10 : SSTI - Unknown Language
- **URL** : https://portswigger.net/web-security/server-side-template-injection/exploiting/lab-server-side-template-injection-in-an-unknown-language-with-a-documented-exploit
- [ ] Challenge complété
- [ ] Flag récupéré
- [ ] Documentation dans CHALLENGES.md
  - [ ] Étapes de découverte
  - [ ] Identification du moteur ({{7*7}}, etc.)
  - [ ] Payload RCE adapté au moteur
  - [ ] Screenshots
  - [ ] Recommandations
  - [ ] Références

#### Challenge 11 : API Mass Assignment
- **URL** : https://www.root-me.org/fr/Challenges/Web-Serveur/API-Mass-Assignment
- [ ] Challenge complété
- [ ] Flag récupéré
- [ ] Documentation dans CHALLENGES.md
  - [ ] Étapes de découverte
  - [ ] Payload avec champs additionnels (role, is_admin)
  - [ ] Énumération des champs
  - [ ] Screenshots
  - [ ] Recommandations
  - [ ] Références

### 🛠️ Préparation pour la Partie 2

#### Installation des Outils
- [ ] Installer Burp Suite Community
- [ ] Configurer le proxy (127.0.0.1:8080)
- [ ] Installer le certificat SSL de Burp
- [ ] Installer les extensions de navigateur (FoxyProxy)
- [ ] Installer les dépendances Python :
```bash
pip install requests colorama pyjwt cryptography
```

#### Organisation des Fichiers
- [ ] Créer le dossier screenshots : `mkdir screenshots`
- [ ] Lire CHALLENGE_GUIDE.md
- [ ] Consulter payloads.txt
- [ ] Tester challenge_helper.py

#### Comptes Nécessaires
- [ ] Créer un compte PortSwigger (gratuit)
- [ ] Créer un compte Root-Me (gratuit)
- [ ] (Optionnel) Abonnement Root-Me Premium pour accès complet

### 📊 Progression Globale Partie 2

**Challenges Complétés** : 0/11 (0%)

- [ ] Challenge 1 - Path Traversal
- [ ] Challenge 2 - PHP Filters
- [ ] Challenge 3 - CSRF Contournement
- [ ] Challenge 4 - CSRF Token
- [ ] Challenge 5 - CSRF Referer
- [ ] Challenge 6 - JWT
- [ ] Challenge 7 - SQL Injection
- [ ] Challenge 8 - Command Injection
- [ ] Challenge 9 - XSS
- [ ] Challenge 10 - SSTI
- [ ] Challenge 11 - Mass Assignment

---

## 📦 Livrables Finaux

### Partie 1 : CI/CD

**Fichiers à Remettre :**
- [ ] Lien vers le repository GitHub
- [ ] README.md complet
- [ ] Code source de l'application (app.py, app_secure.py)
- [ ] Tests (test_app.py)
- [ ] Dockerfile et docker-compose.yml
- [ ] Pipeline CI/CD (.github/workflows/ci-cd.yml)
- [ ] SECURITY.md (analyse des vulnérabilités)
- [ ] Screenshots du pipeline en action
- [ ] Screenshots des résultats Trivy
- [ ] Lien vers l'image Docker Hub

**Optionnel mais Recommandé :**
- [ ] Vidéo de démonstration (5-10 min)
- [ ] Rapport d'analyse des vulnérabilités
- [ ] Documentation des corrections appliquées

### Partie 2 : Challenges

**Fichiers à Remettre :**
- [ ] CHALLENGES.md complété (11 challenges)
- [ ] Screenshots de tous les challenges (dossier screenshots/)
- [ ] (Optionnel) Scripts d'exploitation personnalisés
- [ ] (Optionnel) Rapport d'analyse comparative

**Contenu de CHALLENGES.md pour Chaque Challenge :**
- [ ] Nom et URL du challenge
- [ ] Étapes de découverte (méthodologie)
- [ ] Payload utilisé avec explication
- [ ] Screenshots (requête + réponse + flag)
- [ ] Recommandations de sécurisation (code + références)
- [ ] Liens de références (OWASP, documentation)

---

## 🎓 Critères d'Évaluation

### Partie 1 : CI/CD (50%)

| Critère | Points | Statut |
|---------|--------|--------|
| Application fonctionnelle | 10 | ⬜ |
| Vulnérabilités implémentées | 10 | ⬜ |
| Tests et couverture | 10 | ⬜ |
| Pipeline CI/CD complet | 10 | ⬜ |
| Analyse Trivy | 5 | ⬜ |
| Docker Hub | 5 | ⬜ |
| Documentation | 5 | ⬜ |
| Version sécurisée | 5 | ⬜ |
| **Total Partie 1** | **60** | **⬜** |

### Partie 2 : Challenges (50%)

| Critère | Points | Statut |
|---------|--------|--------|
| Challenges résolus (11 x 3) | 33 | ⬜ |
| Documentation détaillée | 10 | ⬜ |
| Screenshots de qualité | 5 | ⬜ |
| Recommandations pertinentes | 7 | ⬜ |
| Références appropriées | 5 | ⬜ |
| **Total Partie 2** | **60** | **⬜** |

### Bonus (20 points max)

- [ ] Personnalisation avancée de l'app (+5)
- [ ] Ajout de vulnérabilités supplémentaires (+5)
- [ ] Scripts d'automatisation (+5)
- [ ] Vidéo de démonstration (+5)
- [ ] Rapport d'analyse approfondi (+5)
- [ ] Contribution originale (+5)

**Note Maximale** : 120/100 → 20/20

---

## ⏰ Planning Recommandé

### Semaine 1 : Partie 1 - CI/CD

**Jour 1-2 : Setup Initial**
- [ ] Comprendre l'application
- [ ] Tester localement
- [ ] Créer le Dockerfile

**Jour 3-4 : Pipeline CI/CD**
- [ ] Créer le workflow GitHub Actions
- [ ] Configurer Trivy
- [ ] Tester le pipeline

**Jour 5 : Docker Hub & Documentation**
- [ ] Configurer le push Docker Hub
- [ ] Finaliser la documentation
- [ ] Personnaliser le code

**Jour 6-7 : Tests et Validation**
- [ ] Tester l'ensemble
- [ ] Capturer les screenshots
- [ ] Préparer les livrables

### Semaine 2 : Partie 2 - Challenges

**Jour 1 : Préparation**
- [ ] Installer les outils (Burp Suite)
- [ ] Lire les guides
- [ ] Créer les comptes

**Jour 2-3 : Challenges Faciles (⭐)**
- [ ] Challenge 2 : PHP Filters
- [ ] Challenge 5 : CSRF Referer
- [ ] Challenge 7 : SQL Injection

**Jour 4-5 : Challenges Intermédiaires (⭐⭐)**
- [ ] Challenges 1, 3, 4, 6
- [ ] Challenges 8, 9, 11

**Jour 6 : Challenge Avancé (⭐⭐⭐)**
- [ ] Challenge 10 : SSTI

**Jour 7 : Documentation Finale**
- [ ] Compléter CHALLENGES.md
- [ ] Organiser les screenshots
- [ ] Relecture et validation

---

## 📝 Notes Importantes

### À Faire Absolument ✅
- Tester localement avant de push
- Documenter au fur et à mesure
- Capturer les screenshots immédiatement
- Personnaliser le code (ne pas laisser tout "comme l'IA")
- Comprendre ce que vous faites (pas juste copier-coller)

### À Éviter ❌
- Ne jamais tester sur des sites sans autorisation
- Ne pas partager les flags publiquement
- Ne pas plagier des write-ups
- Ne pas oublier les screenshots
- Ne pas attendre la dernière minute

### En Cas de Problème 🆘
1. Consulter la documentation (README, guides)
2. Rechercher l'erreur sur Google
3. Vérifier les logs (GitHub Actions, Docker)
4. Tester avec les scripts fournis (challenge_helper.py)
5. Demander de l'aide si vraiment bloqué

---

## ✅ Validation Finale

### Avant de Remettre le Projet

**Partie 1 :**
- [ ] Le repository GitHub est accessible
- [ ] Le pipeline CI/CD fonctionne
- [ ] Tous les jobs passent (ou les échecs sont expliqués)
- [ ] L'image Docker est sur Docker Hub
- [ ] La documentation est complète et claire
- [ ] Les screenshots sont présents et lisibles

**Partie 2 :**
- [ ] Les 11 challenges sont documentés
- [ ] Chaque challenge a ses screenshots
- [ ] Les payloads sont expliqués
- [ ] Les recommandations sont pertinentes
- [ ] Les références sont valides

**Général :**
- [ ] Pas de fautes d'orthographe majeures
- [ ] Langage professionnel
- [ ] Code propre et commenté
- [ ] Tout est compréhensible par quelqu'un d'autre

---

**Date de début** : ___/___/_____
**Date de rendu** : ___/___/_____
**Temps estimé** : 40-60 heures

**Bon courage! 🚀**
