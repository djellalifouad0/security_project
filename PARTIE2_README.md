# Partie 2 - Challenges de Sécurité Web

Documentation et ressources pour la résolution des 11 challenges de sécurité web.

## 📁 Fichiers de la Partie 2

```
ProjetSecu/
├── CHALLENGES.md              # Documentation des challenges (à remplir)
├── CHALLENGE_GUIDE.md         # Guide méthodologique complet
├── PARTIE2_README.md          # Ce fichier
├── challenge_helper.py        # Script d'aide Python
├── payloads.txt               # Collection de payloads
└── screenshots/               # Dossier pour les captures d'écran
```

## 🎯 Liste des Challenges

| # | Challenge | Plateforme | Type | Difficulté |
|---|-----------|------------|------|------------|
| 1 | Path Traversal - Null Byte | PortSwigger | Path Traversal | ⭐⭐ |
| 2 | PHP Filters | Root-Me | LFI | ⭐ |
| 3 | CSRF - Contournement de Jeton | Root-Me | CSRF | ⭐⭐ |
| 4 | CSRF - Token Not Tied to Session | PortSwigger | CSRF | ⭐⭐ |
| 5 | CSRF - Referer Validation Bypass | PortSwigger | CSRF | ⭐ |
| 6 | JWT - Jeton Révoqué | Root-Me | JWT | ⭐⭐ |
| 7 | SQL Injection - Error Based | Root-Me | SQLi | ⭐ |
| 8 | Command Injection - Filter Bypass | Root-Me | Command Injection | ⭐⭐ |
| 9 | XSS Stockée 2 | Root-Me | XSS | ⭐⭐ |
| 10 | SSTI - Unknown Language | PortSwigger | SSTI | ⭐⭐⭐ |
| 11 | API Mass Assignment | Root-Me | API Security | ⭐⭐ |

## 🚀 Démarrage Rapide

### 1. Installation des Dépendances

```bash
# Installer les bibliothèques Python nécessaires
pip install requests colorama pyjwt

# (Optionnel) Installer des outils supplémentaires
pip install sqlmap jwt_tool
```

### 2. Utilisation du Script Helper

```bash
# Voir l'aide
python challenge_helper.py

# Tester Path Traversal
python challenge_helper.py path-traversal "http://target.com/download" file

# Décoder un JWT
python challenge_helper.py jwt-decode "eyJhbGci..."

# Encoder en Base64
python challenge_helper.py base64-encode "texte à encoder"

# Générer un POC CSRF
python challenge_helper.py csrf-poc "http://target.com/action" '{"email":"hack@mail.com"}'
```

### 3. Structure de Documentation

Pour chaque challenge dans [CHALLENGES.md](CHALLENGES.md), documenter :

1. **📋 Informations** :
   - Nom et URL du challenge
   - Catégorie et difficulté

2. **🔍 Étapes de Découverte** :
   - Comment avez-vous identifié la vulnérabilité ?
   - Quels tests avez-vous effectués ?
   - Quelle était votre méthodologie ?

3. **💉 Payload Utilisé** :
   - Le payload final qui a fonctionné
   - Explication du fonctionnement

4. **📸 Screenshot** :
   - Requête avec le payload
   - Réponse du serveur
   - Flag obtenu

5. **🛡️ Recommandations de Sécurisation** :
   - Code vulnérable vs code sécurisé
   - Bonnes pratiques
   - Configuration recommandée

6. **📚 Références** :
   - Liens OWASP
   - Articles techniques
   - Documentation officielle

## 📚 Ressources Principales

### Fichiers Fournis

#### [CHALLENGE_GUIDE.md](CHALLENGE_GUIDE.md)
Guide méthodologique détaillé avec :
- Processus de résolution étape par étape
- Techniques spécifiques par type de vulnérabilité
- Commandes et scripts utiles
- Conseils et astuces

#### [payloads.txt](payloads.txt)
Collection complète de payloads pour :
- Path Traversal
- LFI / PHP Filters
- SQL Injection
- Command Injection
- XSS
- CSRF
- SSTI
- JWT
- Et plus...

#### [challenge_helper.py](challenge_helper.py)
Script Python avec fonctions pour :
- Tester automatiquement les vulnérabilités
- Encoder/décoder (URL, Base64, JWT)
- Envoyer des requêtes HTTP personnalisées
- Générer des POC CSRF

### Sites de Référence

**Plateformes de Challenge :**
- PortSwigger Web Security Academy : https://portswigger.net/web-security
- Root-Me : https://www.root-me.org/

**Documentation de Sécurité :**
- OWASP Top 10 : https://owasp.org/www-project-top-ten/
- OWASP Cheat Sheet Series : https://cheatsheetseries.owasp.org/
- HackTricks : https://book.hacktricks.xyz/
- PayloadsAllTheThings : https://github.com/swisskyrepo/PayloadsAllTheThings

## 🛠️ Configuration des Outils

### Burp Suite Community

1. **Télécharger** : https://portswigger.net/burp/communitydownload
2. **Configuration Proxy** :
   - Proxy → Options → Bind to port: 8080
   - Intercept → Intercept is on
3. **Navigateur** :
   - Installer FoxyProxy
   - Configurer proxy : 127.0.0.1:8080
4. **Certificat SSL** :
   - http://burp → CA Certificate
   - Importer dans le navigateur

### Extensions de Navigateur Utiles

- **FoxyProxy** : Gestion de proxy
- **Cookie-Editor** : Éditer les cookies
- **Wappalyzer** : Détecter les technologies
- **EditThisCookie** : Modifier les cookies
- **HackTools** : Collection d'outils de pentest

## 📸 Capture de Screenshots

### Organisation

```bash
# Créer un dossier pour les screenshots
mkdir screenshots

# Nommage clair
screenshots/
├── challenge01_path_traversal_request.png
├── challenge01_path_traversal_response.png
├── challenge01_flag.png
├── challenge02_php_filters_request.png
├── ...
```

### Que Capturer ?

Pour chaque challenge :
1. La requête avec le payload (Burp Suite ou DevTools)
2. La réponse du serveur montrant l'exploitation
3. Le flag obtenu
4. (Optionnel) Code source ou configuration pertinent

### Outils de Capture

**Windows :**
- Snipping Tool (Win + Shift + S)
- Snagit

**Linux :**
```bash
# Installer Flameshot
sudo apt install flameshot

# Lancer
flameshot gui
```

**macOS :**
- Cmd + Shift + 4 (sélection)
- Cmd + Shift + 3 (plein écran)

## 📝 Workflow Recommandé

### Pour Chaque Challenge

```
1. Lire l'énoncé attentivement
   └─ Noter les indices importants

2. Reconnaissance
   └─ Explorer l'application
   └─ Identifier les technologies
   └─ Cartographier les fonctionnalités

3. Tests initiaux
   └─ Utiliser challenge_helper.py
   └─ Tester avec Burp Suite
   └─ Consulter payloads.txt

4. Exploitation
   └─ Construire le payload
   └─ Tester et itérer
   └─ Capturer les preuves

5. Documentation
   └─ Remplir CHALLENGES.md
   └─ Ajouter les screenshots
   └─ Rechercher les recommandations

6. Validation
   └─ Relire la documentation
   └─ Vérifier les screenshots
   └─ S'assurer que tout est clair
```

## 🎓 Conseils de Résolution

### Stratégies Générales

**Commencer par les Faciles (⭐)**
- Challenge 2 : PHP Filters
- Challenge 5 : CSRF Referer Bypass
- Challenge 7 : SQL Injection Error

**Puis Intermédiaires (⭐⭐)**
- Challenge 1 : Path Traversal
- Challenge 3, 4 : CSRF
- Challenge 6 : JWT
- Challenge 8 : Command Injection
- Challenge 9 : XSS
- Challenge 11 : Mass Assignment

**Finir par l'Avancé (⭐⭐⭐)**
- Challenge 10 : SSTI

### Si Vous êtes Bloqué

1. **Relire l'énoncé** : Les indices sont souvent dans le texte
2. **Consulter le guide** : [CHALLENGE_GUIDE.md](CHALLENGE_GUIDE.md) a des techniques détaillées
3. **Chercher des write-ups similaires** : Google "[type] CTF write-up"
4. **Faire une pause** : Revenir avec un esprit frais
5. **Essayer un autre challenge** : Varier aide à débloquer

### Méthodologie de Test

```python
# Pattern général
for payload in payloads:
    response = send_request(payload)
    if is_vulnerable(response):
        capture_screenshot()
        document_finding()
        break
```

## 🔒 Sécurité et Éthique

### ⚠️ IMPORTANT

- **NE JAMAIS** tester sur des sites sans autorisation
- **UNIQUEMENT** sur :
  - PortSwigger Labs (autorisés)
  - Root-Me Challenges (autorisés)
  - Votre propre infrastructure de test
- **RESPECTER** les règles des plateformes
- **NE PAS** partager les flags publiquement

### Utilisation Légale

Ces outils et techniques sont fournis à des fins éducatives uniquement. L'utilisation sur des systèmes sans autorisation est illégale et peut entraîner des poursuites.

## 📊 Suivi de Progression

### Template de Checklist

```markdown
## Progression des Challenges

- [ ] Challenge 1 - Path Traversal Null Byte
- [ ] Challenge 2 - PHP Filters
- [ ] Challenge 3 - CSRF Contournement
- [ ] Challenge 4 - CSRF Token Not Tied
- [ ] Challenge 5 - CSRF Referer Bypass
- [ ] Challenge 6 - JWT Révoqué
- [ ] Challenge 7 - SQL Injection Error
- [ ] Challenge 8 - Command Injection
- [ ] Challenge 9 - XSS Stockée 2
- [ ] Challenge 10 - SSTI
- [ ] Challenge 11 - API Mass Assignment

Total : 0/11 (0%)
```

### Tableau de Bord

| Challenge | Statut | Flag | Documentation | Screenshots |
|-----------|--------|------|---------------|-------------|
| 1. Path Traversal | ⬜ | ⬜ | ⬜ | ⬜ |
| 2. PHP Filters | ⬜ | ⬜ | ⬜ | ⬜ |
| 3. CSRF Contournement | ⬜ | ⬜ | ⬜ | ⬜ |
| 4. CSRF Token | ⬜ | ⬜ | ⬜ | ⬜ |
| 5. CSRF Referer | ⬜ | ⬜ | ⬜ | ⬜ |
| 6. JWT | ⬜ | ⬜ | ⬜ | ⬜ |
| 7. SQL Injection | ⬜ | ⬜ | ⬜ | ⬜ |
| 8. Command Injection | ⬜ | ⬜ | ⬜ | ⬜ |
| 9. XSS | ⬜ | ⬜ | ⬜ | ⬜ |
| 10. SSTI | ⬜ | ⬜ | ⬜ | ⬜ |
| 11. Mass Assignment | ⬜ | ⬜ | ⬜ | ⬜ |

## 🏆 Critères d'Évaluation

### Ce qui est Attendu

**Pour chaque challenge (obligatoire) :**
- ✅ Nom et URL du challenge
- ✅ Étapes de découverte détaillées
- ✅ Payload utilisé avec explication
- ✅ Screenshots de la preuve
- ✅ Recommandations de sécurisation
- ✅ Références (liens vers documentation)

**Bonus (pour améliorer la note) :**
- 🌟 Explication approfondie de la vulnérabilité
- 🌟 Plusieurs méthodes d'exploitation
- 🌟 Code de démonstration
- 🌟 Comparaison avant/après correction
- 🌟 Analyse d'impact (CVSS, etc.)

### Qualité de la Documentation

**Excellent (18-20/20) :**
- Documentation complète et détaillée
- Explication claire de la méthodologie
- Screenshots professionnels et annotés
- Recommandations de sécurité approfondies
- Références pertinentes et à jour

**Bien (15-17/20) :**
- Documentation complète
- Étapes claires
- Screenshots présents
- Recommandations de base
- Quelques références

**Passable (12-14/20) :**
- Documentation basique
- Étapes manquantes
- Screenshots incomplets
- Recommandations superficielles

## 💡 Astuces pour la Rédaction

### Structure Claire

```markdown
## Challenge X: [Nom]

### 🔍 Découverte
1. J'ai d'abord...
2. Puis j'ai testé...
3. Ensuite j'ai remarqué...

### 💉 Exploitation
Le payload final était : `...`

Explication : Ce payload fonctionne car...

### 📸 Preuve
[Insérer screenshots]

### 🛡️ Correction
Le problème vient de...
La solution est...
```

### Langage Professionnel

**Bon :**
- "J'ai identifié une vulnérabilité de type Path Traversal..."
- "Le test avec le payload `../../../etc/passwd` a révélé..."
- "Cette vulnérabilité permet à un attaquant de..."

**À éviter :**
- "J'ai hacké le site..."
- "C'était facile..."
- "Le site est nul..."

## 📚 Ressources Supplémentaires

### Livres Recommandés
- "The Web Application Hacker's Handbook" - Stuttard & Pinto
- "OWASP Testing Guide v4"
- "Bug Bounty Bootcamp" - Vickie Li

### Chaînes YouTube
- LiveOverflow
- STÖK
- InsiderPhD
- IppSec
- John Hammond

### Communautés
- Discord : HackTheBox, TryHackMe
- Reddit : r/netsec, r/websecurity
- Twitter : #infosec, #bugbounty

---

**Bon courage pour les challenges! 🚀**

**N'oubliez pas** : L'objectif est d'apprendre et de comprendre, pas juste de récupérer les flags.
