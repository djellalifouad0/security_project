# Guide de Démarrage Rapide

Ce guide vous permet de démarrer rapidement avec le projet.

## 🚀 Démarrage en 5 minutes

### Option 1 : Exécution locale (Recommandé pour les tests)

```bash
# 1. Installer les dépendances
pip install -r requirements.txt

# 2. Lancer l'application vulnérable
python app.py

# 3. Ouvrir votre navigateur
# Aller sur http://localhost:5000
```

### Option 2 : Avec Docker

```bash
# 1. Build de l'image
docker build -t bibliotheque-app .

# 2. Lancement du conteneur
docker run -p 5000:5000 bibliotheque-app

# 3. Ouvrir http://localhost:5000
```

### Option 3 : Avec Docker Compose (Les deux versions)

```bash
# Lancer les deux versions (vulnérable et sécurisée)
docker-compose up -d

# Vulnérable: http://localhost:5000
# Sécurisée: http://localhost:5001
```

## 🧪 Tester les Vulnérabilités

### 1. Test manuel - SQL Injection

1. Aller sur http://localhost:5000
2. Dans le formulaire de connexion, entrer:
   - **Username**: `admin' OR '1'='1--`
   - **Password**: `anything`
3. Cliquer sur "Se connecter"
4. Vous êtes connecté sans connaître le mot de passe!

### 2. Test manuel - Path Traversal

1. Dans le formulaire de téléchargement, entrer: `../app.py`
2. Cliquer sur "Télécharger"
3. Le code source de l'application est accessible!

### 3. Test automatisé

```bash
# Installer la dépendance
pip install colorama

# Lancer le script d'exploitation
python exploit_demo.py
```

## 📊 Exécuter les Tests Unitaires

```bash
# Tests simples
pytest test_app.py -v

# Tests avec rapport de couverture
pytest test_app.py -v --cov=app --cov-report=html

# Ouvrir le rapport HTML
# Linux/Mac: open htmlcov/index.html
# Windows: start htmlcov/index.html
```

## 🔒 Comparer avec la Version Sécurisée

```bash
# Lancer la version sécurisée
python app_secure.py

# Essayer les mêmes exploits - ils ne fonctionneront pas!
```

## 🐳 Utiliser avec GitHub Actions

### 1. Créer un Repository GitHub

```bash
# Initialiser Git
git init
git add .
git commit -m "Initial commit - Projet CI/CD Sécurité"

# Ajouter le remote (remplacer par votre URL)
git remote add origin https://github.com/VOTRE_USERNAME/ProjetSecu.git
git push -u origin main
```

### 2. Configurer les Secrets Docker Hub

1. Aller sur **Settings** > **Secrets and variables** > **Actions**
2. Ajouter les secrets:
   - `DOCKER_USERNAME`: Votre nom d'utilisateur Docker Hub
   - `DOCKER_PASSWORD`: Votre token Docker Hub

### 3. Déclencher le Pipeline

```bash
# Le pipeline se lance automatiquement sur chaque push
git add .
git commit -m "Test du pipeline CI/CD"
git push
```

### 4. Voir les Résultats

1. Aller dans l'onglet **Actions** de votre repo
2. Cliquer sur le workflow en cours
3. Observer les 5 jobs:
   - Tests multi-Python (3.9, 3.10, 3.11, 3.12)
   - Scan Trivy du code
   - Build et scan de l'image Docker
   - Push vers Docker Hub (sur main seulement)
   - Rapport final

## 📈 Analyser les Résultats Trivy

### Scan local avec Trivy

```bash
# Installer Trivy (Linux)
wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -
echo "deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | sudo tee -a /etc/apt/sources.list.d/trivy.list
sudo apt-get update
sudo apt-get install trivy

# Installer Trivy (Mac)
brew install aquasecurity/trivy/trivy

# Scanner le code
trivy fs .

# Scanner l'image Docker
trivy image bibliotheque-app:latest
```

### Interpréter les Résultats

Trivy va détecter:
- **CRITICAL/HIGH**: Vulnérabilités dans Flask/Werkzeug
- **MEDIUM**: Problèmes de configuration (debug mode, etc.)
- **LOW**: Avertissements divers

## 📝 Credentials de Test

L'application contient des utilisateurs de test:

| Username | Password | Rôle |
|----------|----------|------|
| admin | admin123 | admin |
| user | user123 | user |

## 🎯 Checklist du Projet

- [ ] Application vulnérable fonctionne
- [ ] Tests unitaires passent (>80% coverage)
- [ ] Docker build réussi
- [ ] Pipeline GitHub Actions configuré
- [ ] Secrets Docker Hub ajoutés
- [ ] Scan Trivy exécuté
- [ ] Vulnérabilités testées manuellement
- [ ] Version sécurisée comparée
- [ ] Documentation lue et comprise

## 🛠️ Commandes Utiles (Makefile)

```bash
make help          # Voir toutes les commandes
make install       # Installer dépendances
make test          # Lancer tests
make run           # App vulnérable
make run-secure    # App sécurisée
make docker-build  # Build Docker
make docker-scan   # Scanner avec Trivy
make exploit       # Démo exploitation
make clean         # Nettoyer
```

## ⚠️ Problèmes Courants

### L'application ne démarre pas

```bash
# Vérifier que Python est installé
python --version

# Vérifier que les dépendances sont installées
pip list | grep Flask

# Réinstaller les dépendances
pip install -r requirements.txt --force-reinstall
```

### Les tests échouent

```bash
# Nettoyer les fichiers de cache
make clean

# Réexécuter les tests
pytest test_app.py -v
```

### Docker build échoue

```bash
# Vérifier que Docker est en cours d'exécution
docker ps

# Nettoyer les images
docker system prune -a

# Rebuild
docker build -t bibliotheque-app . --no-cache
```

### Le pipeline GitHub Actions ne se lance pas

1. Vérifier que le fichier est dans `.github/workflows/ci-cd.yml`
2. Vérifier que vous avez push sur la branche `main` ou `develop`
3. Vérifier les logs dans l'onglet Actions

## 📚 Prochaines Étapes

1. **Comprendre les vulnérabilités** : Lire [SECURITY.md](SECURITY.md)
2. **Analyser le code** : Comparer [app.py](app.py) et [app_secure.py](app_secure.py)
3. **Étudier le pipeline** : Lire [.github/workflows/ci-cd.yml](.github/workflows/ci-cd.yml)
4. **Personnaliser** : Ajouter vos propres vulnérabilités ou fonctionnalités
5. **Améliorer** : Implémenter XSS, CSRF, ou d'autres vulnérabilités OWASP

## 🎓 Ressources d'Apprentissage

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [GitHub Actions Docs](https://docs.github.com/actions)
- [Trivy Documentation](https://aquasecurity.github.io/trivy/)
- [Flask Security](https://flask.palletsprojects.com/security/)
- [Docker Security Best Practices](https://docs.docker.com/develop/security-best-practices/)

## 💡 Astuces pour le Projet

1. **Pour la notation** : Documentez vos tests et analyses Trivy avec des captures d'écran
2. **Personnalisation** : Ajoutez vos propres vulnérabilités (XSS, CSRF, etc.)
3. **Bonus** : Créez une branche avec les corrections de sécurité
4. **Documentation** : Expliquez comment vous avez corrigé chaque vulnérabilité

Bon courage! 🚀
