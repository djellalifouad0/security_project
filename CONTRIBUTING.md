# Guide de Contribution et Personnalisation

Ce document explique comment personnaliser et améliorer le projet pour obtenir une meilleure note.

## 🎯 Idées de Personnalisation

### Niveau Facile ⭐

#### 1. Ajouter une Vulnérabilité XSS (Cross-Site Scripting)

Ajouter un endpoint qui affiche du contenu utilisateur sans échappement :

```python
@app.route('/comment', methods=['POST'])
def add_comment():
    comment = request.form.get('comment', '')
    # VULNERABLE: Pas d'échappement HTML
    return f"<html><body><h1>Votre commentaire:</h1><p>{comment}</p></body></html>"
```

Test d'exploitation :
```html
<script>alert('XSS!')</script>
```

#### 2. Améliorer les Tests

Ajouter plus de tests pour augmenter la couverture :

```python
def test_xss_vulnerability(client):
    """Test de vulnérabilité XSS"""
    payload = "<script>alert('XSS')</script>"
    response = client.post('/comment', data={'comment': payload})
    assert payload in response.text  # Vulnérabilité confirmée
```

#### 3. Ajouter des Badges au README

Ajouter des badges pour montrer le statut du build :

```markdown
![Build Status](https://github.com/USERNAME/REPO/workflows/CI%2FCD%20Pipeline/badge.svg)
![Coverage](https://img.shields.io/badge/coverage-85%25-green)
![Python](https://img.shields.io/badge/python-3.9%20%7C%203.10%20%7C%203.11%20%7C%203.12-blue)
```

### Niveau Intermédiaire ⭐⭐

#### 4. Ajouter une Vulnérabilité CSRF

```python
@app.route('/delete_account', methods=['POST'])
def delete_account():
    # VULNERABLE: Pas de protection CSRF
    user_id = request.form.get('user_id')
    # Supprimer le compte...
    return "Compte supprimé"
```

#### 5. Implémenter un Scan OWASP ZAP dans le Pipeline

Ajouter un job dans `.github/workflows/ci-cd.yml` :

```yaml
  zap-scan:
    name: OWASP ZAP Security Scan
    runs-on: ubuntu-latest
    steps:
      - name: ZAP Scan
        uses: zaproxy/action-baseline@v0.7.0
        with:
          target: 'http://localhost:5000'
```

#### 6. Ajouter des Variables d'Environnement

Créer un fichier `.env.example` :

```bash
SECRET_KEY=your-secret-key-here
DATABASE_URL=sqlite:///library.db
FLASK_DEBUG=False
```

Modifier `app.py` pour utiliser :

```python
from dotenv import load_dotenv
load_dotenv()

app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-key')
```

### Niveau Avancé ⭐⭐⭐

#### 7. Implémenter des Corrections Progressives

Créer plusieurs branches avec différents niveaux de sécurité :

```bash
git checkout -b feature/fix-sql-injection
# Corriger uniquement SQLi
git commit -m "Fix: Correct SQL injection vulnerabilities"

git checkout -b feature/fix-path-traversal
# Corriger uniquement Path Traversal
git commit -m "Fix: Correct path traversal vulnerability"

git checkout -b feature/all-fixes
# Corriger toutes les vulnérabilités
```

#### 8. Ajouter une Analyse de Sécurité Continue

Intégrer Bandit et Safety dans le pipeline :

```yaml
  security-analysis:
    name: Advanced Security Analysis
    runs-on: ubuntu-latest
    steps:
      - name: Run Bandit
        run: |
          pip install bandit
          bandit -r . -f json -o bandit-report.json

      - name: Run Safety
        run: |
          pip install safety
          safety check --json
```

#### 9. Créer une Interface de Démonstration

Ajouter une page web qui montre les vulnérabilités :

```python
@app.route('/demo')
def demo_page():
    return render_template('demo.html')
```

Avec `templates/demo.html` qui explique et démontre chaque vulnérabilité.

#### 10. Implémenter un Système de Logging Avancé

```python
import logging
from logging.handlers import RotatingFileHandler

# Configuration des logs de sécurité
security_logger = logging.getLogger('security')
handler = RotatingFileHandler('security.log', maxBytes=10000, backupCount=3)
handler.setLevel(logging.WARNING)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
security_logger.addHandler(handler)

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    # Log des tentatives de connexion suspectes
    if "'" in username or "--" in username:
        security_logger.warning(f"Suspicious login attempt from {request.remote_addr}: {username}")
```

## 📊 Améliorer la Documentation

### 1. Ajouter des Diagrammes

Utiliser Mermaid pour créer des diagrammes :

```markdown
## Architecture de Sécurité

\`\`\`mermaid
graph TD
    A[Utilisateur] -->|Requête| B[Application Flask]
    B -->|Query| C[SQLite DB]
    B -->|Logs| D[Security Logger]
    E[GitHub Actions] -->|Scan| B
    E -->|Build| F[Docker Image]
    G[Trivy] -->|Scan| F
\`\`\`
```

### 2. Documenter les Corrections

Créer un fichier `FIXES.md` :

```markdown
# Documentation des Corrections de Sécurité

## SQL Injection

### Avant
\`\`\`python
query = f"SELECT * FROM users WHERE username='{username}'"
\`\`\`

### Après
\`\`\`python
cursor.execute("SELECT * FROM users WHERE username=?", (username,))
\`\`\`

### Explication
L'utilisation de requêtes paramétrées...
```

### 3. Ajouter des Captures d'Écran

Créer un dossier `screenshots/` avec :
- Résultats de Trivy
- Logs GitHub Actions
- Tests d'exploitation réussis
- Comparaison avant/après corrections

## 🧪 Tests Avancés

### Test de Performance

```python
def test_performance_under_load():
    """Test de performance avec plusieurs requêtes"""
    import time
    start = time.time()

    for _ in range(100):
        client.get('/')

    duration = time.time() - start
    assert duration < 5.0, "Application trop lente"
```

### Test de Sécurité Automatisé

```python
def test_sql_injection_patterns():
    """Test de différents patterns d'injection SQL"""
    payloads = [
        "admin' OR '1'='1",
        "admin'--",
        "' UNION SELECT NULL--",
        "admin' AND 1=1--"
    ]

    for payload in payloads:
        response = client.post('/login', data={
            'username': payload,
            'password': 'test'
        })
        # Vérifier que l'injection est détectée ou bloquée
```

## 🎨 Améliorations Visuelles

### 1. Améliorer l'Interface Web

Utiliser Bootstrap pour rendre l'application plus professionnelle :

```html
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
```

### 2. Ajouter des Graphiques de Sécurité

Créer une page de dashboard avec Chart.js montrant :
- Nombre de vulnérabilités détectées
- Évolution de la couverture de tests
- Historique des scans Trivy

## 📝 Checklist de Personnalisation

- [ ] Ajouter au moins une nouvelle vulnérabilité (XSS, CSRF, etc.)
- [ ] Créer des tests pour la nouvelle vulnérabilité
- [ ] Documenter la vulnérabilité dans SECURITY.md
- [ ] Créer la version corrigée dans app_secure.py
- [ ] Ajouter des diagrammes dans le README
- [ ] Créer des captures d'écran des résultats
- [ ] Ajouter des badges au README
- [ ] Améliorer le pipeline CI/CD
- [ ] Documenter toutes les modifications
- [ ] Tester l'ensemble du workflow

## 💡 Conseils pour la Présentation

1. **Démonstration Live** : Préparez une démo montrant les vulnérabilités
2. **Comparaison** : Montrez la différence entre app.py et app_secure.py
3. **Métriques** : Présentez les résultats de Trivy et la couverture de tests
4. **Apprentissage** : Expliquez ce que vous avez appris sur chaque vulnérabilité
5. **Amélioration Continue** : Proposez des améliorations futures

## 🏆 Critères de Notation Attendus

| Critère | Points | Comment maximiser |
|---------|--------|-------------------|
| Application fonctionnelle | 20% | Tests passants, démo réussie |
| Vulnérabilités implémentées | 25% | Au moins 3-4 vulnérabilités OWASP |
| Pipeline CI/CD | 25% | Tests multi-versions, Trivy, Docker |
| Documentation | 15% | README complet, diagrammes, captures |
| Corrections de sécurité | 15% | app_secure.py avec explications |

## 📚 Ressources Supplémentaires

- [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [GitHub Actions Best Practices](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions)
- [Docker Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html)
- [Python Security Best Practices](https://python.readthedocs.io/en/stable/library/security_warnings.html)

## ❓ Questions Fréquentes

**Q: Combien de vulnérabilités dois-je ajouter ?**
R: Le projet contient déjà 3 vulnérabilités majeures. Ajoutez-en 1-2 de plus pour vous démarquer (XSS, CSRF recommandés).

**Q: Dois-je vraiment créer deux versions (vulnérable et sécurisée) ?**
R: Oui, cela montre que vous comprenez les vulnérabilités ET comment les corriger.

**Q: Le pipeline doit-il passer sans erreurs ?**
R: Le pipeline doit s'exécuter avec succès. Trivy va détecter des vulnérabilités (c'est normal), mais les tests doivent passer.

**Q: Puis-je utiliser un autre framework que Flask ?**
R: Oui, mais Flask est simple et bien documenté pour ce type de projet.

---

N'hésitez pas à être créatif et à ajouter vos propres idées! 🚀
