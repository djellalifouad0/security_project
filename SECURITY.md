# Politique de Sécurité

## Avertissement

Cette application a été développée à des fins éducatives et contient **intentionnellement** des vulnérabilités de sécurité. Elle ne doit **JAMAIS** être déployée en production ou sur un réseau accessible publiquement.

## Vulnérabilités Connues

### 1. Injection SQL (CWE-89)

**Sévérité** : CRITIQUE

**Localisation** :
- [app.py:87](app.py#L87) - Fonction `login()`
- [app.py:143](app.py#L143) - Fonction `search()`

**Description** :
Les entrées utilisateur sont directement intégrées dans les requêtes SQL via des f-strings, permettant à un attaquant d'exécuter du code SQL arbitraire.

**Preuve de Concept** :
```python
# Bypass d'authentification
username = "admin' OR '1'='1' --"
password = "anything"

# Résultat de la requête générée :
# SELECT * FROM users WHERE username='admin' OR '1'='1' --' AND password='anything'
# La partie après -- est commentée, la condition '1'='1' est toujours vraie
```

**Exploitation Avancée** :
```sql
# Extraction de la structure de la base
' UNION SELECT sql, type, name FROM sqlite_master--

# Dump des utilisateurs
' UNION SELECT username, password, role FROM users--
```

**Correction** :
```python
# Utiliser des requêtes paramétrées
cursor.execute("SELECT * FROM users WHERE username=? AND password=?", (username, password))
```

### 2. Path Traversal (CWE-22)

**Sévérité** : HAUTE

**Localisation** :
- [app.py:117](app.py#L117) - Fonction `download()`

**Description** :
Aucune validation du chemin de fichier n'est effectuée, permettant l'accès à des fichiers en dehors du répertoire prévu.

**Preuve de Concept** :
```bash
# Accès au code source
curl "http://localhost:5000/download?file=../app.py"

# Accès aux fichiers système (Linux)
curl "http://localhost:5000/download?file=../../../etc/passwd"

# Accès aux fichiers système (Windows)
curl "http://localhost:5000/download?file=..\..\..\..\Windows\System32\drivers\etc\hosts"
```

**Correction** :
```python
from werkzeug.utils import secure_filename
import os

@app.route('/download')
def download():
    filename = secure_filename(request.args.get('file', ''))
    base_dir = os.path.abspath('files')
    file_path = os.path.abspath(os.path.join(base_dir, filename))

    # Vérifier que le chemin résolu est dans le dossier autorisé
    if not file_path.startswith(base_dir):
        abort(403)

    return send_file(file_path)
```

### 3. Exposition d'Informations Sensibles (CWE-209)

**Sévérité** : MOYENNE

**Localisation** :
- [app.py:98](app.py#L98) - Gestion des erreurs SQL
- [app.py:156](app.py#L156) - Gestion des erreurs de recherche

**Description** :
Les messages d'erreur SQL complets sont affichés à l'utilisateur, révélant la structure de la base de données.

**Impact** :
- Révélation de la structure des tables
- Aide à l'exploitation d'autres vulnérabilités
- Fingerprinting de la base de données

**Correction** :
```python
try:
    cursor.execute(query)
except Exception as e:
    # Logger l'erreur pour l'admin
    app.logger.error(f"Database error: {str(e)}")
    # Message générique pour l'utilisateur
    return "Une erreur est survenue", 500
```

### 4. Stockage de Mots de Passe en Clair (CWE-256)

**Sévérité** : CRITIQUE

**Localisation** :
- [app.py:47-48](app.py#L47) - Initialisation de la base de données

**Description** :
Les mots de passe sont stockés en clair dans la base de données.

**Correction** :
```python
from werkzeug.security import generate_password_hash, check_password_hash

# Lors de la création
hashed = generate_password_hash('admin123')
cursor.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
               ('admin', hashed, 'admin'))

# Lors de la vérification
if user and check_password_hash(user[2], password):
    # Authentification réussie
```

### 5. Mode Debug Activé en Production (CWE-489)

**Sévérité** : HAUTE

**Localisation** :
- [app.py:175](app.py#L175) - Configuration Flask

**Description** :
`debug=True` expose des informations sensibles et permet l'exécution de code.

**Correction** :
```python
if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)
```

### 6. Absence de CSRF Protection (CWE-352)

**Sévérité** : MOYENNE

**Description** :
Aucune protection CSRF n'est implémentée sur les formulaires.

**Correction** :
```python
from flask_wtf.csrf import CSRFProtect

csrf = CSRFProtect(app)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'votre-clé-secrète')
```

### 7. Absence de Rate Limiting (CWE-770)

**Sévérité** : MOYENNE

**Description** :
Pas de limitation des requêtes, permettant des attaques par force brute.

**Correction** :
```python
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

@app.route('/login', methods=['POST'])
@limiter.limit("5 per minute")
def login():
    # ...
```

## Résultats Trivy Attendus

L'analyse Trivy devrait détecter :

### Vulnérabilités de Dépendances
- Flask : Versions anciennes avec CVE connues
- Werkzeug : Vulnérabilités potentielles

### Problèmes de Configuration
- Absence de certificat SSL
- Mode debug activé
- Credentials en dur

### Recommandations
- Mettre à jour toutes les dépendances
- Utiliser des variables d'environnement
- Implémenter HTTPS
- Ajouter une authentification forte

## Matrice des Risques

| Vulnérabilité | Sévérité | Facilité d'Exploitation | Impact | Priorité |
|---------------|----------|------------------------|---------|----------|
| SQL Injection | Critique | Facile | Élevé | P0 |
| Path Traversal | Haute | Facile | Moyen | P1 |
| Mots de passe en clair | Critique | Facile | Élevé | P0 |
| Debug Mode | Haute | Facile | Moyen | P1 |
| Exposition d'infos | Moyenne | Facile | Faible | P2 |
| Absence CSRF | Moyenne | Moyenne | Moyen | P2 |
| Absence Rate Limiting | Moyenne | Facile | Faible | P3 |

## Plan de Remédiation

### Phase 1 : Critique (À faire immédiatement)
1. Corriger les injections SQL
2. Implémenter le hashage de mots de passe
3. Désactiver le mode debug

### Phase 2 : Haute (À faire sous 1 semaine)
1. Corriger le path traversal
2. Mettre en place une gestion d'erreurs appropriée
3. Mettre à jour les dépendances

### Phase 3 : Moyenne (À faire sous 1 mois)
1. Ajouter la protection CSRF
2. Implémenter le rate limiting
3. Ajouter HTTPS
4. Mettre en place des logs de sécurité

## Tests de Sécurité

Pour tester les vulnérabilités :

```bash
# Tester SQLi
python -c "import requests; r=requests.post('http://localhost:5000/login', data={'username': \"admin' OR '1'='1--\", 'password': 'x'}); print(r.text)"

# Tester Path Traversal
curl "http://localhost:5000/download?file=../app.py"

# Scanner avec OWASP ZAP
docker run -t owasp/zap2docker-stable zap-baseline.py -t http://localhost:5000
```

## Reporting de Vulnérabilités

Si vous découvrez des vulnérabilités non intentionnelles dans ce projet :

1. Ne pas les exploiter publiquement
2. Créer une issue GitHub avec le tag [SECURITY]
3. Décrire la vulnérabilité de manière responsable

## Références

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CWE Top 25](https://cwe.mitre.org/top25/)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [Flask Security](https://flask.palletsprojects.com/en/latest/security/)

---

**Dernière mise à jour** : 2025-12-01
