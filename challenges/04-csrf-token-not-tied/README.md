# Challenge 4 : CSRF - Token Not Tied to User Session

## Informations

**Plateforme** : PortSwigger Web Security Academy
**URL** : https://portswigger.net/web-security/csrf/bypassing-token-validation/lab-token-not-tied-to-user-session
**Categorie** : CSRF
**Difficulte** : Intermediaire

## Objectif

Exploiter un jeton CSRF non lie a la session pour modifier l'email d'un utilisateur.

## Reconnaissance

[Decrire comment vous avez explore l'application]

## Methode d'exploitation

[Expliquer les etapes suivies]

## Payload/POC utilise

```html
[INSERER CODE HTML/JAVASCRIPT ICI]
```

## Requete HTTP

```http
POST /my-account/change-email HTTP/1.1
Host: lab.web-security-academy.net


```

## Explication

[Expliquer pourquoi le jeton peut etre reutilise]

## Screenshots

- valid_token.png : Recuperation d'un jeton valide
- exploit.png : Exploitation avec jeton reutilise
- flag.png : Validation du challenge

## Code vulnerable

```php
[Code exemple]
```

## Correction recommandee

```php
[Code securise]
```

## Mesures de securisation

1. Lier chaque jeton CSRF a la session utilisateur specifique
2. Generer un nouveau jeton pour chaque session
3. Valider que le jeton appartient bien a l'utilisateur faisant la requete
4. Expirer les jetons apres utilisation

## References

- PortSwigger CSRF: https://portswigger.net/web-security/csrf
- OWASP CSRF Token: https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html

## Notes

[Notes personnelles]

---

Date : [DATE]
Statut : [ ] Resolu
