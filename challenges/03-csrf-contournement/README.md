# Challenge 3 : CSRF - Contournement de Jeton

## Informations

**Plateforme** : Root-Me
**URL** : https://www.root-me.org/fr/Challenges/Web-Client/CSRF-contournement-de-jeton
**Categorie** : CSRF (Cross-Site Request Forgery)
**Difficulte** : Intermediaire

## Objectif

Contourner la protection CSRF par jeton pour executer une action non autorisee.

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
POST /action HTTP/1.1
Host: challenge01.root-me.org
Content-Type: application/x-www-form-urlencoded


```

## Explication

[Expliquer comment contourner le jeton CSRF]

## Screenshots

- initial_request.png : Requete initiale avec jeton
- exploit.png : Exploitation du contournement
- flag.png : Flag obtenu

## Code vulnerable

```php
[Code exemple]
```

## Correction recommandee

```php
[Code securise]
```

## Mesures de securisation

1. Lier le jeton CSRF a la session utilisateur
2. Valider le jeton cote serveur pour chaque requete sensible
3. Utiliser SameSite cookies
4. Verifier l'origine de la requete

## References

- OWASP CSRF: https://owasp.org/www-community/attacks/csrf
- OWASP CSRF Prevention: https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html

## Notes

[Notes personnelles]

---

Date : [DATE]
Statut : [ ] Resolu
