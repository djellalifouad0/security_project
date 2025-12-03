# Challenge 5 : CSRF - Referer Validation Bypass

## Informations

**Plateforme** : PortSwigger Web Security Academy
**URL** : https://portswigger.net/web-security/csrf/bypassing-referer-based-defenses/lab-referer-validation-depends-on-header-being-present
**Categorie** : CSRF
**Difficulte** : Facile

## Objectif

Contourner la validation du header Referer pour executer une attaque CSRF.

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

[Expliquer comment contourner la validation du Referer]

## Screenshots

- with_referer.png : Requete avec Referer
- without_referer.png : Requete sans Referer
- exploit.png : Exploitation reussie
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

1. Ne pas se fier uniquement au header Referer
2. Utiliser des jetons CSRF anti-forgery
3. Implementer SameSite cookies
4. Verifier l'origine avec Origin header

## References

- PortSwigger CSRF Referer: https://portswigger.net/web-security/csrf/bypassing-referer-based-defenses
- OWASP CSRF Prevention: https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html

## Notes

[Notes personnelles]

---

Date : [DATE]
Statut : [ ] Resolu
