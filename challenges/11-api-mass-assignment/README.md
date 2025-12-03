# Challenge 11 : API Mass Assignment

## Informations

**Plateforme** : Root-Me
**URL** : https://www.root-me.org/fr/Challenges/Web-Serveur/API-Mass-Assignment
**Categorie** : API Security
**Difficulte** : Intermediaire

## Objectif

Exploiter une vulnerabilite de mass assignment pour modifier des attributs non autorises.

## Reconnaissance

[Decrire comment vous avez explore l'API]

## Methode d'exploitation

[Expliquer les etapes suivies]

## Payload utilise

```json
{
  "field1": "value1",
  "field2": "value2",
  "hidden_field": "malicious_value"
}
```

## Requete HTTP

```http
POST /api/endpoint HTTP/1.1
Host: challenge01.root-me.org
Content-Type: application/json

{
  [INSERER PAYLOAD JSON ICI]
}
```

## Explication

[Expliquer comment le mass assignment fonctionne]

## Champs testes

- [ ] id
- [ ] role
- [ ] is_admin
- [ ] permissions
- [ ] Autres:

## Screenshots

- initial_request.png : Requete initiale
- mass_assignment.png : Ajout de champs caches
- response.png : Reponse confirmant la modification
- flag.png : Flag obtenu

## Code vulnerable

```python
[Code exemple]
```

## Correction recommandee

```python
[Code securise avec whitelist]
```

## Mesures de securisation

1. Utiliser une whitelist de champs autorises
2. Implementer des DTOs (Data Transfer Objects)
3. Valider explicitement chaque champ
4. Utiliser des decorateurs pour marquer les champs modifiables
5. Separer les modeles de donnees et les requetes API

## References

- OWASP Mass Assignment: https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html
- OWASP API Security: https://owasp.org/www-project-api-security/
- CWE-915: https://cwe.mitre.org/data/definitions/915.html

## Notes

[Notes personnelles]

---

Date : [DATE]
Statut : [ ] Resolu
