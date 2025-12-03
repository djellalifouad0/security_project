# Challenge 10 : SSTI - Unknown Language

## Informations

**Plateforme** : PortSwigger Web Security Academy
**URL** : https://portswigger.net/web-security/server-side-template-injection/exploiting/lab-server-side-template-injection-in-an-unknown-language-with-a-documented-exploit
**Categorie** : SSTI (Server-Side Template Injection)
**Difficulte** : Avance

## Objectif

Identifier le moteur de template et exploiter une SSTI pour executer du code.

## Reconnaissance

[Decrire comment vous avez explore l'application]

## Identification du moteur de template

Tests effectues:
```
{{7*7}} = ?
${7*7} = ?
<%= 7*7 %> = ?
${{7*7}} = ?
#{7*7} = ?
```

Moteur identifie: [NOM]

## Methode d'exploitation

[Expliquer les etapes suivies]

## Payload utilise

```
[INSERER PAYLOAD SSTI ICI]
```

## Requete HTTP

```http
GET /chemin?param=payload HTTP/1.1
Host: lab.web-security-academy.net


```

## Explication

[Expliquer comment le payload fonctionne]

## Screenshots

- template_detection.png : Detection du moteur
- payload_test.png : Test du payload
- exploit.png : Exploitation reussie
- flag.png : Validation du challenge

## Code vulnerable

```python
[Code exemple]
```

## Correction recommandee

```python
[Code securise]
```

## Mesures de securisation

1. Ne jamais passer d'entrees utilisateur directement au moteur de template
2. Utiliser une sandbox pour les templates
3. Desactiver les fonctionnalites dangereuses du moteur
4. Valider et echapper les entrees
5. Utiliser des templates precompiles

## References

- PortSwigger SSTI: https://portswigger.net/web-security/server-side-template-injection
- HackTricks SSTI: https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection
- PayloadsAllTheThings SSTI: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection

## Notes

[Notes personnelles]

---

Date : [DATE]
Statut : [ ] Resolu
