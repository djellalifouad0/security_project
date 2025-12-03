# Challenge 8 : Command Injection - Filter Bypass

## Informations

**Plateforme** : Root-Me
**URL** : https://www.root-me.org/fr/Challenges/Web-Serveur/Injection-de-commande-Contournement-de-filtre
**Categorie** : Command Injection
**Difficulte** : Intermediaire

## Objectif

Contourner les filtres de validation pour executer des commandes systeme.

## Reconnaissance

[Decrire comment vous avez explore l'application]

## Methode d'exploitation

[Expliquer les etapes suivies]

## Payload utilise

```bash
[INSERER PAYLOAD ICI]
```

## Requete HTTP

```http
GET /chemin?cmd=payload HTTP/1.1
Host: challenge01.root-me.org


```

## Explication

[Expliquer comment contourner les filtres]

## Techniques de bypass testees

- [ ] Separateurs: ; | & && ||
- [ ] Variables d'environnement: $IFS
- [ ] Encodage: Base64, Hex
- [ ] Wildcards: * ? []
- [ ] Autres:

## Screenshots

- initial_test.png : Test initial
- bypass.png : Contournement du filtre
- command_output.png : Sortie de la commande
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

1. Eviter d'executer des commandes systeme
2. Utiliser une liste blanche de commandes autorisees
3. Valider strictement les entrees
4. Utiliser escapeshellarg() et escapeshellcmd()
5. Limiter les privileges du processus web

## References

- OWASP Command Injection: https://owasp.org/www-community/attacks/Command_Injection
- HackTricks Command Injection: https://book.hacktricks.xyz/pentesting-web/command-injection
- PayloadsAllTheThings: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection

## Notes

[Notes personnelles]

---

Date : [DATE]
Statut : [ ] Resolu
