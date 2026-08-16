# AGENTS.md — le serveur MCP de Yogfile

Sacha écrit en français ; **réponds en français**.

## Où est le contexte

Ce repo ne contient que le serveur MCP. **Le brief du produit vit dans
l'autre repo** : `~/Documents/yogfile/AGENTS.md` (privé,
`sifrah/yogfile`) — architecture, décisions produit, exploitation. Le
lire d'abord si la tâche touche au sens de ce qu'on expose, et pas
seulement à sa plomberie.

Le minimum à savoir : **Yogfile est un drive pour agents IA,
model-agnostic.** Ce qu'un agent y écrit reste et se relit à la session
suivante, avec un autre modèle si besoin. Le partage en découle, ce
n'est pas la raison d'être. Rien ici ne doit se mettre à parler comme
si le produit appartenait à un assistant en particulier.

## Ce repo est PUBLIC

`sifrah/yogfile-mcp` est public, et le repo produit ne peut pas le
devenir (des secrets de prod dorment dans l'historique de sa branche
`legacy`). Donc : **aucune adresse d'infrastructure, aucun nom de
serveur, aucune clé, aucun extrait de la base ici.** Les URL publiques
(`api.yogfile.com`, `mcp.yogfile.com`, `yogfile.com`) sont les seules
qui aient leur place.

## La forme du code

Une seule lib, deux transports :

| Fichier | Rôle |
|---|---|
| `src/lib.rs` | les outils, leurs descriptions, le client API. **Tout le sens est là.** |
| `src/main.rs` | le binaire local `yogfile-mcp` (stdio), pour les fichiers sur disque |
| `src/bin/remote.rs` | le connecteur `mcp.yogfile.com` : Streamable HTTP + OAuth 2.0 (DCR/PKCE), sans état, page `/authorize` |

Le connecteur est **sans état** : codes, refresh tokens et client_id
sont des blobs ChaCha20 chiffrés par `YOGFILE_MCP_SECRET`, et l'access
token est le JWT de session de l'API. Il n'y a pas de base ici.

Sept outils : `create_account` (binaire local seulement),
`create_drive`, `create_folder`, `upload_file`, `share_link`,
`list_files`, `delete_file`.

## Les descriptions d'outils sont du produit, pas du commentaire

C'est le seul texte que le modèle lit avant de décider. Deux règles
qui viennent des décisions produit et qu'une réécriture ne doit pas
reperdre :

1. **Ne jamais promettre d'expiration.** Un fichier reste jusqu'à ce
   qu'on le supprime. Le TTL (`ttl_secs`, `default_ttl_secs`) est une
   **politique de cycle de vie** qu'on demande, jamais un défaut.
   `expires_at` arrive à `null` dans le cas normal : le lire avec un
   `unwrap_or(0)` le transforme en une date de 1970, et le modèle
   annonce « already past » sur un fichier vivant. C'est arrivé ; d'où
   `lifetime_phrase()` et son test.
2. **Dire que ça dure.** `upload_file` sert autant à garder du travail
   qu'à donner un fichier ; `list_files` sert à relire ce qu'une
   exécution précédente a laissé. Si les descriptions ne le disent
   pas, le modèle traite Yogfile comme un tube d'envoi.

## Compatibilité qu'on ne retire pas

Les drives s'appelaient des « boxes ». Le renommage est total, mais un
serveur MCP local est **un binaire posé sur la machine de quelqu'un** :
rien n'oblige son propriétaire à le remplacer. Restent donc acceptés,
sans être annoncés dans `tools/list` :

- le nom d'outil `create_box` (dispatcher de `call_tool`) ;
- l'argument `box` (`drive_arg()`, qui lit `drive` puis `box`).

Côté API, les routes `/v2/boxes/*` et le header `x-box-passphrase`
répondent toujours pour la même raison.

## Déploiement

| Cible | Déclencheur | Job |
|---|---|---|
| Connecteur `mcp.yogfile.com` | push sur `main` | `deploy-remote` |
| Binaire local, releases | tag `v*` | `release.yml` |

`deploy-remote` compile `--features remote --bin yogfile-mcp-remote`,
envoie le binaire par SSH sur la VM qui héberge aussi l'API, installe
et redémarre l'unit via un sudo restreint, puis vérifie
`/.well-known/oauth-authorization-server`. Secrets : `DEPLOY_SSH_KEY`,
`DEPLOY_HOST`, `DEPLOY_KNOWN_HOSTS`.

**L'ordre compte quand un changement touche les deux repos** :
déployer l'API (repo produit, push sur `v2`) AVANT le connecteur,
sinon celui-ci appelle une API qui n'a pas encore la route.

Les releases du binaire local sont attestées
(`gh attestation verify <tarball> --repo sifrah/yogfile-mcp`) et
installées par `curl -sSfL https://yogfile.com/install.sh | sh` — le
script est servi par le front, il vit dans l'autre repo
(`front/public/install.sh`).

## Tester pour de vrai

`cargo test` couvre le protocole hors réseau. Ce qu'il ne couvre pas,
et qu'il faut faire avant de pousser un changement d'outil, c'est
parler le protocole au binaire contre l'API de production :

```bash
export YOGFILE_MCP_STATE=/tmp/mcp-test.json      # jamais l'état réel
printf '%s\n' \
 '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}' \
 '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' \
 | ./target/release/yogfile-mcp
```

Un compte anonyme est créé au premier appel : **supprimer les drives
de test ensuite** (`DELETE /v2/drives/{name}` avec une session ouverte
sur le numéro écrit dans le fichier d'état).

## Règles de travail

- **Jamais de commit attribué à un agent** : auteur = `Sacha IFRAH
  <sacha@syfrah.com>`.
- Jamais de `git push --force`. Jamais de `gh pr create` ni de
  `gh issue create`.
- Branche → push → CI verte → merge dans `main` (ce qui **déploie le
  connecteur**, donc le demander avant).
- Code et commentaires en français, descriptions d'outils en anglais.
