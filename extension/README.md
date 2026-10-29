# directus-extension-pii-protect (d9 PII Protect)

Hook d9 / Directus d'**anonymisation gouvernée des PII pour les agents IA**.

Pour un utilisateur de rôle *agent*, tout ce qui lui est accessible est protégé **secure-by-default** :
les champs texte libre sont **détectés (moteur FR) et chiffrés de façon réversible** à la lecture
(et **rehydratés à l'écriture**), les documents texte sont anonymisés et les images caviardées à la
volée. Un humain autorisé voit l'original. d9 gère le RBAC ; cette extension gère le contenu PII que
le RBAC au champ ne voit pas. L'anonymisation est déléguée au **moteur sidecar** (voir le repo racine).

## Installation

1. Déposer ce dossier dans `extensions/` de l'instance d9 (hook **non-sandboxé** — accès à l'`accountability`).
2. Lancer le **moteur sidecar** et pointer l'extension dessus via `PII_PROTECT_ENGINE_URL`.
3. Marquer un rôle comme agent : ajouter/activer le booléen **`is_agent`** sur `directus_roles`
   (c'est le seul ajout UI — un toggle sur la définition du rôle).

## Configuration (variables d'environnement)

| Variable | Rôle | Défaut |
|---|---|---|
| `PII_PROTECT_ENGINE_URL` | URL du moteur sidecar (dans le réseau de l'environnement). | `http://host.docker.internal:8077` |
| `PII_PROTECT_FIELDS` | JSON `{collection:[champs]}` pour restreindre. Vide/`*` = **tous les champs `text`**. | *(vide)* |

Le choix de **quels types de PII** chiffrer (`PII_PROTECT_ENTITIES` / `PII_PROTECT_SKIP`) se fait
**côté moteur**. Aucune config en dur, aucun couplage d'environnement.

**Pas de logs custom** : l'activity log natif de d9 trace déjà les accès.

## Développement

```bash
npm install
npm run build      # directus-extension build → dist/index.js
npm run dev        # watch
```

Source : `src/index.ts`. Sortie : `dist/index.js`.

## Licence

MIT © La Webcapsule
