# directus-extension-ecluse

Hook d9 / Directus d'**anonymisation gouvernée des PII pour les agents IA**.

Pour un utilisateur de rôle *agent*, les PII des champs texte libre sont **détectées (moteur FR) et chiffrées in-place de façon réversible** à la lecture, et **rehydratées à l'écriture**. Un humain voit le clair. d9 gère le RBAC ; cette extension gère le contenu PII que le RBAC au champ ne voit pas.

## Installation

Déposer le dossier dans `extensions/` de votre instance d9, et lancer le moteur d'anonymisation (voir le repo racine). Hook **non-sandboxé** (accès à l'`accountability`).

## Configuration

`extensions/ecluse.config.json` (relu à chaud) :

```json
{
  "engine": "http://host.docker.internal:8077",
  "agentRoleIds": ["<uuid-du-role-agent>"],
  "fields": { "tickets": ["note"] }
}
```

| Clé | Rôle |
|-----|------|
| `engine` | URL du moteur d'anonymisation (dans votre réseau) |
| `agentRoleIds` | Rôles traités comme « agents » → anonymisation activée |
| `fields` | Collections → champs texte libre à traiter |

## Développement

```bash
npm install
npm run build      # directus-extension build → dist/index.js
npm run dev        # watch
```

Source : `src/index.ts`. Sortie : `dist/index.js`.

## Licence

MIT © La Webcapsule
