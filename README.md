# d9 PII Protect — anonymisation gouvernée des PII pour agents IA (dans d9)

> POC « brique manquante ». *Écluse* = nom de code interne du moteur d'anonymisation.

**L'idée :** d9 gère le RBAC (qui accède à quoi). Écluse gère le **contenu PII** des champs
texte libre — ce que le RBAC au champ ne peut pas voir (un NIR tapé dans un `note`).
Pour un user de **rôle agent**, les PII sont **détectées (moteur FR) et chiffrées in-place
(AES-256-GCM réversible)** à la lecture ; **rehydratées à l'écriture**. Un humain voit le clair.

```
Agent IA ──GET /items/tickets──▶  d9 (RBAC) ──hook items.read──▶ Écluse engine ──▶ Presidio/Anonym-IA (FR)
   ◀── note chiffrée in-place ───                                   └── AES-GCM encrypt/decrypt
Humain  ──GET /items/tickets──▶  d9 ──▶ note en clair
```

## Démo live (1 commande)

```bash
bash demo.sh
```
Montre côte à côte : humain = PII en clair, agent = PII chiffrées. Même base, même endpoint.

## Ce qui tourne

| Brique | Où | Détail |
|---|---|---|
| **d9 dédié** | http://localhost:8060 | image `d9-main:latest`, SQLite, admin `admin@ecluse.io` / `ecluse-admin` |
| **Plugin Écluse** | `d9/extensions/directus-extension-ecluse/` | hook `items.read` (anonymise) + `items.create/update` (rehydrate) |
| **Engine Écluse** | http://localhost:8077 | `/anonymize` `/rehydrate` — détection FR + AES-256-GCM in-place |
| **Moteur FR** | Presidio/Anonym-IA :5005 + :5001 | CamemBERT/Anonym-IA (FR_NIR…) + customs SIREN/SIRET/date FR |

- Rôle agent : `agent@ecluse.io` / `agent-pwd`. Champ anonymisé : `tickets.note` (configurable dans `d9/extensions/ecluse.config.json`).
- **Fail-closed** : si l'engine est indispo, le champ est masqué (`[protégé — Écluse indisponible]`), jamais laissé en clair.

## Démarrer / arrêter / dépanner

```bash
# d9
cd d9 && docker compose up -d        # démarrer
docker compose logs -f d9            # logs (chercher "[ecluse] hook chargé")
docker compose down                  # arrêter

# engine (host, port 8077)
curl -s localhost:8077/health
# relancer si besoin :
pkill -f ecluse_engine.py
nohup <venv>/bin/python engine/ecluse_engine.py > engine/engine.log 2>&1 &
```

## Limites du POC (à dire en transparence)

- Clé de chiffrement = clé démo en dur. **En prod : custody gouvernée (KMS/HSM), rotation, accès RBAC + audit.**
- Anonymise les champs texte libre configurés ; un vrai déploiement couvre tous les champs + le JSON imbriqué.
- Le label d'entité peut diverger (Anonym-IA tague parfois un SIREN en `FR_NIR`) — **la valeur est chiffrée dans tous les cas** (ce qui compte pour la fuite).
- Détection FR mesurée par ailleurs : **46/46** vs hoop/Alcatraz 16/46, hoop/Presidio-EN ~0 sur les IDs FR.
