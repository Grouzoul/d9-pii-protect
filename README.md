# d9 PII Protect

**Anonymisation gouvernée des PII pour les agents IA, dans [d9](https://github.com/LaWebcapsule/d9) (fork Directus 9).**

Le RBAC décide *qui accède à quoi*. PII Protect couvre l'angle mort : le **contenu PII des champs
libres et des fichiers** — un NIR tapé dans une `note`, un nom dans un `.docx`, une pièce d'identité
scannée. Pour un utilisateur de **rôle « agent »**, les PII sont **détectées (moteur FR) puis
chiffrées de façon réversible** (texte/documents) ou **caviardées** (images) ; un **humain autorisé**
voit l'original. La ré-identification est décidée par le RBAC d9 + la custody de la clé.

> Mesuré sur un corpus FR : **détection 46/46** (identifiants FR NIR/SIREN/SIRET inclus), là où
> hoop.dev/Alcatraz fait 16/46 et hoop.dev/Presidio-EN ~0 sur les identifiants français.

## Architecture en deux briques

- **`engine/`** — un **sidecar Docker auto-suffisant** : [Presidio](https://microsoft.github.io/presidio/)
  (orchestration) + NER FR [Anonym-IA](https://huggingface.co/Anonym-IA/V2-camembert-ner-pii-french)
  + recognizers regex/checksum (SIREN, SIRET, IBAN, NIR…) + chiffrement **AES-256-GCM** maison + caviardage
  d'images (Tesseract OCR). **Un moteur par environnement** (confinement — pas de proxy central).
- **`extension/`** — l'**intégration 1-clic dans d9** : un hook par rôle + un seul ajout UI (le toggle
  `is_agent` sur la définition du rôle). Entièrement **piloté par variables d'environnement**.

Détail et schéma : **[ARCHITECTURE.md](ARCHITECTURE.md)**.

## Démarrage rapide

Prérequis : Docker, et l'image `d9-main:latest` disponible localement.

```bash
cd deploy
cp .env.example .env            # renseigner au minimum PII_PROTECT_KEY
docker compose up -d --build    # construit le moteur + lance d9
```

- d9 : http://localhost:8055 (admin défini dans `.env`)
- Mettre un rôle en mode agent : passer `is_agent = true` sur le rôle (champ booléen sur `directus_roles`).
  → **secure-by-default** : tous les champs `text` et tous les fichiers accessibles à ce rôle sont protégés.

### Voir la démo (optionnel)

```bash
python3 seed_ecluse.py          # collection tickets + rôle/user agent + toggle is_agent (depuis la racine)
bash demo.sh                    # texte / document / image / type refusé / round-trip, agent vs humain
```

Comptes de démo : `admin@ecluse.io` / `ecluse-admin` et `agent@ecluse.io` / `agent-pwd`.

## Configuration (variables d'environnement)

| Variable | Brique | Rôle | Défaut |
|---|---|---|---|
| `PII_PROTECT_KEY` | moteur | **Clé AES-256** (secret/KMS en prod). La custody = la frontière de sécurité. | — (obligatoire) |
| `PII_PROTECT_ENGINE_URL` | extension | URL du moteur sidecar. | `http://engine:8077` |
| `PII_PROTECT_FIELDS` | extension | JSON `{collection:[champs]}` pour restreindre. Vide = **tous les champs `text`**. | *(vide)* |
| `PII_PROTECT_ENTITIES` | moteur | Allow-list : seuls ces types de PII sont chiffrés. | *(vide = tous)* |
| `PII_PROTECT_SKIP` | moteur | Deny-list : ces types restent en clair. | *(vide)* |
| `PII_NER_MODEL` | moteur | Modèle NER HuggingFace (voir [`engine/MODELS.md`](engine/MODELS.md)). | Anonym-IA FR |
| `PII_NER_THRESHOLD` | moteur | Seuil de confiance du NER. | `0.4` |
| `PII_OCR_LANG` | moteur | Langue Tesseract pour le caviardage d'images. | `fra` |

**Secure-by-default** : sans configuration, tout ce qui est accessible à un rôle agent est protégé
(champs texte, documents, images). On restreint *ensuite*, pas l'inverse.

## Personnalisation (points flaggés dans le code)

- Ajouter une **regex / recognizer** → `engine/recognizers.py` (bloc « AJOUTER UN RECOGNIZER »).
- Changer le **modèle NER** (langue, modèle) → `PII_NER_MODEL` + `engine/MODELS.md`.
- Choisir **quels types** sont chiffrés → `PII_PROTECT_ENTITIES` / `PII_PROTECT_SKIP`.
- Choisir **quels champs** sont traités → `PII_PROTECT_FIELDS`.

## Roadmap

- [ ] **Validation humaine (HITL)** — workflow d'approbation pour la ré-identification (phase 2, possiblement payant).
- [ ] **Rotation de clé** + fenêtre de validité des jetons ; custody via KMS/HSM.
- [ ] **PDF** (texte et scanné) — aujourd'hui refusé fail-closed faute de pipeline OCR PDF.
- [ ] **Mode déterministe** optionnel (même entrée → même jeton) pour corrélation inter-appels.
- [ ] **Canaux de notification** (Slack/Teams) pour les demandes de ré-identification.
- [ ] **Sidecar standalone** documenté (réutilisation hors d9).
- [ ] Enrichir les recognizers + affiner le NER (par langue).

## Licence

MIT — voir [LICENSE](LICENSE).
