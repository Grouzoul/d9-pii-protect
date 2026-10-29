# Moteur PII Protect (sidecar)

Service auto-suffisant qui **détecte** les PII d'un texte/document/image et les **chiffre
(réversible)** ou **caviarde (images)**. Réutilisable par n'importe quel service, pas seulement d9.

## Ce qu'il y a dedans

| Fichier | Rôle |
|---|---|
| `app.py` | Serveur HTTP (stdlib) + endpoints. |
| `analyzer.py` | Orchestration **Presidio** : tokenizer spaCy FR vide + NER + recognizers regex, dédoublonnage par score. |
| `ner.py` | Le **modèle NER** exposé en recognizer Presidio. ← *changer de modèle ici / via `PII_NER_MODEL`*. |
| `recognizers.py` | Les **regex + checksums** (SIREN/SIRET/IBAN/NIR…). ← *ajouter une regex ici*. |
| `crypto.py` | Chiffrement **AES-256-GCM** + marqueurs `[[PII:TYPE:b64]]`. |
| `image_redact.py` | **Caviardage d'images** (Presidio Image Redactor + notre analyzer FR + Tesseract OCR). |
| `MODELS.md` | Répertoire de modèles NER par langue (liens HuggingFace) pour swapper. |

## Endpoints

```
POST /anonymize      {text}                  -> {text, count, entities}   # chiffre
POST /rehydrate      {text}                  -> {text, count}             # déchiffre
POST /anonymize-doc  {filename, content_b64} -> {filename, content_b64}   # .txt/.md/.csv/.json/.docx
POST /rehydrate-doc  {filename, content_b64} -> {filename, content_b64}
POST /redact-image   {filename, content_b64} -> {filename, content_b64}   # caviardage (destructif)
POST /detect         {text}                  -> {spans:[{start,end,type,text}]}
GET  /health
```

## Lancer (Docker)

```bash
docker build -t ecluse-engine:latest .
docker run --rm -p 8077:8077 -e PII_PROTECT_KEY=$(openssl rand -base64 32) ecluse-engine:latest
curl -s localhost:8077/health
```

Variables : voir le [README racine](../README.md#configuration-variables-denvironnement).

## Ajouter un recognizer regex

Dans `recognizers.py` :
- **sans checksum** : une ligne dans `SIMPLE` → `(ENTITÉ, regex, score, [mots de contexte])`.
  Les mots de contexte montent le score si présents à proximité (fonctionnalité Presidio).
- **avec checksum** (validation type Luhn/mod-97) : un `_Checksum(...)` dans `build_recognizers()`.

Réutilise le **vocabulaire de types du modèle NER** (voir `ner.py` `LABELS`) pour qu'il n'y ait
qu'une seule liste de types à connaître côté config (`PII_PROTECT_SKIP`, etc.).

## Changer le modèle NER / de langue

`PII_NER_MODEL=<hf/model>` (au build : `--build-arg PII_NER_MODEL=...` pour le baker dans l'image).
Adapter `LABELS` dans `ner.py` au jeu d'entités du nouveau modèle. Candidats par langue : `MODELS.md`.
