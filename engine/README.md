# PII Protect engine (sidecar)

A self-contained service that **detects** PII in a text/document/image and **encrypts
(reversible)** or **redacts (images)** it. Reusable by any service, not just d9.

## What's inside

| File | Role |
|---|---|
| `app.py` | HTTP server (stdlib) + endpoints. |
| `analyzer.py` | **Presidio** orchestration: blank FR spaCy tokenizer + NER + regex recognizers, dedup by score. |
| `ner.py` | The **NER model** exposed as a Presidio recognizer. ← *change the model here / via `PII_NER_MODEL`*. |
| `recognizers.py` | The **regex + checksums** (SIREN/SIRET/IBAN/NIR…). ← *add a regex here*. |
| `crypto.py` | **AES-256-GCM** encryption + `[[PII:TYPE:b64]]` markers. |
| `image_redact.py` | **Image/PDF redaction** (Presidio Image Redactor + our analyzer, FR by default + Tesseract OCR). |
| `MODELS.md` | Directory of NER models per language (Hugging Face links) for switching. |

## Endpoints

```
POST /anonymize      {text}                  -> {text, count, entities}   # encrypt
POST /encrypt        {text}                  -> {text, count}             # encrypt the whole value
POST /rehydrate      {text}                  -> {text, count}             # decrypt
POST /anonymize-doc  {filename, content_b64} -> {filename, content_b64}   # .txt/.md/.csv/.json/.docx
POST /rehydrate-doc  {filename, content_b64} -> {filename, content_b64}
POST /redact-image   {filename, content_b64} -> {filename, content_b64}   # redaction (destructive)
POST /redact-pdf     {filename, content_b64} -> {filename, content_b64}   # PDF redaction (destructive)
POST /detect         {text}                  -> {spans:[{start,end,type,text}]}
GET  /health
```

## Run (Docker)

```bash
docker build -t pii-protect-engine:latest .
docker run --rm -p 8077:8077 -e PII_PROTECT_KEY=$(openssl rand -base64 32) pii-protect-engine:latest
curl -s localhost:8077/health
```

Variables: see the [root README](../README.md#configuration-environment-variables).

## Add a regex recognizer

In `recognizers.py`:
- **without checksum**: one line in `SIMPLE` → `(ENTITY, regex, score, [context words])`.
  Context words raise the score when present nearby (a Presidio feature).
- **with checksum** (Luhn/mod-97 validation): one `_Checksum(...)` in `build_recognizers()`.

Reuse the **type vocabulary of the NER model** (see `ner.py` `LABELS`) so there is a single list of
types to know about on the config side (`PII_PROTECT_SKIP`, etc.).

## Change the NER model / language

`PII_NER_MODEL=<hf/model>` (at build time: `--build-arg PII_NER_MODEL=...` to bake it into the image).
Adapt `LABELS` in `ner.py` to the new model's entity set. Candidates per language: `MODELS.md`.
