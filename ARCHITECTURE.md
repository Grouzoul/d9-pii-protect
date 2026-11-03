# Architecture — d9 PII Protect

Two bricks, decoupled by an environment variable. **One engine per environment** (dev / staging /
prod): no central proxy, PII never leaves its environment (confinement principle).

```
                        ENVIRONMENT (dev / staging / prod)
  ┌──────────────────────────────────────────────────────────────────────────┐
  │                                                                            │
  │   AI agent / API ─────────┐                                                │
  │   (anonymized role)        │  reads/writes items & files                   │
  │                            ▼                                                │
  │                    ┌───────────────┐   PII_PROTECT_ENGINE_URL   ┌────────┐ │
  │   Human ──────────▶│      d9       │ ─────────────────────────▶ │ ENGINE │ │
  │   (sees clear)     │               │ ◀───────────────────────── │(sidecar)│ │
  │                    │  + extension  │     text <-> markers         └────────┘ │
  │                    │  PII Protect  │                             Presidio FR │
  │                    └───────┬───────┘                             + FR NER    │
  │                            │                                     + regex     │
  │                            ▼                                     + AES-GCM    │
  │                        Database                                  (key = env)  │
  │                   (PII IN CLEAR, protected by RBAC)                           │
  └──────────────────────────────────────────────────────────────────────────┘
```

```mermaid
flowchart LR
    agent["AI agent / API<br/>(anonymized role)"]
    human["Human<br/>(authorized)"]
    d9["d9<br/>+ PII Protect extension<br/>(per-role hook)"]
    db[("Database<br/>PII in clear")]
    engine["ENGINE sidecar<br/>Presidio FR + NER + regex<br/>+ AES-GCM encryption"]

    human -->|reads/writes| d9
    agent -->|reads/writes| d9
    d9 <-->|PII_PROTECT_ENGINE_URL| engine
    d9 --> db
    engine -. "AES key = PII_PROTECT_KEY<br/>(secret / KMS)" .- engine
```

## Who does what

| Brick | Role | Tech | Repo contents |
|---|---|---|---|
| **Engine** (`engine/`) | Detects PII in a text and encrypts/decrypts it. | Python, [Presidio](https://microsoft.github.io/presidio/) (orchestration) + FR NER [Anonym-IA](https://huggingface.co/Anonym-IA/V2-camembert-ner-pii-french) + regex/checksum recognizers + AES-256-GCM | `Dockerfile`, `app.py`, `analyzer.py`, `recognizers.py`, `ner.py`, `crypto.py`, `image_redact.py`, `MODELS.md` |
| **Extension** (`extension/`) | Integrates the engine into d9 as one hook. Anonymizes on read for the roles you configure (per collection), rehydrates on write. | TypeScript (d9 hook) | `src/index.ts`, `dist/index.js` |
| **Deploy** (`deploy/`) | Reference stack wiring the two together. | docker-compose | `docker-compose.yml`, `.env.example` |

## The flow, step by step

1. A user whose **role anonymizes that collection** (see Design decisions) reads an item. The d9 hook
   calls `POST /anonymize` on the engine for each relevant free-text field.
2. The engine **detects** PII (FR NER + regex + Presidio context scoring) and replaces each value
   with an encrypted marker `[[PII:TYPE:base64(nonce+ciphertext)]]`.
   → the user **never** sees the clear value; a random nonce per value prevents any equality leak
   or brute-force without the key.
3. That user **writes** (create/update) a text containing markers. The hook calls `POST /rehydrate`:
   the engine **decrypts** and restores the clear value before storage.
4. A user whose **role is not configured** reads normally: no anonymization.
5. **Fail-closed**: if the engine is unreachable, the user gets `[protected — unavailable]` rather
   than the clear value.

## Design decisions

- **Per role × collection, admin-controlled**: anonymization is a property of the role, set via two
  fields on `directus_roles` (`pii_encrypt_all`, `pii_encrypt_collections`) — editable on the role page
  like the other permissions, so **only users who can edit roles can change what is encrypted**. It applies
  to **any role, humans included** (partial anonymization). RBAC covers structured fields; we cover the
  **free-text fields** (and files), where unexpected PII slips in. Within a protected collection, all
  `text` fields are covered by default — narrow with `PII_PROTECT_FIELDS`, choose types with
  `PII_PROTECT_ENTITIES` / `PII_PROTECT_SKIP`.
- **Reversible encryption, not masking**: we re-identify for authorized humans. Key custody
  (`PII_PROTECT_KEY`) **is** the security boundary.
- **Embedded Presidio**: reuse its recognizer registry and context scoring
  (which disambiguates e.g. SIREN vs NIR), and keep **our own** encryption (Presidio's unsalted
  `hash` is insufficient).
- **One engine per environment**: confinement. No central proxy through which every environment's
  data would transit.
- **No custom logs**: activity is already tracked by d9's native **audit**.

## Customizable points (flagged in the code)

- Add a **regex** / recognizer → `engine/recognizers.py` ("ADD A REGEX RECOGNIZER" block).
- Change the **NER model** (other language, other model) → env `PII_NER_MODEL`, see `engine/MODELS.md`.
- Choose **which types** are encrypted → `PII_PROTECT_ENTITIES` / `PII_PROTECT_SKIP`.
- Choose **which fields** are processed → `PII_PROTECT_FIELDS`.
