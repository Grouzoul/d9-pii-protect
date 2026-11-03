# d9 PII Protect

**Governed PII anonymization for AI agents, inside [d9](https://github.com/LaWebcapsule/d9) (a Directus 9 fork).**

RBAC decides *who accesses what*. PII Protect covers the blind spot: the **PII content of free-text
fields and files** — a NIR typed into a `note`, a name inside a `.docx`, a scanned ID document. For a
user with an **"agent" role**, PII is **detected (FR engine) and reversibly encrypted** (text/documents)
or **redacted** (images); an **authorized human** sees the original. Re-identification is decided by
d9 RBAC + key custody.

## Two-brick architecture

- **`engine/`** — a **self-contained Docker sidecar**: [Presidio](https://microsoft.github.io/presidio/)
  (orchestration) + FR NER [Anonym-IA](https://huggingface.co/Anonym-IA/V2-camembert-ner-pii-french)
  + regex/checksum recognizers (SIREN, SIRET, IBAN, NIR…) + **AES-256-GCM** encryption + image
  redaction (Tesseract OCR). **One engine per environment** (confinement — no central proxy).
- **`extension/`** — the **one-click integration into d9**: a hook driven by **per-role × per-collection**
  config, editable from the d9 role page (like the other permissions). Applies to **any role, humans
  included** (partial anonymization). Engine URL etc. stay **environment-driven**.

Details and diagram: **[ARCHITECTURE.md](ARCHITECTURE.md)**.

## Quick start

Prerequisites: Docker. The d9 image is pulled from Docker Hub (`lawebcapsule/d9`); the PII engine is built
locally on first `up` (it downloads the NER model at build time, so the first build needs internet).

```bash
cd deploy
cp .env.example .env            # set at least PII_PROTECT_KEY
docker compose up -d --build    # builds the engine + starts d9
```

- d9: http://localhost:8055 (admin defined in `.env`)
- The extension **adds its own config to each role automatically** (no setup script). On the **role page**
  (Settings → Roles & Permissions → a role) you get **Encrypt all collections** (toggle) and, when it's off,
  **checkboxes of your collections** to anonymize. Changing them needs role-edit rights, so a regular user
  can't alter what's encrypted — same access control as the other permissions.

## Configuration (environment variables)

| Variable | Brick | Role | Default |
|---|---|---|---|
| `PII_PROTECT_KEY` | engine | **AES-256 key** (secret/KMS in prod). Custody = the security boundary. | — (required) |
| `PII_PROTECT_ENGINE_URL` | extension | URL of the sidecar engine. | `http://engine:8077` |
| `PII_PROTECT_FIELDS` | extension | JSON `{collection:[fields]}` to narrow **which fields** within a collection (the role config picks **which collections**). Empty = all `text` fields. | *(empty)* |
| `PII_PROTECT_ENTITIES` | engine | Allow-list: only these PII types are encrypted. | *(empty = all)* |
| `PII_PROTECT_SKIP` | engine | Deny-list: these types stay in clear. | *(empty)* |
| `PII_NER_MODEL` | engine | Hugging Face NER model (see [`engine/MODELS.md`](engine/MODELS.md)). | Anonym-IA FR |
| `PII_NER_BACKEND` | engine | `onnx` (ONNX Runtime, ~30% faster, same results) or `torch`. | `onnx` |
| `PII_NER_THRESHOLD` | engine | NER confidence threshold. | `0.4` |
| `PII_NER_ONNX_THREADS` | engine | ONNX Runtime intra-op threads. Empty = auto; cap to physical/perf cores on heterogeneous CPUs (e.g. 4 on Apple Silicon). | *(empty = auto)* |
| `PII_OCR_LANG` | engine | Tesseract language for image redaction. | `fra` |

**Per role × collection**: a role anonymizes a collection when `pii_encrypt_all` is on, or that collection
is listed in `pii_encrypt_collections`. When it applies, **everything** in scope (text fields, documents,
images) is protected, and unknown file types are refused (fail-closed) — never a partial leak. The config
lives on `directus_roles`, so only users who can edit roles can change it.

## Customization (points flagged in the code)

- Add a **regex / recognizer** → `engine/recognizers.py` (the "ADD A REGEX RECOGNIZER" block).
- Change the **NER model** (language, model) → `PII_NER_MODEL` + `engine/MODELS.md`.
- Choose **which types** are encrypted → `PII_PROTECT_ENTITIES` / `PII_PROTECT_SKIP`.
- Choose **which fields** are processed → `PII_PROTECT_FIELDS`.

## Roadmap

- [ ] **Human-in-the-loop (HITL)** — approval workflow for re-identification using d9 MFA.
- [ ] **Key rotation** + token validity window; custody via KMS/HSM.
- [ ] **PDF** (text and scanned) — currently redacted page-by-page; a text-layer path could be added.
- [ ] **Optional deterministic mode** (same input → same token) for cross-call correlation.
- [ ] **Notification channels** (Slack/Teams) for re-identification requests.
- [ ] **Standalone sidecar** documented (reuse outside d9).
- [ ] Richer recognizers + NER refinement (per language).

## License

MIT — see [LICENSE](LICENSE).
