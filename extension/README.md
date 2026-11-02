# directus-extension-pii-protect (d9 PII Protect)

d9 / Directus hook for **governed PII anonymization for AI agents**.

Anonymization is driven **per role × per collection**: for a role that anonymizes a collection,
free-text fields are **detected (engine, FR by default) and reversibly encrypted** on read (and
**rehydrated** on write), text documents are anonymized and images/PDF redacted on the fly. This applies
to **any role, humans included** (partial anonymization); anyone else sees the original. d9 handles RBAC;
this extension handles the PII content that field-level RBAC cannot see, delegating to the **sidecar engine**.

## Installation

1. Drop this folder into the `extensions/` directory of the d9 instance (non-sandboxed hook — needs
   access to `accountability`).
2. Start the **sidecar engine** and point the extension at it via `PII_PROTECT_ENGINE_URL`.
3. Add two **config fields on `directus_roles`** (one-time; the control surface on each role page):
   - `pii_encrypt_all` (boolean) — anonymize every collection for the role;
   - `pii_encrypt_collections` (csv/tags) — specific collections to anonymize.
   Editing them requires role-edit rights, so a regular user can't change what's encrypted. By default
   (fields absent) the extension stays inert. See [`examples/seed_ecluse.py`](../examples/seed_ecluse.py).

## Configuration (environment variables)

| Variable | Role | Default |
|---|---|---|
| `PII_PROTECT_ENGINE_URL` | URL of the sidecar engine (within the environment's network). | `http://host.docker.internal:8077` |
| `PII_PROTECT_FIELDS` | JSON `{collection:[fields]}` to narrow **which fields** within a collection (the role config picks **which collections**). Empty/`*` = all `text` fields. | *(empty)* |

Choosing **which PII types** to encrypt (`PII_PROTECT_ENTITIES` / `PII_PROTECT_SKIP`) happens on the
**engine side**.

**No custom logs**: d9's native activity log already records accesses.

## Development

```bash
npm install
npm run build      # esbuild: transpile src/index.ts → dist/index.js (readable, non-minified, un-bundled)
npm run dev        # same, in watch mode
```

Single source: `src/index.ts`. Versioned output: `dist/index.js` (the artifact loaded by d9 — a plain
1:1 transpile, auditable). The hook has **no runtime dependency** (only `node:stream`, built-in).

## License

MIT © La Webcapsule
