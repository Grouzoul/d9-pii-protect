# directus-extension-pii-protect (d9 PII Protect)

d9 / Directus hook for **governed PII anonymization for AI agents**.

For a user with an *agent* role, everything accessible to them is protected **secure-by-default**:
free-text fields are **detected (FR engine) and reversibly encrypted** on read (and **rehydrated** on
write), text documents are anonymized and images redacted on the fly. An authorized human sees the
original. d9 handles RBAC; this extension handles the PII content that field-level RBAC cannot see.
The anonymization is delegated to the **sidecar engine** (see the root repo).

## Installation

1. Drop this folder into the `extensions/` directory of the d9 instance (non-sandboxed hook — needs
   access to `accountability`).
2. Start the **sidecar engine** and point the extension at it via `PII_PROTECT_ENGINE_URL`.
3. Flag a role as an agent: add/enable the **`is_agent`** boolean on `directus_roles` (this is the
   only UI addition — a toggle on the role definition).

## Configuration (environment variables)

| Variable | Role | Default |
|---|---|---|
| `PII_PROTECT_ENGINE_URL` | URL of the sidecar engine (within the environment's network). | `http://host.docker.internal:8077` |
| `PII_PROTECT_FIELDS` | JSON `{collection:[fields]}` to restrict. Empty/`*` = **all `text` fields**. | *(empty)* |

Choosing **which PII types** to encrypt (`PII_PROTECT_ENTITIES` / `PII_PROTECT_SKIP`) happens on the
**engine side**. No hardcoded config, no environment coupling.

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
