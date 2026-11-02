/**
 * directus-extension-pii-protect — integrates the PII anonymization engine into d9, PER ROLE × COLLECTION.
 *
 * Which data gets anonymized is driven by two OPT-IN config fields on each role (directus_roles), so an
 * admin controls it from the d9 UI (the role detail page) — like the other permissions, and it applies to
 * ANY role, humans included (partial anonymization):
 *   pii_encrypt_all          boolean    → anonymize ALL collections for this role ("encrypt everything" toggle)
 *   pii_encrypt_collections  csv/tags   → list of collection keys to anonymize for this role (per-collection)
 * When those fields are absent, the extension does nothing (zero schema footprint by default).
 *
 * For a role that anonymizes a given collection:
 *   items.read           → encrypt the PII of its free-text fields
 *   items.create/update  → rehydrate the [[PII:…]] markers before writing
 *   GET /assets/:pk       → text docs anonymized, images/PDF redacted, unknown type refused (fail-closed)
 *   GET /files[/:pk]      → file name/title/description encrypted
 *   files.upload          → rehydrate a document re-uploaded by such a role (round-trip)
 * File routes are gated by "all" OR the collection `directus_files` being listed.
 *
 * Environment (no coupling to a specific environment):
 *   PII_PROTECT_ENGINE_URL  URL of the sidecar engine (default http://host.docker.internal:8077)
 *   PII_PROTECT_FIELDS      JSON {collection:[fields]} to narrow WHICH fields within a collection
 *                           (default = all `text` fields). The role config decides WHICH collections.
 *   PORT                    d9 internal port, for the self-call (default 8055)
 * No custom logs: d9's native audit already records accesses.
 */
import { Readable } from 'node:stream';

const ENGINE = process.env.PII_PROTECT_ENGINE_URL || 'http://host.docker.internal:8077';
const SELF = 'http://127.0.0.1:' + (process.env.PORT || '8055'); // d9 self-calls on its internal port

// File extension → engine endpoint. Absent = unsupported type → fail-closed refusal.
const FILE_ROUTE: Record<string, string> = {
  txt: '/anonymize-doc', md: '/anonymize-doc', csv: '/anonymize-doc', json: '/anonymize-doc', docx: '/anonymize-doc',
  png: '/redact-image', jpg: '/redact-image', jpeg: '/redact-image', gif: '/redact-image',
  bmp: '/redact-image', tiff: '/redact-image', tif: '/redact-image', webp: '/redact-image',
  pdf: '/redact-pdf',
};
// File metadata that carries PII (the NAME of the object, not just its content) → encrypted as a whole.
const FILE_META = ['filename_download', 'title', 'description'];

// Optional env refinement of WHICH fields within a collection (default = all `text`-type fields).
let FIELDS_MAP: Record<string, string[]> | null = null;
const _pf = process.env.PII_PROTECT_FIELDS;
if (_pf && _pf !== '*') { try { FIELDS_MAP = JSON.parse(_pf); } catch { /* default: all text fields */ } }

const ext = (name: string) => name.toLowerCase().split('.').pop() || '';

function textFields(schema: any, collection: string): string[] {
  if (FIELDS_MAP) return FIELDS_MAP[collection] || [];
  const fields = schema?.collections?.[collection]?.fields || {};
  return Object.values(fields).filter((f: any) => f?.type === 'text').map((f: any) => f.field);
}

function toList(v: any): string[] {
  if (!v) return [];
  if (Array.isArray(v)) return v;
  try { const j = JSON.parse(v); if (Array.isArray(j)) return j; } catch { /* csv */ }
  return String(v).split(',').map((s) => s.trim()).filter(Boolean);
}

// Per-role config, cached briefly (avoids a DB query per read item). Missing fields → no anonymization.
type Cfg = { all: boolean; cols: Set<string>; at: number };
const roleCache = new Map<string, Cfg>();
async function roleConfig(database: any, roleId?: string): Promise<Cfg> {
  if (!roleId) return { all: false, cols: new Set(), at: 0 };
  const hit = roleCache.get(roleId);
  if (hit && Date.now() - hit.at < 10_000) return hit;
  let all = false, cols = new Set<string>();
  try {
    const row = await database('directus_roles')
      .select('pii_encrypt_all', 'pii_encrypt_collections').where({ id: roleId }).first();
    all = !!row?.pii_encrypt_all;
    cols = new Set(toList(row?.pii_encrypt_collections));
  } catch { /* config fields not installed → extension stays inert */ }
  const cfg = { all, cols, at: Date.now() };
  roleCache.set(roleId, cfg);
  return cfg;
}
const anonymizes = (cfg: Cfg, collection: string) => cfg.all || cfg.cols.has(collection);
const anonymizesFiles = (cfg: Cfg) => cfg.all || cfg.cols.has('directus_files');

// Engine calls: text (→ text) and file (→ file). Throw if the engine returns an error (→ fail-closed upstream).
async function post(path: string, payload: object): Promise<any> {
  const r = await fetch(ENGINE + path, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(payload) });
  if (!r.ok) throw new Error('engine HTTP ' + r.status);
  return r.json();
}
const callText = async (path: string, text: string): Promise<string> => (await post(path, { text })).text;
const callFile = async (path: string, filename: string, buf: Buffer): Promise<Buffer> =>
  Buffer.from((await post(path, { filename, content_b64: buf.toString('base64') })).content_b64, 'base64');

async function bufferStream(stream: any): Promise<Buffer> {
  const chunks: Buffer[] = [];
  for await (const c of stream) chunks.push(Buffer.isBuffer(c) ? c : Buffer.from(c));
  return Buffer.concat(chunks);
}

export default ({ filter, init, action }: any, { logger, database, services, getSchema }: any) => {
  // ---- READ: encrypt free-text fields of the collections this role anonymizes ----
  filter('items.read', async (payload: any, meta: any, ctx: any) => {
    if (!Array.isArray(payload)) return payload;
    const cfg = await roleConfig(ctx?.database, ctx?.accountability?.role);
    if (!anonymizes(cfg, meta.collection)) return payload;
    const fields = textFields(ctx?.schema, meta.collection);
    for (const item of payload) for (const f of fields) {
      if (typeof item?.[f] === 'string' && item[f]) {
        try { item[f] = await callText('/anonymize', item[f]); }
        catch (e: any) { logger.warn('[pii-protect] anonymize: ' + e.message); item[f] = '[protected — unavailable]'; } // fail-closed
      }
    }
    return payload;
  });

  // ---- WRITE: rehydrate the markers before persistence ----
  const rehydrate = async (payload: any, meta: any, ctx: any) => {
    if (!payload) return payload;
    const cfg = await roleConfig(ctx?.database, ctx?.accountability?.role);
    if (!anonymizes(cfg, meta.collection)) return payload;
    for (const f of textFields(ctx?.schema, meta.collection)) {
      if (typeof payload[f] === 'string' && payload[f].includes('[[PII:')) {
        try { payload[f] = await callText('/rehydrate', payload[f]); } catch (e: any) { logger.warn('[pii-protect] rehydrate: ' + e.message); }
      }
    }
    return payload;
  };
  filter('items.create', rehydrate);
  filter('items.update', rehydrate);

  // ---- FILES: shared route guard (gated by the role anonymizing directus_files) ----
  init('routes.before', ({ app }: any) => {
    // Cross-cutting logic: internal re-fetch / non-matching role → raw (next); otherwise re-fetch the
    // original with ITS creds then `handle`; any error (access denied, engine down) → `deny` (never clear).
    const guard = (deny: (res: any, code: number) => any, handle: (orig: Response, req: any, res: any) => Promise<any>) =>
      async (req: any, res: any, next: any) => {
        if (req.query.ecluse_bypass || req.headers['x-ecluse-bypass']) return next(); // internal re-fetch → raw
        let on = false;
        try { on = anonymizesFiles(await roleConfig(database, req.accountability?.role)); } catch { /* off */ }
        if (!on) return next(); // role doesn't anonymize files → raw (d9 RBAC decides access)
        try {
          const sep = req.originalUrl.includes('?') ? '&' : '?';
          const orig = await fetch(SELF + req.originalUrl + sep + 'ecluse_bypass=1', {
            headers: { authorization: req.headers.authorization || '', cookie: req.headers.cookie || '' },
          });
          if (!orig.ok) return deny(res, orig.status > 200 ? orig.status : 502); // upstream perm/error
          await handle(orig, req, res);
        } catch (e: any) {
          logger.warn('[pii-protect] ' + req.path + ' (fail-closed): ' + e.message);
          deny(res, 503);
        }
      };
    const denyText = (res: any, code: number) => res.status(code).send('[protected]');
    const denyJson = (res: any, code: number) => res.status(code).json({ errors: [{ message: 'protected' }] });

    // Metadata: d9 does not emit items.read for directus_files → encrypt name/title/description here.
    app.get(['/files', '/files/:pk'], guard(denyJson, async (orig: Response, _req: any, res: any) => {
      const json: any = await orig.json();
      const rows = Array.isArray(json?.data) ? json.data : [json?.data];
      for (const row of rows) for (const f of (row ? FILE_META : [])) {
        if (typeof row[f] === 'string' && row[f]) row[f] = await callText('/encrypt', row[f]); // WHOLE name encrypted, reversible
      }
      res.json(json);
    }));

    // Content: text doc anonymized / image|PDF redacted / unknown type refused.
    app.get('/assets/:pk', guard(denyText, async (orig: Response, req: any, res: any) => {
      const cdisp = orig.headers.get('content-disposition') || '';
      const name = decodeURIComponent(/filename\*?=(?:UTF-8''|")?([^";]+)/i.exec(cdisp)?.[1] || String(req.params.pk));
      const endpoint = FILE_ROUTE[ext(name)];
      if (!endpoint) return res.status(415).send('[protected — unsupported file type]'); // nothing unknown leaks
      const out = await callFile(endpoint, name, Buffer.from(await orig.arrayBuffer()));
      res.setHeader('content-type', orig.headers.get('content-type') || 'application/octet-stream');
      if (cdisp) res.setHeader('content-disposition', cdisp);
      res.send(out);
    }));
  });

  // ---- UPLOAD: rehydrate a document re-uploaded by a file-anonymizing role (reversible, text docs only) ----
  action('files.upload', async (meta: any, ctx: any) => {
    try {
      if (!anonymizesFiles(await roleConfig(database, ctx?.accountability?.role))) return;
      const key = meta?.key || meta?.payload?.id || meta;
      if (typeof key !== 'string') return;
      const schema = await getSchema();
      const sys = { admin: true, role: null };
      const files = new services.FilesService({ schema, accountability: sys });
      const file = await files.readOne(key);
      const name = file?.filename_download || file?.filename_disk || '';
      if (FILE_ROUTE[ext(name)] !== '/anonymize-doc') return; // images/PDF = destructive redaction, no round-trip
      const asset = await new services.AssetsService({ schema, accountability: sys }).getAsset(key, {});
      const buf = await bufferStream(asset.stream || asset);
      const clear = await callFile('/rehydrate-doc', name, buf);
      if (clear.equals(buf)) return; // nothing to restore
      await files.uploadOne(Readable.from(clear),
        { type: file.type, filename_download: file.filename_download, storage: file.storage, title: file.title }, key);
      logger.info('[pii-protect] document rehydrated on re-upload (' + name + ')');
    } catch (e: any) { logger.warn('[pii-protect] files.upload: ' + e.message); }
  });

  logger.info('[pii-protect] loaded (engine ' + ENGINE + ')');
};
