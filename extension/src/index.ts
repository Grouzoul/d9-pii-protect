/**
 * directus-extension-pii-protect — one-click integration of the PII anonymization engine into d9, per role.
 *
 * For a role flagged as an "agent" (boolean is_agent on the role):
 *   items.read           → encrypt the PII of free-text fields (secure-by-default)
 *   items.create/update  → rehydrate the [[PII:…]] markers before writing
 *   GET /assets/:pk       → text docs anonymized, images/PDF redacted, unknown type refused (fail-closed)
 *   GET /files[/:pk]      → file name/title/description encrypted (d9 does not emit items.read for them)
 *   files.upload          → rehydrate a document re-uploaded by an agent (round-trip)
 *
 * Environment-driven — no coupling to a specific environment:
 *   PII_PROTECT_ENGINE_URL  URL of the sidecar engine (default http://host.docker.internal:8077)
 *   PII_PROTECT_FIELDS      JSON {collection:[fields]} to restrict; empty/"*" = all `text` fields
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

// Explicit per-collection restriction, otherwise secure-by-default (all `text`-type fields).
let FIELDS_MAP: Record<string, string[]> | null = null;
const _pf = process.env.PII_PROTECT_FIELDS;
if (_pf && _pf !== '*') { try { FIELDS_MAP = JSON.parse(_pf); } catch { /* secure-by-default */ } }

const ext = (name: string) => name.toLowerCase().split('.').pop() || '';

function textFields(schema: any, collection: string): string[] {
  if (FIELDS_MAP) return FIELDS_MAP[collection] || [];
  const fields = schema?.collections?.[collection]?.fields || {};
  return Object.values(fields).filter((f: any) => f?.type === 'text').map((f: any) => f.field);
}

// Short-lived cache of the is_agent boolean per role (avoids a DB query per read item).
const roleCache = new Map<string, { v: boolean; at: number }>();
async function isAgent(database: any, roleId?: string): Promise<boolean> {
  if (!roleId) return false;
  const hit = roleCache.get(roleId);
  if (hit && Date.now() - hit.at < 10_000) return hit.v;
  let v = false;
  try { v = !!(await database('directus_roles').select('is_agent').where({ id: roleId }).first())?.is_agent; } catch { /* default: non-agent */ }
  roleCache.set(roleId, { v, at: Date.now() });
  return v;
}

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
  // ---- READ: encrypt free-text fields for agent roles ----
  filter('items.read', async (payload: any, meta: any, ctx: any) => {
    if (!Array.isArray(payload) || !(await isAgent(ctx?.database, ctx?.accountability?.role))) return payload;
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
    for (const f of payload ? textFields(ctx?.schema, meta.collection) : []) {
      if (typeof payload[f] === 'string' && payload[f].includes('[[PII:')) {
        try { payload[f] = await callText('/rehydrate', payload[f]); } catch (e: any) { logger.warn('[pii-protect] rehydrate: ' + e.message); }
      }
    }
    return payload;
  };
  filter('items.create', rehydrate);
  filter('items.update', rehydrate);

  // ---- FILES: shared route guard ----
  init('routes.before', ({ app }: any) => {
    // Wraps all the cross-cutting logic: internal request / human → raw (next); agent → re-fetch the
    // original with ITS creds then `handle`; any error (access denied, engine down) → `deny` (never clear).
    const guard = (deny: (res: any, code: number) => any, handle: (orig: Response, req: any, res: any) => Promise<any>) =>
      async (req: any, res: any, next: any) => {
        if (req.query.ecluse_bypass || req.headers['x-ecluse-bypass']) return next(); // internal re-fetch → raw
        let agent = false;
        try { agent = await isAgent(database, req.accountability?.role); } catch { /* non-agent */ }
        if (!agent) return next(); // human → raw (d9 RBAC decides access)
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
      if (!endpoint) return res.status(415).send('[protected — unsupported file type]'); // secure-by-default
      const out = await callFile(endpoint, name, Buffer.from(await orig.arrayBuffer()));
      res.setHeader('content-type', orig.headers.get('content-type') || 'application/octet-stream');
      if (cdisp) res.setHeader('content-disposition', cdisp);
      res.send(out);
    }));
  });

  // ---- UPLOAD: rehydrate a document re-uploaded by an agent (reversible round-trip, text docs only) ----
  action('files.upload', async (meta: any, ctx: any) => {
    try {
      if (!(await isAgent(database, ctx?.accountability?.role))) return;
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
