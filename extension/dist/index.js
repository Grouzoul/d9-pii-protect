/**
 * directus-extension-pii-protect — sortie buildée (dist). Source : src/index.ts.
 * Rôle « Agent IA » (is_agent) → chiffre les champs TEXTE LIBRE (secure-by-default),
 * rehydrate à l'écriture ; SECURE-BY-DEFAULT sur TOUT fichier via /assets : docs texte anonymisés,
 * images caviardées, type non pris en charge = refus fail-closed (+ round-trip au ré-upload).
 * Piloté par env : PII_PROTECT_ENGINE_URL, PII_PROTECT_FIELDS. Pas de logs custom (audit d9 natif).
 */
import { Readable } from 'node:stream';

const ENGINE = process.env.PII_PROTECT_ENGINE_URL || 'http://host.docker.internal:8077';
// Auto-appel de d9 sur son port interne (env PORT de Directus, défaut 8055). Jamais en dur.
const SELF = 'http://127.0.0.1:' + (process.env.PORT || '8055');
const TEXT_DOCS = ['txt', 'md', 'csv', 'json', 'docx'];
const IMAGE_DOCS = ['png', 'jpg', 'jpeg', 'gif', 'bmp', 'tiff', 'tif', 'webp'];

let FIELDS_MAP = null;
if (process.env.PII_PROTECT_FIELDS && process.env.PII_PROTECT_FIELDS !== '*') {
  try { FIELDS_MAP = JSON.parse(process.env.PII_PROTECT_FIELDS); } catch { FIELDS_MAP = null; }
}
const FILE_META_FIELDS = ['filename_download', 'title', 'description'];
function freeTextFields(schema, collection) {
  if (FIELDS_MAP) return FIELDS_MAP[collection] || [];
  try {
    const fields = (schema && schema.collections && schema.collections[collection] && schema.collections[collection].fields) || {};
    const texts = Object.values(fields).filter((f) => f.type === 'text').map((f) => f.field);
    if (collection === 'directus_files') return Array.from(new Set([...texts, ...FILE_META_FIELDS]));
    return texts;
  } catch { return []; }
}

const roleCache = new Map();
async function isAgentRole(database, roleId) {
  if (!roleId) return false;
  const hit = roleCache.get(roleId);
  if (hit && Date.now() - hit.at < 10000) return hit.v;
  let v = false;
  try {
    const row = await database('directus_roles').select('is_agent').where({ id: roleId }).first();
    v = !!(row && row.is_agent);
  } catch { v = false; }
  roleCache.set(roleId, { v, at: Date.now() });
  return v;
}

async function call(path, text) {
  const r = await fetch(ENGINE + path, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ text }),
  });
  if (!r.ok) throw new Error('engine HTTP ' + r.status);
  return (await r.json()).text;
}

async function bufferStream(stream) {
  const chunks = [];
  for await (const c of stream) chunks.push(Buffer.isBuffer(c) ? c : Buffer.from(c));
  return Buffer.concat(chunks);
}

export default ({ filter, init, action }, { logger, database, services, getSchema }) => {
  filter('items.read', async (payload, meta, ctx) => {
    const role = ctx && ctx.accountability && ctx.accountability.role;
    if (!(await isAgentRole(ctx && ctx.database, role))) return payload;
    const fields = freeTextFields(ctx && ctx.schema, meta.collection);
    if (!fields.length || !Array.isArray(payload)) return payload;
    for (const item of payload) {
      if (!item) continue;
      for (const f of fields) {
        if (typeof item[f] === 'string' && item[f]) {
          try { item[f] = await call('/anonymize', item[f]); }
          catch (e) { logger.warn('[pii-protect] anonymize indispo: ' + e.message); item[f] = '[protégé — indisponible]'; }
        }
      }
    }
    return payload;
  });

  const rehydrate = async (payload, meta, ctx) => {
    if (!payload) return payload;
    const fields = freeTextFields(ctx && ctx.schema, meta.collection);
    for (const f of fields) {
      if (typeof payload[f] === 'string' && payload[f].includes('[[PII:')) {
        try { payload[f] = await call('/rehydrate', payload[f]); }
        catch (e) { logger.warn('[pii-protect] rehydrate: ' + e.message); }
      }
    }
    return payload;
  };
  filter('items.create', rehydrate);
  filter('items.update', rehydrate);

  init('routes.before', ({ app }) => {
    // d9 n'émet pas items.read pour directus_files -> on intercepte /files pour anonymiser nom/titre/description.
    const anonFileMeta = async (o) => {
      if (!o || typeof o !== 'object') return;
      for (const f of FILE_META_FIELDS) {
        if (typeof o[f] === 'string' && o[f]) {
          try { o[f] = await call('/anonymize', o[f]); } catch { o[f] = '[protégé — indisponible]'; }
        }
      }
    };
    const filesHandler = async (req, res, next) => {
      if (req.query.ecluse_bypass || req.headers['x-ecluse-bypass']) return next();
      let agent = false;
      try { agent = await isAgentRole(database, req.accountability && req.accountability.role); } catch { agent = false; }
      if (!agent) return next();
      try {
        const sep = req.originalUrl.includes('?') ? '&' : '?';
        const orig = await fetch(SELF + req.originalUrl + sep + 'ecluse_bypass=1', {
          headers: { authorization: req.headers.authorization || '', cookie: req.headers.cookie || '' },
        });
        if (!orig.ok) return res.status(orig.status && orig.status !== 200 ? orig.status : 502).json({ errors: [{ message: 'protégé — accès refusé' }] });
        const json = await orig.json();
        if (Array.isArray(json && json.data)) for (const it of json.data) await anonFileMeta(it);
        else await anonFileMeta(json && json.data);
        return res.json(json);
      } catch (e) {
        logger.warn('[pii-protect] /files (agent, fail-closed): ' + e.message);
        return res.status(503).json({ errors: [{ message: 'protégé — indisponible' }] });
      }
    };
    app.get('/files', filesHandler);
    app.get('/files/:pk', filesHandler);

    app.get('/assets/:pk', async (req, res, next) => {
      if (req.query.ecluse_bypass || req.headers['x-ecluse-bypass']) return next(); // interne -> original
      let agent = false;
      try { agent = await isAgentRole(database, req.accountability && req.accountability.role); } catch { agent = false; }
      if (!agent) return next(); // humain -> original (RBAC d9)
      try {
        // Re-fetch interne : transmettre TOUTES les creds (header + cookie ; token en query déjà dans originalUrl).
        const sep = req.originalUrl.includes('?') ? '&' : '?';
        const orig = await fetch(SELF + req.originalUrl + sep + 'ecluse_bypass=1', {
          headers: { authorization: req.headers.authorization || '', cookie: req.headers.cookie || '' },
        });
        if (!orig.ok) {
          return res.status(orig.status && orig.status !== 200 ? orig.status : 502).send('[protégé — accès refusé]'); // fail-closed
        }
        const ctype = orig.headers.get('content-type') || 'application/octet-stream';
        const cdisp = orig.headers.get('content-disposition') || '';
        const m = /filename\*?=(?:UTF-8''|")?([^";]+)/i.exec(cdisp);
        const name = decodeURIComponent((m && m[1]) || String(req.params.pk));
        const ext = name.toLowerCase().split('.').pop() || '';
        const buf = Buffer.from(await orig.arrayBuffer());
        const endpoint = TEXT_DOCS.includes(ext) ? '/anonymize-doc'
                       : IMAGE_DOCS.includes(ext) ? '/redact-image'
                       : ext === 'pdf' ? '/redact-pdf'
                       : null;
        if (!endpoint) {
          return res.status(415).send('[protégé — type de fichier non pris en charge]');
        }
        const r = await fetch(ENGINE + endpoint, {
          method: 'POST', headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ filename: name, content_b64: buf.toString('base64') }),
        });
        if (!r.ok) throw new Error('engine HTTP ' + r.status);
        const out = Buffer.from((await r.json()).content_b64, 'base64');
        res.setHeader('content-type', ctype);
        if (cdisp) res.setHeader('content-disposition', cdisp);
        return res.send(out);
      } catch (e) {
        logger.warn('[pii-protect] /assets (agent, fail-closed): ' + e.message);
        return res.status(503).send('[protégé — moteur indisponible]'); // jamais next()->clair
      }
    });
  });

  action('files.upload', async (meta, ctx) => {
    try {
      if (!(await isAgentRole(database, ctx && ctx.accountability && ctx.accountability.role))) return;
      const key = (meta && (meta.key || (meta.payload && meta.payload.id))) || meta;
      if (!key || typeof key !== 'string') return;
      const schema = await getSchema();
      const sys = { admin: true, role: null };
      const files = new services.FilesService({ schema, accountability: sys });
      const file = await files.readOne(key);
      const name = (file && (file.filename_download || file.filename_disk)) || '';
      if (!TEXT_DOCS.includes(name.toLowerCase().split('.').pop())) return;
      const assets = new services.AssetsService({ schema, accountability: sys });
      const asset = await assets.getAsset(key, {});
      const buf = await bufferStream(asset.stream || asset);
      const r = await fetch(ENGINE + '/rehydrate-doc', {
        method: 'POST', headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ filename: name, content_b64: buf.toString('base64') }),
      });
      if (!r.ok) throw new Error('engine HTTP ' + r.status);
      const clear = Buffer.from((await r.json()).content_b64, 'base64');
      if (clear.equals(buf)) return;
      await files.uploadOne(Readable.from(clear),
        { type: file.type, filename_download: file.filename_download, storage: file.storage, title: file.title }, key);
      logger.info('[pii-protect] document ré-uploadé rehydraté (' + name + ')');
    } catch (e) {
      logger.warn('[pii-protect] files.upload: ' + e.message);
    }
  });

  logger.info('[pii-protect] hook chargé (engine ' + ENGINE + ')');
};
