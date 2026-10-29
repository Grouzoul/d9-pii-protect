/**
 * directus-extension-pii-protect — sortie buildée (dist). Source : src/index.ts.
 * Rôle « Agent IA » (is_agent) → chiffre les champs TEXTE LIBRE (secure-by-default),
 * rehydrate à l'écriture, documents texte via /assets (+ round-trip au ré-upload).
 * Piloté par env : PII_PROTECT_ENGINE_URL, PII_PROTECT_FIELDS. Pas de logs custom (audit d9 natif).
 */
import { Readable } from 'node:stream';

const ENGINE = process.env.PII_PROTECT_ENGINE_URL || 'http://host.docker.internal:8077';
const TEXT_DOCS = ['txt', 'md', 'csv', 'json', 'docx'];

let FIELDS_MAP = null;
if (process.env.PII_PROTECT_FIELDS && process.env.PII_PROTECT_FIELDS !== '*') {
  try { FIELDS_MAP = JSON.parse(process.env.PII_PROTECT_FIELDS); } catch { FIELDS_MAP = null; }
}
function freeTextFields(schema, collection) {
  if (FIELDS_MAP) return FIELDS_MAP[collection] || [];
  try {
    const fields = (schema && schema.collections && schema.collections[collection] && schema.collections[collection].fields) || {};
    return Object.values(fields).filter((f) => f.type === 'text').map((f) => f.field);
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
    app.get('/assets/:pk', async (req, res, next) => {
      try {
        if (req.query.ecluse_bypass || req.headers['x-ecluse-bypass']) return next();
        if (!(await isAgentRole(database, req.accountability && req.accountability.role))) return next();
        const sep = req.originalUrl.includes('?') ? '&' : '?';
        const orig = await fetch('http://127.0.0.1:8055' + req.originalUrl + sep + 'ecluse_bypass=1',
          { headers: { authorization: req.headers.authorization || '' } });
        if (!orig.ok) return next();
        const ctype = orig.headers.get('content-type') || 'application/octet-stream';
        const cdisp = orig.headers.get('content-disposition') || '';
        const m = /filename\*?=(?:UTF-8''|")?([^";]+)/i.exec(cdisp);
        const name = decodeURIComponent((m && m[1]) || String(req.params.pk));
        const ext = name.toLowerCase().split('.').pop();
        const buf = Buffer.from(await orig.arrayBuffer());
        if (!TEXT_DOCS.includes(ext)) {
          res.setHeader('content-type', ctype);
          if (cdisp) res.setHeader('content-disposition', cdisp);
          return res.send(buf);
        }
        let out;
        try {
          const r = await fetch(ENGINE + '/anonymize-doc', {
            method: 'POST', headers: { 'content-type': 'application/json' },
            body: JSON.stringify({ filename: name, content_b64: buf.toString('base64') }),
          });
          if (!r.ok) throw new Error('engine HTTP ' + r.status);
          out = Buffer.from((await r.json()).content_b64, 'base64');
        } catch (e) {
          logger.warn('[pii-protect] /assets doc indispo: ' + e.message);
          return res.status(503).send('[protégé — moteur indisponible]');
        }
        res.setHeader('content-type', ctype);
        if (cdisp) res.setHeader('content-disposition', cdisp);
        return res.send(out);
      } catch (e) {
        logger.warn('[pii-protect] /assets: ' + e.message);
        return next();
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
