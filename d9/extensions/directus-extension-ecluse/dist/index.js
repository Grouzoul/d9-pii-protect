/**
 * directus-extension-pii-protect — hook (non-sandboxé). Sortie buildée (dist). Source : src/index.ts.
 *
 * Rôle marqué "Agent IA" (champ is_agent) → anonymisation :
 *   - items.read            : chiffre les PII des champs texte libre (moteur FR, AES-256-GCM, marqueurs [[PII:]])
 *   - items.create/update   : rehydrate les marqueurs avant écriture
 *   - GET /assets/:pk        : documents texte (.txt/.docx/.md/.csv/.json) tokenisés réversiblement
 * Repli rôle : ecluse.config.json > agentRoleIds.
 */
import { readFileSync } from 'node:fs';

const CONFIG_PATH = '/directus/extensions/ecluse.config.json';
let _cfg = null, _at = 0;
function cfg() {
  if (_cfg && Date.now() - _at < 2000) return _cfg;
  try { _cfg = JSON.parse(readFileSync(CONFIG_PATH, 'utf8')); }
  catch { _cfg = { engine: 'http://host.docker.internal:8077', agentRoleIds: [], fields: {} }; }
  _at = Date.now();
  return _cfg;
}

const roleCache = new Map();
async function isAgentRole(database, roleId) {
  if (!roleId) return false;
  const c = cfg();
  if (Array.isArray(c.agentRoleIds) && c.agentRoleIds.includes(roleId)) return true;
  const hit = roleCache.get(roleId);
  if (hit && Date.now() - hit.at < 10000) return hit.v;
  let v = false;
  try {
    const row = await database('directus_roles').select('is_agent').where({ id: roleId }).first();
    v = !!(row && row.is_agent);
  } catch (e) { v = false; }
  roleCache.set(roleId, { v, at: Date.now() });
  return v;
}

async function call(engine, path, text) {
  const r = await fetch(engine + path, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ text }),
  });
  if (!r.ok) throw new Error('engine HTTP ' + r.status);
  return (await r.json()).text;
}

// documents texte traités de façon réversible via l'engine
const TEXT_DOCS = ['txt', 'md', 'csv', 'json', 'docx'];

export default ({ filter, init }, { logger, database }) => {
  // -------- LECTURE : anonymisation des champs texte pour les rôles agents --------
  filter('items.read', async (payload, meta, ctx) => {
    const c = cfg();
    const role = ctx && ctx.accountability && ctx.accountability.role;
    if (!(await isAgentRole(ctx && ctx.database, role))) return payload;
    const fields = c.fields && c.fields[meta.collection];
    if (!fields || !Array.isArray(payload)) return payload;
    for (const item of payload) {
      if (!item) continue;
      for (const f of fields) {
        if (typeof item[f] === 'string' && item[f]) {
          try { item[f] = await call(c.engine, '/anonymize', item[f]); }
          catch (e) { logger.warn('[pii-protect] anonymize indispo: ' + e.message); item[f] = '[protégé — indisponible]'; }
        }
      }
    }
    return payload;
  });

  // -------- ÉCRITURE : rehydrate les marqueurs avant persistance --------
  const rehydrate = async (payload, meta) => {
    const c = cfg();
    const fields = c.fields && c.fields[meta.collection];
    if (!fields || !payload) return payload;
    for (const f of fields) {
      if (typeof payload[f] === 'string' && payload[f].includes('[[PII:')) {
        try { payload[f] = await call(c.engine, '/rehydrate', payload[f]); }
        catch (e) { logger.warn('[pii-protect] rehydrate: ' + e.message); }
      }
    }
    return payload;
  };
  filter('items.create', rehydrate);
  filter('items.update', rehydrate);

  // -------- FICHIERS : documents texte tokenisés pour les rôles agents --------
  init('routes.before', ({ app }) => {
    app.get('/assets/:pk', async (req, res, next) => {
      try {
        if (req.query.ecluse_bypass || req.headers['x-ecluse-bypass']) return next(); // requête interne -> original
        const role = req.accountability && req.accountability.role;
        if (!(await isAgentRole(database, role))) return next(); // humain -> original
        // récupère l'original via une requête interne (le RBAC d9 est réappliqué par la route native)
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
          // type non géré (image/pdf/icône d'app…) : passthrough (POC — pas de caviardage image ici)
          res.setHeader('content-type', ctype);
          if (cdisp) res.setHeader('content-disposition', cdisp);
          return res.send(buf);
        }
        // document texte -> anonymisation réversible (fail-closed si l'engine est indispo)
        let out;
        try {
          const r = await fetch(cfg().engine + '/anonymize-doc', {
            method: 'POST', headers: { 'content-type': 'application/json' },
            body: JSON.stringify({ filename: name, content_b64: buf.toString('base64') }),
          });
          if (!r.ok) throw new Error('engine HTTP ' + r.status);
          out = Buffer.from((await r.json()).content_b64, 'base64');
        } catch (e) {
          logger.warn('[pii-protect] /assets doc indispo: ' + e.message);
          return res.status(503).send('[protégé — anonymiseur indisponible]');
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

  logger.info('[pii-protect] hook chargé');
};
