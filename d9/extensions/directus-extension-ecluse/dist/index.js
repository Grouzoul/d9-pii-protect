/**
 * directus-extension-pii-protect — hook (non-sandboxé)
 * Sortie "buildée" (dist). Source : src/index.ts — `npm run build` pour régénérer.
 *
 * Un rôle marqué "Agent IA" (champ is_agent sur le rôle) passe par l'anonymiseur :
 *   - items.read          -> chiffre les PII des champs texte libre (moteur FR, AES-256-GCM)
 *   - items.create/update -> rehydrate les marqueurs [[PII:...]] avant écriture en base
 * Repli : rôles listés dans ecluse.config.json > agentRoleIds.
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

// cache rôle -> is_agent (flag porté par le rôle d9)
const roleCache = new Map();
async function isAgentRole(database, roleId) {
  if (!roleId) return false;
  const c = cfg();
  if (Array.isArray(c.agentRoleIds) && c.agentRoleIds.includes(roleId)) return true; // repli config
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
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ text }),
  });
  if (!r.ok) throw new Error('engine HTTP ' + r.status);
  return (await r.json()).text;
}

export default ({ filter }, { logger }) => {
  // -------- LECTURE : anonymisation pour les rôles agents --------
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
          // fail-closed : si l'engine est indisponible, on NE laisse PAS fuir le clair.
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

  logger.info('[pii-protect] hook chargé');
};
