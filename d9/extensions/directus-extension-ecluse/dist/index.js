/**
 * directus-extension-ecluse — hook (non-sandboxé)
 * Sortie "buildée" (dist). Source : src/index.ts — `npm run build` pour régénérer.
 *
 * Pour un user de rôle "agent" :
 *   - items.read          -> anonymise (chiffre) les PII des champs texte libre via l'engine Écluse
 *   - items.create/update -> rehydrate les marqueurs [[ECLUSE:...]] avant écriture en base
 *
 * Config lue à chaud dans /directus/extensions/ecluse.config.json :
 *   { "engine": "http://host.docker.internal:8077",
 *     "agentRoleIds": ["<uuid-role-agent>"], "fields": { "tickets": ["note"] } }
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
  // -------- LECTURE : anonymisation pour les agents --------
  filter('items.read', async (payload, meta, ctx) => {
    const c = cfg();
    const role = ctx && ctx.accountability && ctx.accountability.role;
    if (!role || !c.agentRoleIds.includes(role)) return payload;
    const fields = c.fields && c.fields[meta.collection];
    if (!fields || !Array.isArray(payload)) return payload;
    for (const item of payload) {
      if (!item) continue;
      for (const f of fields) {
        if (typeof item[f] === 'string' && item[f]) {
          // fail-closed : si l'engine est indisponible, on NE laisse PAS fuir le clair.
          try { item[f] = await call(c.engine, '/anonymize', item[f]); }
          catch (e) { logger.warn('[ecluse] anonymize indispo: ' + e.message); item[f] = '[protégé — Écluse indisponible]'; }
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
      if (typeof payload[f] === 'string' && payload[f].includes('[[ECLUSE:')) {
        try { payload[f] = await call(c.engine, '/rehydrate', payload[f]); }
        catch (e) { logger.warn('[ecluse] rehydrate: ' + e.message); }
      }
    }
    return payload;
  };
  filter('items.create', rehydrate);
  filter('items.update', rehydrate);

  logger.info('[ecluse] hook chargé');
};
